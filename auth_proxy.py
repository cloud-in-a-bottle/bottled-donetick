"""OpenHost auto-login auth-proxy for Donetick.

Sits between the OpenHost router and Donetick.  When an
authenticated zone owner navigates to the SPA without an
existing localStorage token, this proxy serves a tiny HTML
bootstrap page whose inline JavaScript:

  1. POSTs the on-disk admin credentials to Donetick's
     ``/api/v1/auth/login`` endpoint.
  2. Reads the ``access_token``, ``access_token_expiry``, and
     ``refresh_token_expiry`` fields from the JSON response.
  3. ``localStorage.setItem('token', ...)`` for each.
  4. Sets a ``donetick_auth_done`` cookie (HttpOnly, ours)
     so subsequent navigations skip the bootstrap page.
  5. ``window.location.replace(<original_path>)`` to load the
     real SPA, which now boots fully authenticated.

The HttpOnly ``refresh_token`` cookie is set by Donetick's
own login handler and survives across the location.replace,
so the SPA's silent-refresh path works once the user lands.

Why an HTML bootstrap page instead of a 303 + Set-Cookie?
Donetick's SPA stores its JWT in localStorage, not in a
cookie.  A 303 + Set-Cookie can't reach localStorage; we need
JavaScript to run on the visitor's browser to write to it.
A small HTML page with inline JS is the cleanest way to do
that — same shape as the openhost-plane.so cookie-stamping
trick, but writing to localStorage instead of cookies.

Defence in depth: the proxy ALSO injects
``Authorization: Bearer <token>`` is NOT possible here
because the SPA-issued requests carry their own header from
localStorage, and we don't want to override the SPA's
Authorization (multi-user accounts in Donetick mean the SPA
might be acting on behalf of a non-admin user later).  We
trust the SPA to attach its own auth, and the proxy is just
a header-gate + bootstrap server.

Auth model summary:

  * Anonymous (no zone_auth)       → OpenHost router 302's to
                                      /login BEFORE reaching us.
  * Owner, has Donetick session    → forward unchanged.
  * Owner, no Donetick session     → serve bootstrap HTML
                                      page.  Page JS does the
                                      login dance.
  * Non-owner reaching us somehow  → 403.

This proxy uses only Python stdlib — no third-party deps.
"""

from __future__ import annotations

import http.client
import json
import logging
import os
import re
import socket
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import AbstractSet, Iterable

# -- Constants -----------------------------------------------------

OWNER_HEADER_NAME = "X-OpenHost-Is-Owner"
USER_HEADER_NAME = "X-OpenHost-User"

# Cookie we set ourselves to mark "the bootstrap page already
# stamped localStorage; don't run it again."  Without this
# marker we'd bootstrap on every navigation because we can't
# read localStorage from the proxy.  HttpOnly so JS can't
# tamper; SameSite=Lax so it survives top-level navigations.
BOOTSTRAP_DONE_COOKIE = "donetick_auth_done"

# Donetick's login endpoint.  Verified against
# internal/user/handler.go:1652 (authRoutes := router.Group(
# "api/v1/auth"); authRoutes.POST("login",
# authHandler.EnhancedLoginHandler)).
DONETICK_LOGIN_PATH = "/api/v1/auth/login"

# Hop-by-hop headers (RFC 9110 §7.6.1) plus a few we rewrite
# at the proxy seam.
HOP_BY_HOP_HEADERS = frozenset(
    h.lower()
    for h in (
        "Connection",
        "Keep-Alive",
        "Proxy-Authenticate",
        "Proxy-Authorization",
        "TE",
        "Trailer",
        "Transfer-Encoding",
        "Upgrade",
        "Host",
        "Content-Length",
    )
)

# Trust headers a hostile client could try to forge.
ALWAYS_STRIP_HEADERS = frozenset(
    h.lower() for h in (OWNER_HEADER_NAME, USER_HEADER_NAME)
)

CLIENT_READ_TIMEOUT_SECONDS = 60
MAX_BODY_BYTES = 64 * 1024 * 1024

logging.basicConfig(
    level=os.environ.get("AUTH_PROXY_LOG_LEVEL", "INFO"),
    format="[auth-proxy] %(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("auth_proxy")


# -- Helpers -------------------------------------------------------


def _parse_cookie_header(cookie_header: str | None) -> dict[str, str]:
    """First-value-wins RFC6265 cookie parser."""
    if not cookie_header:
        return {}
    result: dict[str, str] = {}
    for part in cookie_header.split(";"):
        if "=" not in part:
            continue
        name, value = part.split("=", 1)
        result.setdefault(name.strip(), value.strip())
    return result


def _strip_headers(
    headers: Iterable[tuple[str, str]], drop: AbstractSet[str]
) -> list[tuple[str, str]]:
    drop_lower = {h.lower() for h in drop}
    return [(k, v) for k, v in headers if k.lower() not in drop_lower]


def _read_admin_creds(cred_file: str) -> tuple[str, str] | None:
    """Read DONETICK_ADMIN_USERNAME / DONETICK_ADMIN_PASSWORD from
    start.sh's credentials file.

    Format: ``KEY=VALUE`` lines, optionally single-quoted.
    """
    try:
        with open(cred_file, encoding="utf-8") as fh:
            content = fh.read()
    except FileNotFoundError:
        return None
    user = password = None
    for line in content.splitlines():
        m = re.match(
            r"^\s*(?:export\s+)?"
            r"(DONETICK_ADMIN_USERNAME|DONETICK_ADMIN_PASSWORD)"
            r"\s*=\s*(.*?)\s*$",
            line,
        )
        if not m:
            continue
        key, val = m.group(1), m.group(2)
        if len(val) >= 2 and val[0] == val[-1] and val[0] in ("'", '"'):
            val = val[1:-1]
        if key == "DONETICK_ADMIN_USERNAME":
            user = val
        elif key == "DONETICK_ADMIN_PASSWORD":
            password = val
    if user and password:
        return user, password
    return None


# Bootstrap HTML page.
#
# Inline JavaScript that:
#   1. POST /api/v1/auth/login with admin creds.
#   2. Stamp localStorage from the JSON response.
#   3. Set the donetick_auth_done marker cookie via fetch
#      (the proxy returns Set-Cookie on the response).
#   4. window.location.replace(target_path).
#
# We embed the credentials INTO the page JS, which is fine:
# the page is only served to authenticated zone owners (the
# OpenHost router gates anything reaching us, and the
# auth-proxy verifies X-OpenHost-Is-Owner).  Anyone who can
# read this page already had owner-level access.
#
# The page deliberately does NOT use innerHTML or eval; all
# DOM mutations are via textContent so a CSP that disallows
# inline scripts (which we don't ship by default but might
# add later) doesn't break us.  Inline script is the only
# JS source — no external CDN, no build step, no module.

_BOOTSTRAP_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Signing in to Donetick…</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  body {{
    font-family: system-ui, -apple-system, sans-serif;
    background: #1a1a1a; color: #e0e0e0;
    display: flex; align-items: center; justify-content: center;
    min-height: 100vh; margin: 0; padding: 1rem;
  }}
  .card {{
    background: #2a2a2a;
    border-radius: 8px;
    padding: 2rem 3rem;
    max-width: 480px;
    text-align: center;
    box-shadow: 0 4px 16px rgba(0,0,0,0.4);
  }}
  h1 {{ font-size: 1.25rem; margin: 0 0 1rem; font-weight: 500; }}
  p  {{ font-size: 0.9rem; color: #aaa; margin: 0.5rem 0; }}
  .err {{ color: #f87171; }}
</style>
</head>
<body>
<div class="card">
  <h1>Signing in to Donetick…</h1>
  <p id="status">Authenticating with the zone identity.</p>
</div>
<script>
(async function(){{
  var statusEl = document.getElementById('status');
  function fail(msg) {{
    statusEl.textContent = msg;
    statusEl.className = 'err';
  }}
  try {{
    var resp = await fetch({login_path_json}, {{
      method: 'POST',
      credentials: 'same-origin',
      headers: {{ 'Content-Type': 'application/json' }},
      body: JSON.stringify({{
        username: {username_json},
        password: {password_json},
      }}),
    }});
    if (!resp.ok) {{
      fail('Login failed (HTTP ' + resp.status + '). The on-disk admin ' +
           'credentials may not match Donetick\\u0027s database state. ' +
           'See container logs for details.');
      return;
    }}
    var data = await resp.json();
    var accessToken = data.access_token || data.token;
    var accessExpiry = data.access_token_expiry || data.expire;
    var refreshExpiry = data.refresh_token_expiry;
    if (!accessToken) {{
      fail('Login response had no access_token. This is a bug; please ' +
           'file an issue.');
      return;
    }}
    localStorage.setItem('token', accessToken);
    if (accessExpiry) localStorage.setItem('token_expiry', accessExpiry);
    if (refreshExpiry) localStorage.setItem('refresh_token_expiry', refreshExpiry);

    // Tell the auth-proxy we successfully bootstrapped, so it
    // stops serving this HTML page on subsequent navigations.
    // We make a tiny fetch to a marker URL — the proxy
    // intercepts it and 204s back with the cookie set.
    await fetch({marker_path_json}, {{
      method: 'POST',
      credentials: 'same-origin',
    }});

    statusEl.textContent = 'Loading Donetick…';
    window.location.replace({target_url_json});
  }} catch (err) {{
    fail('Unexpected error during sign-in: ' + (err.message || err));
  }}
}})();
</script>
</body>
</html>
"""

# Marker path the bootstrap HTML JS POSTs to in step (3),
# triggering the proxy to set the donetick_auth_done cookie.
# Chosen to be path that Donetick definitely doesn't route on,
# so a request that bypasses our proxy doesn't accidentally
# match it.  Underscored prefix is a hint to anyone reading
# logs that this is an internal proxy convention.
BOOTSTRAP_MARKER_PATH = "/_openhost_donetick_bootstrap_done"


def _build_bootstrap_html(
    target_path: str, username: str, password: str
) -> bytes:
    """Render the bootstrap HTML page with creds + target embedded.

    All values are JSON-encoded into the page (rather than
    string-interpolated into JS) so the page is robust against
    quotes / backslashes / unicode in the credentials and
    target path.  json.dumps handles these the same way the
    JS Object literal would.
    """
    body = _BOOTSTRAP_HTML_TEMPLATE.format(
        login_path_json=json.dumps(DONETICK_LOGIN_PATH),
        username_json=json.dumps(username),
        password_json=json.dumps(password),
        marker_path_json=json.dumps(BOOTSTRAP_MARKER_PATH),
        target_url_json=json.dumps(target_path),
    )
    return body.encode("utf-8")


def _build_marker_set_cookie(secure: bool) -> str:
    """Return Set-Cookie value that pins the bootstrap-done marker.

    HttpOnly: nothing inside the SPA reads it; only the proxy
        does, and we want browser-level protection from XSS.
    SameSite=Lax: same-origin only flows.
    Max-Age = 1 year: matches the JWT lifetime.  Rotation =
        operator clears the cookie + restarts container.
    Secure when behind HTTPS.
    """
    parts = [
        f"{BOOTSTRAP_DONE_COOKIE}=1",
        "Path=/",
        "HttpOnly",
        "SameSite=Lax",
        "Max-Age=31536000",
    ]
    if secure:
        parts.append("Secure")
    return "; ".join(parts)


# -- Request handler -----------------------------------------------


class AuthProxyHandler(BaseHTTPRequestHandler):
    upstream_host: str = "127.0.0.1"
    upstream_port: int = 2021
    cred_file: str = "/data/app_data/donetick/admin-credentials.txt"

    def log_message(self, format: str, *args) -> None:  # noqa: A002, N802
        log.info("%s - " + format, self.address_string(), *args)

    def do_GET(self) -> None:  # noqa: N802
        self._dispatch()

    def do_HEAD(self) -> None:  # noqa: N802
        self._dispatch()

    def do_POST(self) -> None:  # noqa: N802
        self._dispatch()

    def do_PUT(self) -> None:  # noqa: N802
        self._dispatch()

    def do_DELETE(self) -> None:  # noqa: N802
        self._dispatch()

    def do_PATCH(self) -> None:  # noqa: N802
        self._dispatch()

    def do_OPTIONS(self) -> None:  # noqa: N802
        self._dispatch()

    def _safe_send_error(self, code: int, message: str) -> None:
        try:
            self.send_error(code, message)
        except OSError as exc:
            log.debug("client disconnected before error response: %s", exc)

    def _dispatch(self) -> None:
        try:
            self.connection.settimeout(CLIENT_READ_TIMEOUT_SECONDS)
        except OSError:
            pass

        path = self.path or ""

        # Auth gate.
        is_owner = (
            self.headers.get(OWNER_HEADER_NAME, "").lower() == "true"
        )
        if not is_owner:
            self._safe_send_error(403, "Forbidden")
            return

        cookies = _parse_cookie_header(self.headers.get("Cookie"))

        # Bootstrap-done marker endpoint: when the bootstrap
        # HTML page successfully stamps localStorage, its JS
        # POSTs to this path.  We respond 204 + Set-Cookie so
        # subsequent navigations skip the bootstrap page.
        marker_path = BOOTSTRAP_MARKER_PATH
        if path == marker_path or path.startswith(marker_path + "?"):
            self._serve_marker()
            return

        # First owner navigation without the bootstrap-done
        # marker: serve the bootstrap HTML page.  Restrict to
        # GET requests with Accept: text/html so XHR + asset
        # fetches don't ricochet through the bootstrap.
        accept = self.headers.get("Accept", "")
        is_html_navigation = (
            self.command == "GET"
            and "text/html" in accept.lower()
        )
        has_bootstrap_marker = BOOTSTRAP_DONE_COOKIE in cookies

        if is_html_navigation and not has_bootstrap_marker:
            if self._serve_bootstrap_html():
                return
            # If bootstrap couldn't be served (creds missing),
            # fall through to upstream so the user sees
            # Donetick's own login form.

        # Pass through.
        self._proxy()

    def _serve_marker(self) -> None:
        """Set the bootstrap-done cookie and 204."""
        secure = (
            self.headers.get("X-Forwarded-Proto", "").lower() == "https"
        )
        try:
            self.send_response(204, "No Content")
            self.send_header("Set-Cookie", _build_marker_set_cookie(secure=secure))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
        except OSError as exc:
            log.debug("client disconnected during marker response: %s", exc)

    def _serve_bootstrap_html(self) -> bool:
        """Render and serve the bootstrap HTML.  Returns True iff
        the page was successfully sent; False if creds are
        missing and the caller should fall through.
        """
        creds = _read_admin_creds(self.cred_file)
        if creds is None:
            log.warning(
                "bootstrap: credentials file missing or unreadable at %s; "
                "falling through to manual login",
                self.cred_file,
            )
            return False
        username, password = creds

        # Ensure the target path is same-origin to defend
        # against open-redirect via attacker-controlled path.
        target_path = self.path or "/"
        parsed = urllib.parse.urlparse(target_path)
        if parsed.scheme or parsed.netloc:
            target_path = "/"

        body = _build_bootstrap_html(target_path, username, password)
        try:
            self.send_response(200, "OK")
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            # Don't allow framing — the bootstrap page would
            # never be embedded legitimately, so deny it
            # outright.
            self.send_header("X-Frame-Options", "DENY")
            self.end_headers()
            self.wfile.write(body)
        except OSError as exc:
            log.debug("client disconnected mid-bootstrap: %s", exc)
            return True  # we tried
        return True

    # -- HTTP forward ---------------------------------------------

    def _proxy(self) -> None:
        cleaned_headers = _strip_headers(
            self.headers.items(),
            HOP_BY_HOP_HEADERS | ALWAYS_STRIP_HEADERS,
        )

        transfer_encoding = (
            self.headers.get("Transfer-Encoding", "").lower().strip()
        )
        if transfer_encoding and transfer_encoding != "identity":
            self._safe_send_error(501, "Transfer-Encoding not supported")
            return

        body: bytes | None = None
        content_length_header = self.headers.get("Content-Length")
        if content_length_header:
            try:
                length = int(content_length_header)
            except ValueError:
                self._safe_send_error(400, "invalid Content-Length")
                return
            if length < 0:
                self._safe_send_error(400, "negative Content-Length")
                return
            if length > MAX_BODY_BYTES:
                self._safe_send_error(413, "request body too large")
                return
            if length > 0:
                try:
                    body = self.rfile.read(length)
                except (OSError, TimeoutError) as exc:
                    log.info("client read error: %s", exc)
                    self._safe_send_error(400, "request body read failed")
                    return
                if len(body) != length:
                    log.info(
                        "short read: expected %d bytes, got %d",
                        length,
                        len(body),
                    )
                    self._safe_send_error(400, "incomplete request body")
                    return
            else:
                body = b""
        elif self.command in ("POST", "PUT", "PATCH", "DELETE"):
            body = b""

        conn = http.client.HTTPConnection(
            self.upstream_host, self.upstream_port, timeout=60
        )
        try:
            try:
                conn.putrequest(
                    self.command,
                    self.path,
                    skip_host=False,
                    skip_accept_encoding=True,
                )
                for key, value in cleaned_headers:
                    conn.putheader(key, value)
                if body is not None:
                    conn.putheader("Content-Length", str(len(body)))
                conn.endheaders(message_body=body)
                upstream = conn.getresponse()
            except (OSError, http.client.HTTPException) as exc:
                log.warning("upstream error: %s", exc)
                self._safe_send_error(502, "Bad Gateway")
                return

            try:
                payload = upstream.read(MAX_BODY_BYTES + 1)
            except (OSError, http.client.HTTPException) as exc:
                log.warning("upstream read error: %s", exc)
                self._safe_send_error(502, "Bad Gateway")
                try:
                    upstream.close()
                except Exception as close_exc:  # noqa: BLE001 - best effort
                    log.debug("upstream.close() raised: %s", close_exc)
                return
            try:
                upstream.close()
            except Exception as exc:  # noqa: BLE001 - best effort only
                log.debug("upstream.close() raised (ignored): %s", exc)
            if len(payload) > MAX_BODY_BYTES:
                log.warning(
                    "upstream response exceeded %d bytes; returning 502",
                    MAX_BODY_BYTES,
                )
                self._safe_send_error(502, "upstream response too large")
                return

            reason = upstream.reason or ""
            try:
                self.send_response(upstream.status, reason)
                for key, value in upstream.getheaders():
                    if key.lower() in HOP_BY_HOP_HEADERS:
                        continue
                    self.send_header(key, value)
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(payload)
            except OSError as exc:
                log.debug("client disconnected mid-response: %s", exc)
        finally:
            conn.close()


# -- Server bootstrap ---------------------------------------------


class IPv4ThreadingServer(ThreadingHTTPServer):
    address_family = socket.AF_INET
    allow_reuse_address = True
    daemon_threads = True


def _port_from_env(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        port = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name}={raw!r} is not an integer: {exc}") from exc
    if not 1 <= port <= 65535:
        raise ValueError(f"{name}={raw!r} is out of range (1-65535)")
    return port


def main() -> int:
    try:
        listen_port = _port_from_env("AUTH_PROXY_LISTEN_PORT", 2022)
        upstream_port = _port_from_env("AUTH_PROXY_UPSTREAM_PORT", 2021)
    except ValueError as exc:
        log.error("invalid port configuration: %s", exc)
        return 1

    upstream_host = (
        os.environ.get("AUTH_PROXY_UPSTREAM_HOST", "").strip() or "127.0.0.1"
    )
    cred_file = os.environ.get(
        "AUTH_PROXY_CRED_FILE",
        "/data/app_data/donetick/admin-credentials.txt",
    )

    AuthProxyHandler.upstream_host = upstream_host
    AuthProxyHandler.upstream_port = upstream_port
    AuthProxyHandler.cred_file = cred_file

    try:
        server = IPv4ThreadingServer(
            ("0.0.0.0", listen_port), AuthProxyHandler
        )
    except OSError as exc:
        log.error(
            "failed to bind auth-proxy listener on 0.0.0.0:%d: %s",
            listen_port,
            exc,
        )
        return 1
    log.info(
        "listening on 0.0.0.0:%d -> %s:%d (creds=%s)",
        listen_port,
        upstream_host,
        upstream_port,
        cred_file,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
