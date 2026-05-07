# OpenHost Donetick container.
#
# Layers an OpenHost auth-proxy sidecar on top of the upstream
# Donetick Go binary.  The auth-proxy renders a tiny HTML
# bootstrap page on the first owner visit that JS-stamps the
# JWT into localStorage; subsequent requests pass through to
# Donetick verbatim.
#
# Auth flow:
#
#   1. Browser hits https://donetick.<zone>/.  The OpenHost
#      router verifies the visitor's zone_auth JWT and stamps
#      X-OpenHost-Is-Owner: true on the request before
#      forwarding to the auth-proxy on container port 2022.
#   2. Auth-proxy: if owner AND no `token` localStorage entry
#      yet (we detect this by looking for the
#      `donetick_auth_done` cookie that the bootstrap page
#      sets on completion), serve the bootstrap HTML page.
#      Otherwise pass through to Donetick.
#   3. Bootstrap page JS POSTs admin creds to
#      /api/v1/auth/login, captures the JWT, stamps
#      localStorage, sets the marker cookie, and
#      window.location.replaces() to the original URL.
#   4. The SPA loads, reads the JWT from localStorage, and
#      operates normally.
#
# This is a variant of the openhost-minio auto-login pattern
# tailored to Donetick's localStorage-based SPA storage.

# Stage 1: lift the upstream Donetick binary + bundled SPA.
#
# Pin to v0.1.75 (latest stable as of Apr 2026) by image tag.
# The upstream image is published to docker.io/donetick/donetick.
FROM docker.io/donetick/donetick:v0.1.75 AS donetick-source

# Stage 2: build the runtime image.
#
# We need (a) the Donetick binary + bundled SPA, and (b)
# Python 3 + bash for the auth-proxy + start.sh.  Donetick's
# upstream image is alpine-based and is already very small;
# layering Python on top adds ~50 MiB.
#
# A leaner alternative would be `FROM scratch` + just the
# Donetick binary + auth-proxy translated to Go, but the
# Python auth-proxy is the OpenHost-wide template and
# matching it across apps keeps the surface area small.
FROM docker.io/donetick/donetick:v0.1.75

USER root

# -- Python + bash for the auth-proxy + start.sh ----------------
RUN apk add --no-cache python3 bash

# -- auth-proxy + start.sh -------------------------------------
#
# Both files are committed with mode 0755 (verify with
# `git ls-files --stage`).
COPY auth_proxy.py /opt/openhost-donetick/auth_proxy.py
COPY start.sh      /opt/openhost-donetick/start.sh

# -- runtime ---------------------------------------------------
#
# 2022 = auth-proxy (the openhost.toml `port`).
# 2021 = Donetick (loopback only via start.sh; never EXPOSE'd).
EXPOSE 2022

ENTRYPOINT ["/opt/openhost-donetick/start.sh"]
