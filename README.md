# openhost-donetick

[Donetick](https://donetick.com/) — open-source task and chore
management with natural-language task creation, REST + eAPI
tokens, real-time sync, and a calendar/dashboard UI — packaged
as an OpenHost app with seamless OpenHost SSO.

## What you get

- Donetick running on `https://donetick.<zone>/` with TLS
  terminated by the OpenHost outer Caddy.
- The zone owner is auto-logged in to Donetick on first visit.
  No application-level sign-in form ever appears.
- Real-time task sync via SSE.
- REST API + long-lived eAPI tokens for agents and external
  automations (Home Assistant, Telegram, Discord webhooks,
  the official mobile app, ...).
- Persistent state under `/data/app_data/donetick/` — sqlite
  DB, the runtime config, and the on-disk admin credentials
  file.

## Why this app

For an "agent posts task progress that the human user can see
and edit" workflow, Donetick has the best feature set of any
open-source self-hostable task manager:

- **Natural-language task creation:** an agent can write
  "Take the trash out every Monday at 6:15 pm" or "Refactor
  login flow before Friday" and Donetick parses the recurrence
  / due date out automatically. Saves a ton of structured-API
  busywork.
- **eAPI tokens:** explicit long-lived tokens designed for
  automation — distinct from the user-session JWT — so an
  agent's credentials don't get rotated when the human
  signs out and back in.
- **REST API + Webhooks:** every task operation is reachable
  programmatically; tasks can fire webhooks to other systems
  on completion.
- **Subtasks + checklists:** an agent can break a complex
  task into stepwise progress that the human approves item
  by item.
- **Points + analytics:** light gamification for the human
  side; doesn't get in the way of agent automation.
- **Mobile native app:** the human doesn't have to be at a
  laptop to see what the agent is up to.

## Architecture

```
browser
   │
   ▼
OpenHost outer Caddy (TLS)
   │
   ▼
OpenHost router (verifies zone_auth JWT;
                 stamps X-OpenHost-Is-Owner: true)
   │
   ▼
container :2022  ── auth_proxy.py ────────────────┐
                   • on first owner navigation,   │
                     serves a bootstrap HTML      │
                     page whose JS:               │
                       - POSTs admin creds to    │
                         /api/v1/auth/login       │
                       - localStorage-stamps the  │
                         JWT + expiries           │
                       - sets a marker cookie     │
                       - replace()s to the SPA   │
                                                  │
                                                  ▼
                                       127.0.0.1:2021
                                       Donetick (Go binary)
                                                  │
                                                  ▼
                                       /data/app_data/donetick/
                                       donetick-data/donetick.db
```

## Auth model

Donetick's SPA stores its JWT in `localStorage`, not in a
cookie. A 303 + Set-Cookie can't reach localStorage, so the
auth-proxy serves a small HTML bootstrap page on the first
owner visit. The page's inline JavaScript:

1. POSTs `{username, password}` to `/api/v1/auth/login`.
2. Reads the `access_token` and expiries from the JSON
   response.
3. Stamps `localStorage` with the SPA's expected keys
   (`token`, `token_expiry`, `refresh_token_expiry`).
4. POSTs to a marker endpoint that the auth-proxy intercepts
   and replies to with a `Set-Cookie: donetick_auth_done=1`.
5. `window.location.replace()`s to the original URL, where
   the SPA boots fully authenticated.

The marker cookie tells the proxy on subsequent navigations
to skip the bootstrap page (the localStorage already has a
valid JWT). The HTTP-only `refresh_token` cookie set by
Donetick's own login handler enables silent refresh once
the JWT expires, so the operator stays signed in across
weeks without re-bouncing.

## Persistence

```
$OPENHOST_APP_DATA_DIR/
├── donetick-data/
│   └── donetick.db              # sqlite DB
├── config/
│   └── selfhosted.yaml          # runtime config (regenerated each boot)
├── admin-credentials.txt        # DONETICK_ADMIN_* (mode 0600)
├── jwt-secret.txt               # JWT signing secret (mode 0600)
└── log/
    ├── donetick.log
    └── auth-proxy.log
```

## API access (for agents)

Donetick has two API surfaces:

1. **Session JWT API** at `/api/v1/...`. Tied to a user
   session; expires per `jwt.session_time` (default 7 days).
   Read it from the operator's browser localStorage, or POST
   to `/api/v1/auth/login` with the admin creds. Renewed
   silently via the refresh_token cookie.

2. **eAPI** for external automations. Long-lived tokens
   issued from the web UI, designed specifically for clients
   that can't do an interactive login flow. Recommended for
   LLM agents:

```bash
# Get the admin creds:
oh exec donetick cat /data/app_data/donetick/admin-credentials.txt
# DONETICK_ADMIN_USERNAME=admin
# DONETICK_ADMIN_PASSWORD=...

# Sign in via the SPA (auto-login takes care of this), then
# go to Settings → API Tokens → Create New Token. Copy the
# bearer token; it does not expire.

# Use it from anywhere:
TOKEN="..."
curl -H "Authorization: Bearer $TOKEN" \
     https://donetick.<zone>/eapi/v1/chore
```

The OpenHost router gates this endpoint with `zone_auth` /
the OpenHost API token, so an agent calling from outside the
zone needs to attach `Authorization: Bearer <openhost-token>`
ALONGSIDE the eAPI token. The simplest pattern is to run the
agent inside the same zone (as another OpenHost app) so it
reaches Donetick directly via the container loopback or via
the OpenHost router-to-router internal path.

## Limitations

- **No OIDC integration yet.** Donetick supports OIDC upstream
  but OpenHost doesn't yet ship an OIDC issuer. When that
  ships, this package will switch to direct OIDC and the
  bootstrap-HTML hack goes away.
- **localStorage bootstrap is fragile-ish.** If a browser
  extension wipes localStorage between page loads the user
  re-bootstraps; if a CSP gets stricter and forbids inline
  script, the bootstrap breaks. We default to a permissive
  CSP for that reason.
- **Single-admin auto-login.** Multi-user accounts via
  signup work, but the auth-proxy only auto-logs the
  bootstrap admin. Other users have to use Donetick's normal
  password login (which is fine, since they're not getting
  zone-owner privilege).
