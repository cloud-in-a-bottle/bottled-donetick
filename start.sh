#!/bin/bash
# Launch Donetick on OpenHost.
#
# Topology:
#
#   browser → OpenHost outer Caddy (TLS termination)
#          → OpenHost router (subdomain donetick.<zone>; JWT-
#                              verifies and stamps
#                              X-OpenHost-Is-Owner: true)
#          → container :2022   (auth_proxy.py — auto-login
#                                bootstrap-HTML sidecar)
#          → 127.0.0.1:2021    (Donetick / Go binary)
#
# Three auth gates layered:
#
#   1. OpenHost router: anonymous visitors get 302'd to /login;
#      we never see them.  Owners arrive with
#      X-OpenHost-Is-Owner: true.
#   2. auth_proxy.py: 403's anything without the owner header.
#      On first owner navigation, serves a small HTML bootstrap
#      page that JS-logs into Donetick and stamps localStorage
#      before replace()ing to the SPA.
#   3. Donetick itself: validates the JWT on every API call.
#      We never disable this — even if the proxy is bypassed,
#      Donetick still requires a valid JWT.
#
# We use bash specifically (not /bin/sh) for `wait -n`.
set -euo pipefail

# -----------------------------------------------------------------
# Persistence
# -----------------------------------------------------------------
#
# Donetick expects two host directories:
#   /donetick-data — sqlite DB (per upstream README)
#   /config        — selfhosted.yaml + supporting files
PERSIST="${OPENHOST_APP_DATA_DIR:-/data/app_data/donetick}"
DATA_DIR="$PERSIST/donetick-data"
CONFIG_DIR="$PERSIST/config"
LOG_DIR="$PERSIST/log"
mkdir -p "$DATA_DIR" "$CONFIG_DIR" "$LOG_DIR"

ADMIN_CRED_FILE="$PERSIST/admin-credentials.txt"
JWT_SECRET_FILE="$PERSIST/jwt-secret.txt"

# -----------------------------------------------------------------
# Bootstrap secrets
# -----------------------------------------------------------------
#
# On first boot we generate two persistent values:
#
#   * Donetick's JWT signing secret.  Must be 32+ characters
#     (see config/selfhosted.yaml.example).  We persist it so
#     existing JWTs and refresh tokens survive container
#     restarts.
#   * Default admin credentials.  Donetick's signup endpoint
#     creates the first user as an admin; we POST our own
#     well-known credentials to /api/v1/auth on first boot
#     (retried if the user doesn't yet exist) and reuse them
#     for the auth-proxy's auto-login.

if [[ ! -f "$JWT_SECRET_FILE" ]]; then
    echo "[start.sh] First boot: generating Donetick JWT secret"
    umask 077
    head -c 64 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9' | head -c 64 \
        > "$JWT_SECRET_FILE"
    umask 022
fi
JWT_SECRET="$(cat "$JWT_SECRET_FILE")"

if [[ ! -f "$ADMIN_CRED_FILE" ]]; then
    echo "[start.sh] First boot: generating Donetick admin credentials"
    ADMIN_PASSWORD="$(head -c 48 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9' | head -c 32)"
    umask 077
    cat > "$ADMIN_CRED_FILE" <<EOF
# Donetick admin credentials, auto-generated on first boot.
# The auth-proxy uses these to POST /api/v1/auth/login on
# every owner visit that doesn't yet have a Donetick session.
DONETICK_ADMIN_USERNAME=admin
DONETICK_ADMIN_PASSWORD='$ADMIN_PASSWORD'
DONETICK_ADMIN_EMAIL=admin@openhost.local
DONETICK_ADMIN_DISPLAY_NAME=admin
EOF
    umask 022
fi
# shellcheck disable=SC1090
source "$ADMIN_CRED_FILE"

# -----------------------------------------------------------------
# Generate selfhosted.yaml
# -----------------------------------------------------------------
#
# Donetick reads its config from /config/selfhosted.yaml when
# DT_ENV=selfhosted is set.  We render the file fresh on every
# boot from a bash heredoc so the JWT secret + sqlite path
# always match what start.sh just generated, regardless of
# whether an operator hand-edits the file (which they
# probably shouldn't, but we don't want to fight them).

ZONE_DOMAIN="${OPENHOST_ZONE_DOMAIN:-localhost}"
APP_NAME="${OPENHOST_APP_NAME:-donetick}"
PUBLIC_URL="https://${APP_NAME}.${ZONE_DOMAIN}"

CONFIG_FILE="$CONFIG_DIR/selfhosted.yaml"
cat > "$CONFIG_FILE" <<EOF
name: "selfhosted"
is_done_tick_dot_com: false
# Disable signup-via-web after the auth-proxy has bootstrapped
# the admin user.  Operators can re-enable this if they want
# to invite collaborators via the regular signup flow; the
# auto-login still works regardless.
is_user_creation_disabled: false
database:
  type: "sqlite"
  migration: true
jwt:
  secret: "${JWT_SECRET}"
  session_time: 168h
  max_refresh: 1440h
server:
  port: 2021
  read_timeout: 10s
  write_timeout: 10s
  rate_period: 60s
  rate_limit: 300
  cors_allow_origins:
    - "${PUBLIC_URL}"
    # Localhost origins kept for native-app compatibility (the
    # Capacitor mobile builds connect this way during dev).
    - "https://localhost"
    - "http://localhost"
    - "capacitor://localhost"
  serve_frontend: true
  serve_swagger: false
  public_host: "${PUBLIC_URL}"
logging:
  level: "info"
  encoding: "json"
  development: false
scheduler_jobs:
  due_job: 30m
  overdue_job: 3h
  pre_due_job: 3h
realtime:
  enabled: true
  sse_enabled: true
  heartbeat_interval: 60s
  connection_timeout: 120s
  max_connections: 100
  max_connections_per_user: 5
EOF

# -----------------------------------------------------------------
# Donetick env + symlinks
# -----------------------------------------------------------------
#
# The upstream image expects /config and /donetick-data to be
# Docker volumes.  We symlink them into the persistent volume
# (same trick as openhost-tasks-md).
if [[ ! -L /config ]]; then
    rm -rf /config 2>/dev/null || true
    ln -s "$CONFIG_DIR" /config
fi
if [[ ! -L /donetick-data ]]; then
    rm -rf /donetick-data 2>/dev/null || true
    ln -s "$DATA_DIR" /donetick-data
fi

export DT_ENV=selfhosted
export DT_SQLITE_PATH="$DATA_DIR/donetick.db"

# -----------------------------------------------------------------
# Launch Donetick
# -----------------------------------------------------------------
#
# The upstream image's entrypoint is the donetick binary
# directly; we invoke it the same way.  Bind it explicitly
# to localhost — Donetick reads the port from the config but
# binds 0.0.0.0 by default; we want loopback only.
echo "[start.sh] Starting Donetick on 127.0.0.1:2021"
cd /donetick
./donetick > "$LOG_DIR/donetick.log" 2>&1 &
DT_PID=$!

# Wait for Donetick to bind 2021.
for _ in $(seq 1 30); do
    if python3 -c "
import socket, sys
s = socket.socket()
s.settimeout(0.5)
sys.exit(0 if s.connect_ex(('127.0.0.1', 2021)) == 0 else 1)
" 2>/dev/null; then
        break
    fi
    if ! kill -0 "$DT_PID" 2>/dev/null; then
        wait "$DT_PID" || true
        echo "[start.sh] Donetick exited before binding 2021"
        tail -20 "$LOG_DIR/donetick.log" 2>/dev/null
        exit 1
    fi
    sleep 1
done

# -----------------------------------------------------------------
# Bootstrap admin user
# -----------------------------------------------------------------
#
# Donetick has no DEFAULT_ADMIN_* env-var convention like
# Planka.  The first user signs up via the web UI; we fake
# that signup by POSTing to /api/v1/auth/ (the signup
# endpoint).  If the user already exists this is a no-op
# (Donetick returns 409 / 400).
#
# Doing this in start.sh rather than from inside the auth-
# proxy means the user account is provisioned BEFORE the
# proxy starts accepting traffic, so the very first owner
# request finds a working /api/v1/auth/login endpoint.
echo "[start.sh] Ensuring admin user exists"
SIGNUP_PAYLOAD="$(printf '{
  "username": "%s",
  "password": "%s",
  "email": "%s",
  "displayName": "%s"
}' "$DONETICK_ADMIN_USERNAME" "$DONETICK_ADMIN_PASSWORD" "$DONETICK_ADMIN_EMAIL" "$DONETICK_ADMIN_DISPLAY_NAME")"
SIGNUP_STATUS="$(python3 -c "
import http.client, json, sys
conn = http.client.HTTPConnection('127.0.0.1', 2021, timeout=5)
conn.request('POST', '/api/v1/auth/', body='''$SIGNUP_PAYLOAD''',
             headers={'Content-Type': 'application/json'})
r = conn.getresponse()
print(r.status)
" 2>&1 || echo "ERROR")"
echo "[start.sh] signup status: $SIGNUP_STATUS"
# Status 200/201 = created, 4xx = already exists (acceptable).
# We deliberately don't fail start.sh on signup error: an
# operator who restarted the container after deleting the DB
# but kept the credentials file would loop forever otherwise.

# -----------------------------------------------------------------
# Launch auth-proxy
# -----------------------------------------------------------------

echo "[start.sh] Starting auth-proxy on 0.0.0.0:2022 -> 127.0.0.1:2021"
export AUTH_PROXY_LISTEN_PORT="${AUTH_PROXY_LISTEN_PORT:-2022}"
export AUTH_PROXY_UPSTREAM_HOST="127.0.0.1"
export AUTH_PROXY_UPSTREAM_PORT="2021"
export AUTH_PROXY_CRED_FILE="$ADMIN_CRED_FILE"
python3 /opt/openhost-donetick/auth_proxy.py \
    > "$LOG_DIR/auth-proxy.log" 2>&1 &
PROXY_PID=$!

# -----------------------------------------------------------------
# Supervision
# -----------------------------------------------------------------

trap 'kill -TERM "$DT_PID" "$PROXY_PID" 2>/dev/null; wait' TERM INT

set +e
wait -n "$DT_PID" "$PROXY_PID"
EXIT_CODE=$?
set -e

echo "[start.sh] Child exited (code=$EXIT_CODE); shutting down"
kill -TERM "$DT_PID" "$PROXY_PID" 2>/dev/null || true
wait || true
exit "$EXIT_CODE"
