#!/usr/bin/env bash
# Runs the app locally against the mock identity provider from
# docker-compose.dev.yml. Deliberately outside Docker, so browser and app use
# the same provider address and no issuer mismatch arises.
set -euo pipefail
cd "$(dirname "$0")/.."

if ! curl -sf http://localhost:8090/default/.well-known/openid-configuration >/dev/null; then
  echo "The mock identity provider is not running. Start it with:" >&2
  echo "  docker compose -f docker-compose.dev.yml up -d" >&2
  exit 1
fi

export APP_TITLE="Grimoire (dev)"
export APP_INSTANCE=personal
export BASE_URL=http://localhost:8080
export LISTEN_ADDR=:8080
export DB_PATH="${DB_PATH:-./data/dev.db}"
export LOG_LEVEL=debug
export STATIC_DIR=./web          # serve the UI from disk: no recompiling
export COOKIE_SECURE=false       # local, no TLS
export DATA_ENCRYPTION_KEY="$(printf 'development-key-32-bytes-long!!!' | base64)"

export OIDC_ISSUER=http://localhost:8090/default
export OIDC_CLIENT_ID=grimoire
export OIDC_CLIENT_SECRET=secret
export OIDC_REDIRECT_URI=http://localhost:8080/auth/callback
export OIDC_SCOPES=openid,profile,email
export OIDC_ROLE_CLAIM=groups
export OIDC_ROLE_MAP=pl-viewer:viewer,pl-editor:editor,pl-admin:admin
export OIDC_CLAIMS_SOURCE=both

export PRIVATE_PROMPTS=on
export ADMIN_PRIVATE_ACCESS=break-glass
export RATE_LIMIT_PER_MIN=120
export AUTH_REVALIDATE_INTERVAL=1m   # so role changes show up quickly

mkdir -p "$(dirname "$DB_PATH")"
echo "UI: http://localhost:8080"
echo
echo "Signing in shows the mock provider's form. Under 'Claims', enter the"
echo "role you want to exercise:"
echo '  {"groups":["pl-admin"]}    → administrator'
echo '  {"groups":["pl-editor"]}   → editor'
echo '  {"groups":["pl-viewer"]}   → viewer'
echo '  {"groups":["something"]}   → no access (expect 403)'
echo
exec go run ./cmd/server
