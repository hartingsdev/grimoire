#!/usr/bin/env bash
# Startet die Anwendung lokal gegen den nachgebildeten Anmeldedienst aus
# docker-compose.dev.yml. Bewusst ohne Container, damit Browser und Anwendung
# dieselbe Provider-Adresse benutzen und kein Issuer-Konflikt entsteht.
set -euo pipefail
cd "$(dirname "$0")/.."

if ! curl -sf http://localhost:8090/default/.well-known/openid-configuration >/dev/null; then
  echo "Der nachgebildete Anmeldedienst läuft nicht. Zuerst starten mit:" >&2
  echo "  docker compose -f docker-compose.dev.yml up -d" >&2
  exit 1
fi

export APP_TITLE="Promptory (dev)"
export APP_INSTANCE=privat
export BASE_URL=http://localhost:8080
export LISTEN_ADDR=:8080
export DB_PATH="${DB_PATH:-./data/dev.db}"
export LOG_LEVEL=debug
export STATIC_DIR=./web          # Oberfläche von der Platte: kein Neuübersetzen nötig
export COOKIE_SECURE=false       # lokal ohne TLS
export DATA_ENCRYPTION_KEY="$(printf 'entwicklungsschluessel-32-byte!!' | base64)"

export OIDC_ISSUER=http://localhost:8090/default
export OIDC_CLIENT_ID=promptory
export OIDC_CLIENT_SECRET=geheim
export OIDC_REDIRECT_URI=http://localhost:8080/auth/callback
export OIDC_SCOPES=openid,profile,email
export OIDC_ROLE_CLAIM=groups
export OIDC_ROLE_MAP=pl-viewer:viewer,pl-editor:editor,pl-admin:admin
export OIDC_CLAIMS_SOURCE=both

export PRIVATE_PROMPTS=on
export ADMIN_PRIVATE_ACCESS=break-glass
export RATE_LIMIT_PER_MIN=120
export AUTH_REVALIDATE_INTERVAL=1m   # damit sich Rollenwechsel schnell zeigen

mkdir -p "$(dirname "$DB_PATH")"
echo "Oberfläche: http://localhost:8080"
echo
echo "Beim Anmelden erscheint das Formular des nachgebildeten Anmeldedienstes."
echo "Dort unter 'Claims' eintragen, welche Rolle getestet werden soll:"
echo '  {"groups":["pl-admin"]}    → Administrator'
echo '  {"groups":["pl-editor"]}   → Bearbeiter'
echo '  {"groups":["pl-viewer"]}   → Betrachter'
echo '  {"groups":["sonstwas"]}    → kein Zugriff (erwartet: 403)'
echo
exec go run ./cmd/server
