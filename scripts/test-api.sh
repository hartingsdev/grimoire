#!/usr/bin/env bash
# Spielt die API mit einem echten Key durch — einmal mit einem Lese-Key und
# einmal mit einem Schreib-Key. Prüft ausdrücklich auch, was NICHT gehen darf.
#
#   ./scripts/test-api.sh http://localhost:8080 plk_privat_… [plk_privat_…]
#                         ^ Basisadresse      ^ Lese-Key      ^ Schreib-Key
set -uo pipefail

BASE="${1:-http://localhost:8080}"
READ_KEY="${2:-${PROMPT_LIBRARY_READ_KEY:-}}"
WRITE_KEY="${3:-${PROMPT_LIBRARY_WRITE_KEY:-}}"

if [[ -z "$READ_KEY" ]]; then
  echo "Aufruf: $0 <basisadresse> <lese-key> [schreib-key]" >&2
  echo "Keys werden in der Oberfläche unter 'API-Keys' erzeugt." >&2
  exit 2
fi

pass=0; fail=0
check() { # check <beschreibung> <erwarteter-status> <tatsächlicher-status> [antwort]
  if [[ "$2" == "$3" ]]; then
    printf '  \033[32mok\033[0m   %-52s %s\n' "$1" "$3"; pass=$((pass+1))
  else
    printf '  \033[31mFEHL\033[0m %-52s %s (erwartet %s)\n' "$1" "$3" "$2"; fail=$((fail+1))
    [[ -n "${4:-}" ]] && echo "       $4"
  fi
}
status() { # status <methode> <pfad> <key> [rumpf]
  local args=(-s -o /tmp/pl_body -w '%{http_code}' -X "$1" "$BASE$2")
  [[ -n "$3" ]] && args+=(-H "Authorization: Bearer $3")
  [[ -n "${4:-}" ]] && args+=(-H 'Content-Type: application/json' -d "$4")
  curl "${args[@]}"
}
body() { cat /tmp/pl_body; }

echo
echo "Lesen und Identität"
check "GET /api/v1/me"                200 "$(status GET /api/v1/me "$READ_KEY")" "$(body)"
check "GET /api/v1/prompts"           200 "$(status GET /api/v1/prompts "$READ_KEY")" "$(body)"
check "GET /api/v1/tags"              200 "$(status GET /api/v1/tags "$READ_KEY")"
check "Suche mit q="                  200 "$(status GET '/api/v1/prompts?q=test&limit=5' "$READ_KEY")"

echo
echo "Was ein Lese-Key nicht darf"
check "POST /api/v1/prompts"          403 "$(status POST /api/v1/prompts "$READ_KEY" '{"title":"x","body":"y"}')"
check "DELETE /api/v1/prompts/{id}"   403 "$(status DELETE /api/v1/prompts/egal "$READ_KEY")"

echo
echo "Was KEIN Key darf — Verwaltung bleibt dem Browser vorbehalten"
for path in /api/v1/api-keys /api/v1/admin/users /api/v1/admin/audit; do
  check "GET $path" 403 "$(status GET "$path" "$READ_KEY")" "$(body)"
done
check "POST /api/v1/api-keys (Key kann keine Keys erzeugen)" \
      403 "$(status POST /api/v1/api-keys "$READ_KEY" '{"name":"x","role":"editor"}')"

echo
echo "Ungültige Keys"
check "ohne Authorization"            401 "$(status GET /api/v1/prompts "")"
check "Unsinn als Key"                401 "$(status GET /api/v1/prompts "voellig-falsch")"
check "Key der anderen Instanz"       401 \
      "$(status GET /api/v1/prompts "$(sed 's/_privat_/_arbeit_/; s/_arbeit_/_privat_/2' <<<"$READ_KEY")")"

if [[ -n "$WRITE_KEY" ]]; then
  echo
  echo "Schreiben mit einem Schreib-Key"
  code=$(status POST /api/v1/prompts "$WRITE_KEY" \
    '{"title":"Testeintrag aus test-api.sh","body":"Zeile eins\nZeile zwei","tags":["test","automatisch"]}')
  check "POST /api/v1/prompts" 201 "$code" "$(body)"
  id=$(sed -n 's/.*"id":"\([^"]*\)".*/\1/p' /tmp/pl_body | head -1)

  if [[ -n "$id" ]]; then
    check "GET  /api/v1/prompts/$id"        200 "$(status GET "/api/v1/prompts/$id" "$WRITE_KEY")"
    check "PATCH /api/v1/prompts/{id}"      200 "$(status PATCH "/api/v1/prompts/$id" "$WRITE_KEY" '{"title":"Geändert"}')"
    check "GET  …/revisions"                200 "$(status GET "/api/v1/prompts/$id/revisions" "$WRITE_KEY")"
    check "Lese-Key sieht den neuen Eintrag" 200 "$(status GET "/api/v1/prompts/$id" "$READ_KEY")"
    check "DELETE /api/v1/prompts/{id}"     204 "$(status DELETE "/api/v1/prompts/$id" "$WRITE_KEY")"
    check "danach nicht mehr abrufbar"      404 "$(status GET "/api/v1/prompts/$id" "$WRITE_KEY")"
  else
    echo "  (keine ID aus der Antwort gelesen, Folgeschritte übersprungen)"
  fi
fi

echo
echo "Rate-Limit (kann je nach RATE_LIMIT_PER_MIN eine Weile dauern)"
limit=$(curl -sI -H "Authorization: Bearer $READ_KEY" "$BASE/api/v1/prompts" \
        | tr -d '\r' | sed -n 's/^RateLimit-Limit: //Ip')
echo "  RateLimit-Limit meldet: ${limit:-<fehlt>}"
if [[ -n "$limit" && "$limit" -le 200 ]]; then
  for _ in $(seq 1 $((limit + 5))); do last=$(status GET /api/v1/prompts "$READ_KEY"); done
  check "nach $((limit + 5)) Anfragen" 429 "$last"
else
  echo "  (übersprungen — für einen schnellen Test RATE_LIMIT_PER_MIN kleiner setzen)"
fi

echo
echo "Ergebnis: $pass bestanden, $fail fehlgeschlagen"
[[ "$fail" -eq 0 ]]
