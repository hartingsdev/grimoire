#!/usr/bin/env bash
# Exercises the API with real keys — one read-only, one read-write. Checks what
# must work, and above all what must not.
#
#   ./scripts/test-api.sh http://localhost:8080 plk_personal_… [plk_personal_…]
#                         ^ base URL           ^ read key      ^ write key
set -uo pipefail

BASE="${1:-http://localhost:8080}"
READ_KEY="${2:-${GRIMOIRE_READ_KEY:-}}"
WRITE_KEY="${3:-${GRIMOIRE_WRITE_KEY:-}}"

if [[ -z "$READ_KEY" ]]; then
  echo "usage: $0 <base-url> <read-key> [write-key]" >&2
  echo "Keys are created in the UI under 'API keys'." >&2
  exit 2
fi

pass=0; fail=0
check() { # check <description> <expected-status> <actual-status> [body]
  if [[ "$2" == "$3" ]]; then
    printf '  \033[32mok\033[0m   %-52s %s\n' "$1" "$3"; pass=$((pass+1))
  else
    printf '  \033[31mFAIL\033[0m %-52s %s (want %s)\n' "$1" "$3" "$2"; fail=$((fail+1))
    [[ -n "${4:-}" ]] && echo "       $4"
  fi
}
status() { # status <method> <path> <key> [body]
  local args=(-s -o /tmp/gr_body -w '%{http_code}' -X "$1" "$BASE$2")
  [[ -n "$3" ]] && args+=(-H "Authorization: Bearer $3")
  [[ -n "${4:-}" ]] && args+=(-H 'Content-Type: application/json' -d "$4")
  curl "${args[@]}"
}
body() { cat /tmp/gr_body; }

echo
echo "Reading and identity"
check "GET /api/v1/me"                200 "$(status GET /api/v1/me "$READ_KEY")" "$(body)"
check "GET /api/v1/prompts"           200 "$(status GET /api/v1/prompts "$READ_KEY")" "$(body)"
check "GET /api/v1/tags"              200 "$(status GET /api/v1/tags "$READ_KEY")"
check "search with q="                200 "$(status GET '/api/v1/prompts?q=test&limit=5' "$READ_KEY")"

echo
echo "What a read-only key must not do"
check "POST /api/v1/prompts"          403 "$(status POST /api/v1/prompts "$READ_KEY" '{"title":"x","body":"y"}')"
check "DELETE /api/v1/prompts/{id}"   403 "$(status DELETE /api/v1/prompts/anything "$READ_KEY")"

echo
echo "What NO key may do — management stays in the browser"
for path in /api/v1/api-keys /api/v1/admin/users /api/v1/admin/audit; do
  check "GET $path" 403 "$(status GET "$path" "$READ_KEY")" "$(body)"
done
check "POST /api/v1/api-keys (a key cannot mint keys)" \
      403 "$(status POST /api/v1/api-keys "$READ_KEY" '{"name":"x","role":"editor"}')"

echo
echo "Invalid keys"
check "no Authorization header"       401 "$(status GET /api/v1/prompts "")"
check "nonsense as a key"             401 "$(status GET /api/v1/prompts "utter-nonsense")"
check "key from another instance"     401 \
      "$(status GET /api/v1/prompts "$(sed 's/_personal_/_work_/; s/_work_/_personal_/2' <<<"$READ_KEY")")"

if [[ -n "$WRITE_KEY" ]]; then
  echo
  echo "Writing with a read-write key"
  code=$(status POST /api/v1/prompts "$WRITE_KEY" \
    '{"title":"Test entry from test-api.sh","body":"line one\nline two","tags":["test","automated"]}')
  check "POST /api/v1/prompts" 201 "$code" "$(body)"
  id=$(sed -n 's/.*"id":"\([^"]*\)".*/\1/p' /tmp/gr_body | head -1)

  if [[ -n "$id" ]]; then
    check "GET  /api/v1/prompts/$id"          200 "$(status GET "/api/v1/prompts/$id" "$WRITE_KEY")"
    check "PATCH /api/v1/prompts/{id}"        200 "$(status PATCH "/api/v1/prompts/$id" "$WRITE_KEY" '{"title":"Changed"}')"
    check "GET  …/revisions"                  200 "$(status GET "/api/v1/prompts/$id/revisions" "$WRITE_KEY")"
    check "read key sees the new prompt"      200 "$(status GET "/api/v1/prompts/$id" "$READ_KEY")"
    check "DELETE /api/v1/prompts/{id}"       204 "$(status DELETE "/api/v1/prompts/$id" "$WRITE_KEY")"
    check "gone afterwards"                   404 "$(status GET "/api/v1/prompts/$id" "$WRITE_KEY")"
  else
    echo "  (no id parsed from the response, skipping follow-ups)"
  fi
fi

echo
echo "Rate limit (may take a while depending on RATE_LIMIT_PER_MIN)"
limit=$(curl -sI -H "Authorization: Bearer $READ_KEY" "$BASE/api/v1/prompts" \
        | tr -d '\r' | sed -n 's/^RateLimit-Limit: //Ip')
echo "  RateLimit-Limit reports: ${limit:-<missing>}"
if [[ -n "$limit" && "$limit" -le 200 ]]; then
  for _ in $(seq 1 $((limit + 5))); do last=$(status GET /api/v1/prompts "$READ_KEY"); done
  check "after $((limit + 5)) requests" 429 "$last"
else
  echo "  (skipped — set RATE_LIMIT_PER_MIN lower for a quick check)"
fi

echo
echo "Result: $pass passed, $fail failed"
[[ "$fail" -eq 0 ]]
