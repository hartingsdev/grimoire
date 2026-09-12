# Grimoire REST API

This file is meant to be handed straight to a script or to an assistant like
Claude Code as a reference.

Every instance (personal, work, …) has its own base URL, its own database and
its own keys. A key from one instance is refused by another before it ever
reaches the database.

---

## Authentication

For scripts there is exactly one way in:

```
Authorization: Bearer plk_<instance>_<key-id>_<secret>
```

* Keys are created **in the UI** under “API keys”, by signed-in editors or
  administrators.
* The plaintext is shown **once**, at creation, and never again. Losing it means
  revoking and issuing a new one.
* A key as a query parameter (`?api_key=…`) is **not** accepted — it would end
  up in access logs and proxy caches.

### What a key may do

Every key carries one of two roles:

| Role     | May |
|----------|-----|
| `viewer` | read, search, view revisions |
| `editor` | also create, update, delete, restore |

Two rules hold regardless of role:

1. **A key can never do more than the person who issued it.** If their role is
   downgraded at the identity provider, the key loses the same rights by itself.
   If they lose access entirely the key answers `401` (`owner_inactive`): it is
   inactive, not revoked, and works again if they come back.
2. **A key can manage neither keys nor users.** Everything under
   `/api/v1/api-keys` and `/api/v1/admin/` answers a key with `403`
   (`forbidden_for_api_key`) — including a key issued by an administrator.
   Management happens only after signing in with a browser.

### Visibility

A key sees exactly its owner's library: every shared prompt plus that person's
own private ones. Other people's private prompts are never visible to a key, not
through listing, search or the tag list.

---

## Endpoints

Base: `{BASE_URL}/api/v1`

| Method   | Path                       | Role     | Purpose |
|----------|----------------------------|----------|---------|
| `GET`    | `/me`                      | either   | who am I, what may I do |
| `GET`    | `/prompts`                 | `viewer` | list and search |
| `POST`   | `/prompts`                 | `editor` | create |
| `GET`    | `/prompts/{id}`            | `viewer` | fetch one |
| `PATCH`  | `/prompts/{id}`            | `editor` | partial update |
| `PUT`    | `/prompts/{id}`            | `editor` | same as PATCH |
| `DELETE` | `/prompts/{id}`            | `editor` | delete (soft, restorable) |
| `GET`    | `/prompts/{id}/revisions`  | `viewer` | revision history |
| `POST`   | `/prompts/{id}/restore`    | `editor` | restore |
| `GET`    | `/tags`                    | `viewer` | tags with counts |
| `GET`    | `/me/audit`                | either   | what happened to your own content |

Browser only (always `403` for keys): `/api-keys`, `/admin/users`,
`/admin/users/{id}/footprint`, `/admin/audit`, `/admin/prompts/{id}/reveal`.

Unauthenticated: `GET /healthz`, `GET /readyz`.

---

## Objects

```json
{
  "id": "0193c5f2-8a41-7b02-9c3d-4e5f6a7b8c9d",
  "title": "Code review",
  "body": "Review the following diff for …",
  "tags": ["code", "review"],
  "visibility": "shared",
  "owner":     { "id": "…", "name": "Anna Example" },
  "revision": 3,
  "createdAt": "2026-09-12T10:04:11Z",
  "updatedAt": "2026-09-12T11:20:03Z",
  "updatedBy": { "id": "…", "name": "Anna Example" }
}
```

`visibility` is `shared` or `private`. Creating without it yields `shared`.

---

## Examples

For brevity:

```bash
export GR=https://prompts.example.org
export GR_KEY=plk_personal_9f3k2md7qa4x_…
```

### Check that the key works

```bash
curl -s -H "Authorization: Bearer $GR_KEY" "$GR/api/v1/me"
```

```json
{
  "principal": "apikey",
  "role": "viewer",
  "roleLabel": "Viewer",
  "capabilities": ["prompts:read"],
  "user": { "id": "…", "name": "Anna Example", "email": "anna@example.org" },
  "key":  { "id": "9f3k2md7qa4x", "role": "viewer" },
  "instance": { "title": "Grimoire (personal)", "name": "personal" }
}
```

`role` is the **effective** role, already combined with the owner's current one;
`key.role` is what was granted at creation. If they differ, the owner has been
downgraded.

### List and search

```bash
curl -s -H "Authorization: Bearer $GR_KEY" "$GR/api/v1/prompts"

# Full-text search over title, tags and body
curl -s -H "Authorization: Bearer $GR_KEY" \
     --get --data-urlencode "q=summary" "$GR/api/v1/prompts"

# Narrow by tags (repeat for AND)
curl -s -H "Authorization: Bearer $GR_KEY" \
     "$GR/api/v1/prompts?tag=code&tag=review"

# Only your own private prompts, paged
curl -s -H "Authorization: Bearer $GR_KEY" \
     "$GR/api/v1/prompts?visibility=private&limit=20&offset=20"
```

Parameters: `q`, `tag` (repeatable), `visibility` (`shared`|`private`),
`limit` (1–200, default 50), `offset`.

On search: a full-text index **and** a substring match run together.
`summar` finds “Summary”, `mariz` finds it too (mid-word), and diacritics are
folded, so `resum` finds “Résumé”.

Response:

```json
{ "prompts": [ … ], "count": 12, "limit": 50, "offset": 0 }
```

### Create

```bash
curl -s -X POST "$GR/api/v1/prompts" \
  -H "Authorization: Bearer $GR_WRITE_KEY" \
  -H "Content-Type: application/json" \
  -d '{
        "title": "Code review",
        "body": "Review the following diff for correctness …",
        "tags": ["code", "review"],
        "visibility": "shared"
      }'
```

`201` with the created object. `title` and `body` are required.

Multi-line text is ordinary JSON (`\n`). From a file:

```bash
jq -n --arg t "Code review" --rawfile b ./prompt.txt \
   '{title:$t, body:$b, tags:["code"]}' \
| curl -s -X POST "$GR/api/v1/prompts" \
    -H "Authorization: Bearer $GR_WRITE_KEY" \
    -H "Content-Type: application/json" --data-binary @-
```

### Update

Only the fields you send are touched:

```bash
curl -s -X PATCH "$GR/api/v1/prompts/$ID" \
  -H "Authorization: Bearer $GR_WRITE_KEY" \
  -H "Content-Type: application/json" \
  -d '{"title": "Code review (strict)"}'
```

`tags` replaces the whole list; omitting it leaves the tags alone.

### Delete and restore

```bash
curl -s -X DELETE "$GR/api/v1/prompts/$ID" \
  -H "Authorization: Bearer $GR_WRITE_KEY"      # 204

curl -s "$GR/api/v1/prompts/$ID/revisions" \
  -H "Authorization: Bearer $GR_KEY"

# Without a body: the last state. With revision: that state.
curl -s -X POST "$GR/api/v1/prompts/$ID/restore" \
  -H "Authorization: Bearer $GR_WRITE_KEY" \
  -H "Content-Type: application/json" -d '{"revision": 2}'
```

Deletion is soft: the prompt leaves listings and the search index but stays
restorable through its revisions.

### Tags

```bash
curl -s -H "Authorization: Bearer $GR_KEY" "$GR/api/v1/tags"
```

```json
{ "tags": [ { "name": "code", "count": 7 }, { "name": "review", "count": 3 } ] }
```

---

## Errors

Every error has the same shape:

```json
{ "error": { "code": "forbidden", "message": "This key may only read. …" } }
```

| Status | `code`                  | Meaning |
|--------|-------------------------|---------|
| 400    | `bad_request`           | input incomplete or not allowed |
| 401    | `unauthorized`          | no Authorization header, or malformed |
| 401    | `invalid_key`           | key unknown, tampered with, or from another instance |
| 401    | `key_revoked`           | revoked (permanent) |
| 401    | `key_expired`           | past its expiry |
| 401    | `owner_inactive`        | the owner has no access right now — inactive, not dead |
| 403    | `forbidden`             | role insufficient (e.g. writing with a read key) |
| 403    | `forbidden_for_api_key` | browser only (management) |
| 404    | `not_found`             | absent **or** not visible to this caller |
| 429    | `rate_limited`          | too many requests |
| 503    | `provider_unavailable`  | identity provider unreachable |

`404` deliberately also covers “exists, but belongs to someone else and is
private” — otherwise the response would confirm that other people's prompts
exist.

---

## Rate limiting

Every response carries:

```
RateLimit-Limit:     120
RateLimit-Remaining: 118
RateLimit-Reset:     31
```

On overrun: `429` with `Retry-After` in seconds. Reading `RateLimit-Remaining`
keeps you out of it entirely. A simple, patient pattern:

```bash
while :; do
  code=$(curl -s -o /tmp/out -w '%{http_code}' \
         -H "Authorization: Bearer $GR_KEY" "$GR/api/v1/prompts")
  [[ "$code" == "429" ]] || break
  sleep 5
done
```

---

## Notes for scripts and assistants

* **A read-only key is enough for almost all automation.** It cannot break
  anything on a bad day. Use a write key only where you actually write.
* **One key per purpose**, with a name that says so (“Claude Code – read only”).
  Then one can be revoked without disturbing the others.
* **Rotation needs no downtime**: create the new key, deploy it, revoke the old
  one. Several valid keys side by side are expected.
* **Never commit a key.** The `plk_` prefix makes keys greppable — helpful when
  searching, equally helpful to everyone else.
* Keys always expire (default 365 days). `GET /me` does not say when; the UI
  shows it under “API keys”.
