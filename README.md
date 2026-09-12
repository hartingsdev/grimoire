# Grimoire

A self-hosted prompt library with OIDC sign-in, role-based permissions and a
REST API for scripts. One Go binary, one SQLite file, one container — runs
anywhere Docker does, tied to no cloud provider.

*A grimoire is a book of spells you keep, refine and reach for again. Prompts
turn out to work much the same way.*

```
  Browser ──── OIDC session ────┐
                                ├──► Principal ──► one permission check ──► handlers
  Script ───── Bearer key ──────┘
```

Prompts you keep, find and paste dozens of times a day deserve better than a
scratch file — but not a SaaS subscription and not an account on someone else's
machine. Grimoire is the small thing in between: a searchable library your
colleagues can share, your scripts can read, and you can move to another server
with `scp` and a `docker compose up`.

📘 **[API.md](API.md)** — REST reference with curl examples, written to be handed
straight to a script or to Claude Code
🔧 **[DEPLOY.md](DEPLOY.md)** — server setup, identity provider configuration,
local testing, backups

---

## What it does

- **Prompts** with a title, tags and multi-line body. Add, edit, delete, copy
  with one click.
- **Search that actually finds things.** Full-text over title, tags and body,
  with prefix matching and diacritic folding (`ubersetz` finds `Übersetzung`)
  plus a substring fallback for mid-word matches that full-text search misses.
- **Shared or private** per entry. Private means private — see below.
- **Every change is versioned**, deletion is soft and reversible.
- **Two instances, one codebase.** Run as many separate instances as you like
  (personal, work, per-team); each gets its own config, its own database file
  and its own keys. Nothing is shared between them.
- **API keys** with the same two roles as people, a mandatory expiry, per-key
  rate limiting, and metadata you can inspect and revoke in the UI.

## Two ways in, one permission check

People sign in over OIDC (authorization code flow with PKCE). The whole flow
stays on the server; the browser only ever gets a session cookie. Scripts send
`Authorization: Bearer plk_<instance>_<id>_<secret>`.

Both produce the same principal, and exactly one function turns a principal into
permissions:

```go
func Capabilities(p Principal) CapSet {
	caps := CapSet{}
	switch p.Role {
	case Viewer: caps.add(PromptsRead)
	case Editor:
		caps.add(PromptsRead, PromptsWrite)
		if p.Kind == Session { caps.add(KeysManage) }
	case Admin:
		caps.add(PromptsRead, PromptsWrite)
		if p.Kind == Session {
			caps.add(KeysManage, AdminRead, AdminUsers, AuditRead)
		}
	}
	return caps
}
```

That `p.Kind == Session` check is the whole of **"API keys cannot manage keys"**.
A key is denied management rights even if someone hand-writes `role='admin'`
into its database row. Two further layers make sure nothing routes around it:

1. **Routes must declare their protection when registered.** There is no
   `register()` overload without it, so a forgotten guard is a compile error.
2. **A test walks the entire route table** and asserts that no endpoint hands an
   API key a management capability. Add an admin route that bypasses the
   derivation and CI goes red.

## Quick start

You need Go 1.25+ and Docker.

```bash
git clone https://github.com/hartingsdev/grimoire && cd grimoire

docker compose -f docker-compose.dev.yml up -d   # mock OIDC provider on :8090
./scripts/dev.sh                                 # app on http://localhost:8080
```

At the sign-in form, enter the claims for the role you want to try:

| Claims | You get |
|--------|---------|
| `{"groups":["pl-admin"]}` | administrator — all three tabs |
| `{"groups":["pl-editor"]}` | editor — library and API keys |
| `{"groups":["pl-viewer"]}` | viewer — read, search, copy |
| `{"groups":["anything-else"]}` | **403, and no account is created** |

Then create two API keys in the UI and exercise the API — including everything
that must *not* work:

```bash
./scripts/test-api.sh http://localhost:8080 <read-key> <write-key>
```

```bash
go test ./...
```

For production, follow [DEPLOY.md](DEPLOY.md): copy the `.env` templates, point
a reverse proxy at it, and `docker compose up -d --build`.

## Using it from a script

```bash
export PL=https://prompts.example.org
export PL_KEY=plk_personal_9f3k2md7qa4x_…

curl -s -H "Authorization: Bearer $PL_KEY" \
     --get --data-urlencode "q=code review" "$PL/api/v1/prompts" | jq '.prompts[].title'
```

Full reference, error codes and rate-limit handling in [API.md](API.md).

## Design decisions

**Roles come from the identity provider and nowhere else.** There is no user
list and no permission editor in the app. A second place where roles live is a
second place to forget. The claim is fully configurable — a custom claim, a
groups array, or a nested path like `resource_access.grimoire.roles` — so the
app is not married to one provider. No matching claim means no access, and no
account is created either.

**The role is re-checked during a session.** Every 15 minutes the app fetches
the claims again. Telling the failure modes apart is the point: an unreachable
provider is *not an answer* and takes nothing away, or a brief IdP outage would
log everyone out. Only a real response without a matching role ends a session.

**A key can never outrank its owner.** The effective role is
`min(key role, owner's current role)`. Demote someone at the IdP and their write
key loses write access by itself. So that this also holds for someone who never
signs in again, the cached role lapses after `OWNER_STALE_AFTER` (default 30
days) and the key goes inactive rather than running on a stale role. Inactive,
not revoked — it works again if they come back.

**Keys are hashed with SHA-256, not bcrypt.** Slow hashes exist to protect weak,
human-chosen passwords from brute force. A 32-byte random secret is not
guessable; a slow hash would only tax every single API request. The key carries
a public id so lookup is an index hit rather than a scan, and that id is safe to
display and log.

**A deleted user becomes a tombstone.** Every foreign key points at an internal
surrogate id, not at the OIDC subject. Deleting clears sub, email and name while
the row stays: shared prompts and the full revision history survive, the person
is gone, and if they sign in again later they get a fresh, empty account.
Deleting in the app does *not* withdraw access — that happens at the IdP, and
the confirmation dialog says so.

**Private means private.** Admins see only counts for other people's private
prompts. For the genuine suspicion case there is a single, deliberate reveal
that requires a written reason, writes an immutable audit entry, and shows up in
the owner's own UI. And whatever an instance is configured to allow, the
visibility toggle in the UI states plainly who can read the entry. Silent access
exists in no configuration.

**No cloud-vendor runtime.** Plain `net/http`, a SQLite file on disk, a
statically linked binary in a `distroless/static` image. Four direct
dependencies: `coreos/go-oidc`, `golang.org/x/oauth2`, `modernc.org/sqlite`
(cgo-free, which is what makes the static binary possible) and the standard
library. Routing is the standard library's `ServeMux`; migrations are embedded
`.sql` files tracked in `PRAGMA user_version`. TLS is your reverse proxy's job.

## Configuration

Each instance is configured entirely through environment variables, one `.env`
file per instance. See `.env.personal.example` for the annotated full set; the
ones worth knowing up front:

| Variable | Default | Notes |
|----------|---------|-------|
| `APP_INSTANCE` | — | Appears in every API key. Changing it invalidates them all. |
| `OIDC_ROLE_CLAIM` | `groups` | Claim path carrying the role; may be nested. |
| `OIDC_ROLE_MAP` | empty | `group:role` pairs. Empty means the claim already names the role. |
| `OIDC_CLAIMS_SOURCE` | `both` | Merges ID token and userinfo — many providers expose groups only at userinfo. |
| `AUTH_REVALIDATE_INTERVAL` | `15m` | How often a live session re-checks its role. |
| `OWNER_STALE_AFTER` | `720h` | After this, an unverified owner's keys go inactive. |
| `PRIVATE_PROMPTS` | `on` | Turn off to make an instance entirely shared. |
| `ADMIN_PRIVATE_ACCESS` | `break-glass` | `none`, `break-glass` or `full`. |
| `RATE_LIMIT_PER_MIN` | `120` | Per API key. |
| `DATA_ENCRYPTION_KEY` | — | 32 bytes, base64. Encrypts stored provider tokens. |

## Layout

```
cmd/server/         startup, healthcheck mode, graceful shutdown
internal/config/    loads and fully validates the .env — bad config fails at start
internal/auth/      roles, capabilities, API keys, OIDC, claim mapping
internal/store/     SQLite: schema, migrations, every query
internal/httpapi/   routes with declared protection, middleware, handlers
internal/ratelimit/
web/                the UI, embedded into the binary via go:embed
```

`STATIC_DIR=./web` serves the UI from disk instead, so HTML, CSS and JS can be
edited without recompiling. `scripts/dev.sh` sets it for you.

## Status

Working and tested end to end: OIDC sign-in with all three roles, the API with
real keys, revocation, downgrade, expiry, rate limiting, revisions and user
deletion. The UI is deliberately plain — complete in function, undesigned on
purpose.

Not built yet: service keys with no human owner (the schema reserves a nullable
`owner_id` for them).
