# Deploying Grimoire

What to set up on your server, what to configure at your identity provider, and
how to test both locally first.

---

## 1. On the server

### 1.1 Prerequisites

* Docker with the Compose plugin (`docker compose version`).
* A reverse proxy that terminates TLS. The app deliberately does not handle
  certificates itself.
* One DNS name per instance.

### 1.2 Configuration

```bash
git clone <this-repo> grimoire && cd grimoire
cp .env.personal.example .env.personal
cp .env.work.example     .env.work

# One key per instance:
openssl rand -base64 32   # → DATA_ENCRYPTION_KEY in .env.personal
openssl rand -base64 32   # → DATA_ENCRYPTION_KEY in .env.work
```

Then set in both files: `BASE_URL`, `OIDC_ISSUER`, `OIDC_CLIENT_ID`,
`OIDC_CLIENT_SECRET`, `OIDC_REDIRECT_URI`, `TRUSTED_PROXY_CIDRS`.

> The real `.env.personal` and `.env.work` are in `.gitignore`; only the
> templates are versioned. Checking the repo out on the server keeps the secrets
> there and nowhere else.

Two values you **cannot change afterwards without consequences**:

* `APP_INSTANCE` appears in every key issued. Changing it invalidates them all.
* `DATA_ENCRYPTION_KEY` decrypts the stored provider tokens. After a rotation
  everyone has to sign in again (the data itself is untouched).

### 1.3 Starting

With Caddy or nginx on the host — the app then listens on localhost only:

```bash
docker compose up -d --build
docker compose ps
curl -s localhost:8081/healthz && curl -s localhost:8082/healthz
```

With traefik on the same Docker network:

```bash
# Adjust the two Host() rules and the certresolver name in
# docker-compose.traefik.yml, then:
docker compose -f docker-compose.yml -f docker-compose.traefik.yml up -d --build
```

`/readyz` returns `200` only once the identity provider has been reached. That
is the endpoint to monitor; `/healthz` only says the process is alive.

### 1.4 Reverse proxy

What matters in every variant is that `X-Forwarded-Proto` is passed through and
that the proxy's network is listed in `TRUSTED_PROXY_CIDRS`. Without both, the
app builds its URLs as `http://` — the classic failure behind TLS termination,
which surfaces as “redirect URI mismatch”.

**Caddy** (`/etc/caddy/Caddyfile`) — sets the forwarded headers by itself:

```caddy
prompts.example.org {
    reverse_proxy 127.0.0.1:8081
}
prompts-work.example.org {
    reverse_proxy 127.0.0.1:8082
}
```

**nginx:**

```nginx
server {
    listen 443 ssl http2;
    server_name prompts.example.org;
    # ssl_certificate … (e.g. via certbot)

    location / {
        proxy_pass         http://127.0.0.1:8081;
        proxy_set_header   Host              $host;
        proxy_set_header   X-Real-IP         $remote_addr;
        proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
    }
}
```

**traefik:** the labels in `docker-compose.traefik.yml` are enough; traefik sets
the forwarded headers itself. `TRUSTED_PROXY_CIDRS` must then cover the Docker
network traefik runs on (usually `172.16.0.0/12`).

### 1.5 Data and backups

Each instance has its own named volume holding exactly one SQLite file (plus
`-wal` and `-shm` while running).

**Do not simply copy the file.** In WAL mode such a copy may be inconsistent.
SQLite has a command for this:

```bash
#!/usr/bin/env bash
# /usr/local/bin/grimoire-backup
set -euo pipefail
DEST=/var/backups/grimoire
STAMP=$(date +%F)
mkdir -p "$DEST"

for instance in personal work; do
  docker run --rm \
    -v "grimoire_${instance}-data:/data:ro" \
    -v "$DEST:/backup" \
    --entrypoint sh keinos/sqlite3 -c \
    "sqlite3 /data/grimoire.db \".backup '/backup/${instance}-${STAMP}.db'\""
  gzip -f "$DEST/${instance}-${STAMP}.db"
done

find "$DEST" -name '*.db.gz' -mtime +30 -delete
```

```cron
17 3 * * * /usr/local/bin/grimoire-backup
```

The volume name is `<project>_<volume>`; `docker volume ls` shows it. Restore a
backup occasionally and check it — an untested backup is a guess:

```bash
gunzip -c /var/backups/grimoire/personal-2026-09-12.db.gz > /tmp/check.db
sqlite3 /tmp/check.db "PRAGMA integrity_check; SELECT COUNT(*) FROM prompts;"
```

### 1.6 Updating

```bash
git pull
docker compose up -d --build
```

Migrations run at startup. Take a backup before an update that touches the
schema.

---

## 2. At the identity provider

One application with its own provider **per instance** — otherwise personal and
work share a client ID and a set of roles. The walkthrough below uses Authentik;
any OIDC provider works, the app only needs a role claim.

### 2.1 Create the provider

*Applications → Providers → Create → OAuth2/OpenID Provider*

| Field | Value |
|-------|-------|
| Name | `grimoire-personal` |
| Authorization flow | your usual explicit-consent flow |
| Client type | **Confidential** |
| Redirect URIs | `https://prompts.example.org/auth/callback` (exact, no trailing slash) |
| Signing key | your certificate |

Copy the client ID and secret into `.env.personal`, and repeat for the work
instance with `https://prompts-work.example.org/auth/callback`.

### 2.2 Delivering the role

Access is decided **solely** by a claim. There is no user list in the app to
maintain — and nobody whose claim yields no role gets in.

**Option A — a custom claim (recommended, because it is granted per
application).**

*Customization → Property mappings → Create → Scope mapping*

| Field | Value |
|-------|-------|
| Name | `grimoire-role-personal` |
| Scope name | `grimoire` |
| Expression | see below |

```python
# Map group membership onto exactly one role. The return value becomes a claim
# in the ID token and in userinfo.
if request.user.ak_groups.filter(name="grimoire-personal-admins").exists():
    role = "admin"
elif request.user.ak_groups.filter(name="grimoire-personal-editors").exists():
    role = "editor"
elif request.user.ak_groups.filter(name="grimoire-personal-viewers").exists():
    role = "viewer"
else:
    role = None          # no claim → no access
return {"grimoire_role": role}
```

Assign the mapping to the provider under *Scopes*, then in the `.env`:

```
OIDC_SCOPES=openid,profile,email,grimoire
OIDC_ROLE_CLAIM=grimoire_role
OIDC_ROLE_MAP=
```

The advantage over groups: the same group tree can mean one thing on the
personal instance and another on the work instance, without inventing globally
unique group names.

**Option B — groups (works with practically any provider).**

```
OIDC_SCOPES=openid,profile,email
OIDC_ROLE_CLAIM=groups
OIDC_ROLE_MAP=grimoire-personal-admins:admin,grimoire-personal-editors:editor,grimoire-personal-viewers:viewer
```

With several matches the highest role wins. For other providers
`OIDC_ROLE_CLAIM` is a path, nested claims included — for Keycloak, for example,
`resource_access.grimoire.roles`.

### 2.3 Claims the app needs

| Claim | Required? | Used for |
|-------|-----------|----------|
| `sub` | **yes** | identity. Without it the sign-in is refused |
| the role claim | **yes** | without a matching value: no access |
| `email` | no | display, user list |
| `name` or `preferred_username` | no | display |

`OIDC_CLAIMS_SOURCE=both` (the default) merges claims from the ID token and
`userinfo`. That is why a role claim is found even when the provider exposes it
at only one of the two.

### 2.4 The first administrator

There is no emergency access through an environment variable — that would be a
second place beside the IdP, exactly what this design avoids. The first
administrator comes about by putting yourself into the admin group at the
provider and signing in. If the mapping is wrong, nobody gets in, and you fix it
at the provider, not in the app.

### 2.5 Withdrawing access

Remove the group or claim at the provider. The app notices at the next
revalidation (default: within 15 minutes):

* live sessions end,
* every key of that person answers `401` — inactive, not revoked, so they work
  again if the person returns.

Their **data** stays in the app. To remove that as well, use *Administration →
Users → Remove* in the UI: shared prompts stay (team knowledge) and are
attributed to “Deleted user”, private ones are deleted, keys and sessions go,
and the audit log remains.

---

## 3. Testing it all locally first

The goal: sign-in, all three roles, the “no access” case and the API with a real
key — all before anything is publicly reachable.

### 3.1 Start the mock provider

```bash
docker compose -f docker-compose.dev.yml up -d
curl -s http://localhost:8090/default/.well-known/openid-configuration | head -5
```

### 3.2 Start the app

```bash
./scripts/dev.sh
```

The app deliberately runs **outside** Docker here, so browser and app use the
same provider address and no issuer mismatch arises. `STATIC_DIR=./web` makes
changes to the UI, CSS and JS take effect without recompiling.

### 3.3 Check sign-in and roles

Open `http://localhost:8080`. The mock provider shows a form; in the claims
field enter the role you want to check:

| Input | Expectation |
|-------|-------------|
| `{"groups":["pl-admin"]}` | signs in, all three tabs visible |
| `{"groups":["pl-editor"]}` | library and API keys, no “Administration” tab |
| `{"groups":["pl-viewer"]}` | library only, no “New prompt” button |
| `{"groups":["something"]}` | **403 “No access”**, and no account is created |

Worth checking here too:

* **Permissions are enforced server-side, not just hidden.** Sign in as a viewer
  and try to write from the browser console — expect `403`.
  ```js
  await fetch('/api/v1/prompts', {method:'POST',
    headers:{'Content-Type':'application/json',
             'X-CSRF-Token':(await (await fetch('/api/v1/me')).json()).csrfToken},
    body:'{"title":"x","body":"y"}'}).then(r => r.status)
  ```
* **Private prompts really are private.** Create one as editor A, sign out, sign
  in as editor B (a different `sub`) — it must appear neither in the listing nor
  in search nor via its direct ID.
* **Withdrawal takes effect.** `AUTH_REVALIDATE_INTERVAL` is set to `1m` in
  `dev.sh`. Stay signed in, re-authenticate at the mock provider with changed
  claims, and within a minute the session follows.
* **Revision history.** Edit a prompt a few times, delete it, inspect
  `/api/v1/prompts/{id}/revisions` and restore it.

### 3.4 Check the API with test keys

Create two keys in the UI, one “read only” and one “read and write”, then:

```bash
./scripts/test-api.sh http://localhost:8080 "plk_personal_…read" "plk_personal_…write"
```

The script checks not only what should work but above all what must **not**:
writing with the read key, any access to management endpoints, a key from
another instance, a tampered key, the rate limit.

For the rate limit a small value saves time:

```bash
RATE_LIMIT_PER_MIN=5 ./scripts/dev.sh
```

### 3.5 Clean up and go live

```bash
docker compose -f docker-compose.dev.yml down
rm -rf ./data          # the development database
```

Then do section 2 at your provider, fill the `.env` files with real values and
start as in section 1.3. The first sign-in on the server is the proof: if you
get in as an administrator, redirect URI, client secret and role mapping are all
correct.

---

## 4. Checklist

**Server**

- [ ] Docker and Compose present
- [ ] Repo checked out, `.env.personal` and `.env.work` created from the templates
- [ ] One `DATA_ENCRYPTION_KEY` generated per instance
- [ ] `TRUSTED_PROXY_CIDRS` matches the proxy
- [ ] Two DNS names point at the server
- [ ] Reverse proxy with TLS and `X-Forwarded-Proto`
- [ ] `docker compose up -d --build`, `/readyz` returns `200`
- [ ] Backup script installed and **restored once** as a check
- [ ] Monitoring on `/readyz`

**Identity provider**

- [ ] Two applications, each with its own confidential OAuth2/OIDC provider
- [ ] Redirect URIs entered exactly
- [ ] Client ID and secret copied into the matching `.env`
- [ ] Role mapping created (custom claim or groups)
- [ ] Scope assigned to the provider, if using a custom claim
- [ ] You are in the admin group of each instance
- [ ] Signing in with an account that has **no** role returns 403
