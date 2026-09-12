# Betrieb (Promptory)

Was du auf deinem Server einrichten musst, was in Authentik einzutragen ist und
wie du beides vorher lokal durchtestest.

---

## 1. Auf dem Server

### 1.1 Voraussetzungen

* Docker mit Compose-Plugin (`docker compose version`).
* Ein Reverse Proxy, der TLS beendet. Die Anwendung kümmert sich bewusst nicht
  selbst um Zertifikate.
* Zwei DNS-Namen, je einer pro Instanz.

### 1.2 Konfiguration anlegen

```bash
git clone <dieses-repo> promptory && cd promptory
cp .env.privat.example .env.privat
cp .env.arbeit.example .env.arbeit

# Für jede Instanz ein eigener Schlüssel:
openssl rand -base64 32   # → DATA_ENCRYPTION_KEY in .env.privat
openssl rand -base64 32   # → DATA_ENCRYPTION_KEY in .env.arbeit
```

Dann in beiden Dateien setzen: `BASE_URL`, `OIDC_ISSUER`, `OIDC_CLIENT_ID`,
`OIDC_CLIENT_SECRET`, `OIDC_REDIRECT_URI`, `TRUSTED_PROXY_CIDRS`.

> Die echten `.env.privat` und `.env.arbeit` sind in `.gitignore` eingetragen.
> Versioniert sind nur die Vorlagen. Wenn du das Repo auf dem Server auscheckst,
> liegen die Geheimnisse damit nur dort.

Zwei Werte, die du nach dem Start **nicht mehr folgenlos ändern kannst**:

* `APP_INSTANCE` steht in jedem ausgestellten Key. Eine Änderung entwertet alle.
* `DATA_ENCRYPTION_KEY` entschlüsselt die abgelegten Provider-Tokens. Nach einem
  Wechsel müssen sich alle neu anmelden (die Daten selbst bleiben unberührt).

### 1.3 Starten

Mit Caddy oder nginx auf dem Host — die Anwendung hört dann nur auf localhost:

```bash
docker compose up -d --build
docker compose ps
curl -s localhost:8081/healthz && curl -s localhost:8082/healthz
```

Mit traefik im selben Docker-Netz:

```bash
# In docker-compose.traefik.yml die beiden Host()-Regeln und ggf. den
# certresolver-Namen anpassen, dann:
docker compose -f docker-compose.yml -f docker-compose.traefik.yml up -d --build
```

`/readyz` meldet erst dann `200`, wenn der Anmeldedienst erreichbar war. Das ist
der richtige Endpunkt für eine Überwachung — `/healthz` sagt nur, dass der
Prozess lebt.

### 1.4 Reverse Proxy

Wichtig ist in allen Varianten, dass `X-Forwarded-Proto` durchgereicht wird und
das Netz des Proxys in `TRUSTED_PROXY_CIDRS` steht. Fehlt beides, baut die
Anwendung ihre Adressen als `http://` — der klassische Fehler hinter
TLS-Terminierung, der sich als „Redirect-URI stimmt nicht" äußert.

**Caddy** (`/etc/caddy/Caddyfile`) — setzt die Forwarded-Header von selbst:

```caddy
prompts.example.org {
    reverse_proxy 127.0.0.1:8081
}
prompts-arbeit.example.org {
    reverse_proxy 127.0.0.1:8082
}
```

**nginx:**

```nginx
server {
    listen 443 ssl http2;
    server_name prompts.example.org;
    # ssl_certificate … (z.B. über certbot)

    location / {
        proxy_pass         http://127.0.0.1:8081;
        proxy_set_header   Host              $host;
        proxy_set_header   X-Real-IP         $remote_addr;
        proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
    }
}
```

**traefik:** die Labels in `docker-compose.traefik.yml` reichen; traefik setzt
die Forwarded-Header selbst. `TRUSTED_PROXY_CIDRS` muss dann das Docker-Netz
umfassen, in dem traefik läuft (üblich: `172.16.0.0/12`).

### 1.5 Datenablage und Sicherung

Jede Instanz hat ein eigenes benanntes Volume mit genau einer SQLite-Datei
(plus `-wal` und `-shm` im laufenden Betrieb).

**Nicht einfach die Datei kopieren.** Im WAL-Modus ist eine so entstandene Kopie
womöglich inkonsistent. SQLite bringt dafür einen eigenen Befehl mit:

```bash
#!/usr/bin/env bash
# /usr/local/bin/promptory-backup
set -euo pipefail
ZIEL=/var/backups/promptory
STAMP=$(date +%F)
mkdir -p "$ZIEL"

for instanz in privat arbeit; do
  docker run --rm \
    -v "promptory_${instanz}-data:/data:ro" \
    -v "$ZIEL:/backup" \
    --entrypoint sh keinos/sqlite3 -c \
    "sqlite3 /data/prompts.db \".backup '/backup/${instanz}-${STAMP}.db'\""
  gzip -f "$ZIEL/${instanz}-${STAMP}.db"
done

find "$ZIEL" -name '*.db.gz' -mtime +30 -delete
```

```cron
17 3 * * * /usr/local/bin/promptory-backup
```

Der Volume-Name ist `<projektname>_<volume>`; `docker volume ls` zeigt ihn.
Prüfe eine Sicherung gelegentlich wirklich zurück — eine ungetestete Sicherung
ist eine Vermutung:

```bash
gunzip -c /var/backups/promptory/privat-2026-09-12.db.gz > /tmp/pruef.db
sqlite3 /tmp/pruef.db "PRAGMA integrity_check; SELECT COUNT(*) FROM prompts;"
```

### 1.6 Aktualisieren

```bash
git pull
docker compose up -d --build
```

Migrationen laufen beim Start selbsttätig. Vor einem Update, das das Schema
anfasst, eine Sicherung ziehen.

---

## 2. In Authentik

Pro Instanz **eine eigene Anwendung mit eigenem Provider** — sonst teilen sich
privat und arbeit Client-ID und Rollen.

### 2.1 Provider anlegen

*Applications → Providers → Create → OAuth2/OpenID Provider*

| Feld | Wert |
|------|------|
| Name | `promptory-privat` |
| Authorization flow | dein üblicher expliziter Einwilligungsfluss |
| Client type | **Confidential** |
| Redirect URIs | `https://prompts.example.org/auth/callback` (exakt, ohne Schrägstrich am Ende) |
| Signing Key | dein Zertifikat |

Client-ID und Client-Secret danach nach `.env.privat` übernehmen.

Für die Arbeits-Instanz dasselbe mit
`https://prompts-arbeit.example.org/auth/callback`.

### 2.2 Rollen übermitteln

Die Anwendung entscheidet über den Zugang **ausschließlich** anhand eines Claims.
Es gibt keine Nutzerliste in der App, die man pflegen müsste — und niemand kommt
hinein, dessen Claim keine Rolle ergibt.

**Variante A — eigener Claim (empfohlen, weil pro Anwendung vergeben).**

*Customization → Property mappings → Create → Scope mapping*

| Feld | Wert |
|------|------|
| Name | `promptory-role-privat` |
| Scope name | `promptory` |
| Expression | siehe unten |

```python
# Gruppenzugehörigkeit auf genau eine Rolle abbilden.
# Der Rückgabewert landet als Claim im ID-Token und in userinfo.
if request.user.ak_groups.filter(name="prompts-privat-admins").exists():
    role = "admin"
elif request.user.ak_groups.filter(name="prompts-privat-editors").exists():
    role = "editor"
elif request.user.ak_groups.filter(name="prompts-privat-viewers").exists():
    role = "viewer"
else:
    role = None          # kein Claim → kein Zugriff
return {"promptory_role": role}
```

Das Mapping dem Provider unter *Scopes* zuweisen. Dann in der `.env`:

```
OIDC_SCOPES=openid,profile,email,promptory
OIDC_ROLE_CLAIM=promptory_role
OIDC_ROLE_MAP=
```

Der Vorteil gegenüber Gruppen: derselbe Gruppenbaum kann in der privaten
Instanz etwas anderes bedeuten als in der Arbeits-Instanz, ohne dass du global
eindeutige Gruppennamen erfinden musst.

**Variante B — Gruppen (funktioniert mit praktisch jedem Provider).**

```
OIDC_SCOPES=openid,profile,email
OIDC_ROLE_CLAIM=groups
OIDC_ROLE_MAP=prompts-privat-admins:admin,prompts-privat-editors:editor,prompts-privat-viewers:viewer
```

Bei mehreren Treffern gewinnt die höchste Rolle. Für andere Provider ist
`OIDC_ROLE_CLAIM` ein Pfad, verschachtelte Claims eingeschlossen — für Keycloak
etwa `resource_access.prompt-lib.roles`.

### 2.3 Benötigte Claims

| Claim | Nötig? | Wofür |
|-------|--------|-------|
| `sub` | **ja** | Identität. Ohne ihn wird die Anmeldung abgelehnt |
| der Rollen-Claim | **ja** | Ohne passenden Wert: kein Zugriff |
| `email` | nein | Anzeige, Nutzerliste |
| `name` oder `preferred_username` | nein | Anzeige |

`OIDC_CLAIMS_SOURCE=both` (Vorgabe) führt die Claims aus ID-Token und
`userinfo` zusammen. Das ist der Grund, warum ein Rollen-Claim auch dann
gefunden wird, wenn der Provider ihn nur an einer der beiden Stellen liefert.

### 2.4 Erster Administrator

Es gibt keinen Notzugang über eine Umgebungsvariable — das wäre eine zweite
Stelle neben dem IdP, genau das, was hier vermieden werden soll. Der erste
Administrator entsteht dadurch, dass du dich selbst in Authentik in die
Admin-Gruppe legst und dich anmeldest. Geht beim Mapping etwas schief, kommt
niemand hinein; repariert wird das in Authentik, nicht in der App.

### 2.5 Zugang entziehen

Im IdP die Gruppe bzw. den Claim entfernen. Die Anwendung merkt es bei der
nächsten Revalidierung (Vorgabe: spätestens nach 15 Minuten):

* laufende Sitzungen werden beendet,
* alle Keys dieser Person antworten `401` — inaktiv, aber nicht widerrufen,
  damit sie bei einer Rückkehr wieder funktionieren.

Die **Daten** der Person bleiben dabei in der App. Sollen die auch weg, zusätzlich
in der Oberfläche unter *Verwaltung → Nutzer → Entfernen*. Dabei gilt: geteilte
Einträge bleiben erhalten (Teamwissen) und werden „Gelöschter Nutzer"
zugeschrieben, private werden gelöscht, Keys und Sitzungen verschwinden, das
Protokoll bleibt.

---

## 3. Vorher lokal durchtesten

Das Ziel: Anmeldung, alle drei Rollen, der Fall „kein Zugriff" und die API mit
einem echten Key — alles bevor irgendetwas öffentlich erreichbar ist.

### 3.1 Nachgebildeten Anmeldedienst starten

```bash
docker compose -f docker-compose.dev.yml up -d
curl -s http://localhost:8090/default/.well-known/openid-configuration | head -5
```

### 3.2 Anwendung lokal starten

```bash
./scripts/dev.sh
```

Die Anwendung läuft dabei absichtlich **nicht** im Container: so benutzen Browser
und Anwendung dieselbe Provider-Adresse und es entsteht kein Issuer-Konflikt.
`STATIC_DIR=./web` sorgt dafür, dass Änderungen an Oberfläche, CSS und JS ohne
Neuübersetzen wirken.

### 3.3 Anmeldung und Rollen prüfen

`http://localhost:8080` öffnen. Der nachgebildete Dienst zeigt ein Formular; im
Feld für die Claims eintragen, welche Rolle geprüft werden soll:

| Eingabe | Erwartung |
|---------|-----------|
| `{"groups":["pl-admin"]}` | Anmeldung klappt, alle drei Reiter sichtbar |
| `{"groups":["pl-editor"]}` | Bibliothek und API-Keys, kein Reiter „Verwaltung" |
| `{"groups":["pl-viewer"]}` | nur Bibliothek, kein „Neuer Eintrag" |
| `{"groups":["sonstwas"]}` | **403 „Kein Zugriff"**, kein Konto wird angelegt |

Weitere Punkte, die sich hier prüfen lassen:

* **Rechte greifen serverseitig, nicht nur in der Anzeige.** Als Betrachter
  anmelden und in der Entwicklerkonsole schreiben wollen — erwartet: `403`.
  ```js
  await fetch('/api/v1/prompts', {method:'POST',
    headers:{'Content-Type':'application/json',
             'X-CSRF-Token':(await (await fetch('/api/v1/me')).json()).csrfToken},
    body:'{"title":"x","body":"y"}'}).then(r => r.status)
  ```
* **Private Einträge sind privat.** Als Bearbeiter A einen privaten Eintrag
  anlegen, abmelden, als Bearbeiter B (anderes `sub`) anmelden — er darf weder
  in der Liste noch in der Suche noch über die direkte ID auftauchen.
* **Entzug wirkt.** `AUTH_REVALIDATE_INTERVAL` steht in `dev.sh` auf `1m`.
  Angemeldet bleiben, sich beim nachgebildeten Dienst mit geänderten Claims neu
  anmelden — nach spätestens einer Minute richtet sich die Sitzung danach.
* **Versionshistorie.** Einen Eintrag mehrfach ändern, löschen, über
  `/api/v1/prompts/{id}/revisions` den Verlauf ansehen und wiederherstellen.

### 3.4 API mit einem Test-Key prüfen

In der Oberfläche zwei Keys anlegen: einen mit „Nur lesen", einen mit
„Lesen und schreiben". Dann:

```bash
./scripts/test-api.sh http://localhost:8080 "plk_privat_…lesend" "plk_privat_…schreibend"
```

Das Skript prüft nicht nur, was gehen soll, sondern vor allem, was **nicht**
gehen darf: Schreiben mit dem Lese-Key, jeder Zugriff auf die Verwaltung,
ein Key der falschen Instanz, ein verfälschter Key, das Rate-Limit.

Fürs Rate-Limit lohnt ein kleiner Wert, sonst dauert es:

```bash
RATE_LIMIT_PER_MIN=5 ./scripts/dev.sh
```

### 3.5 Aufräumen und scharf schalten

```bash
docker compose -f docker-compose.dev.yml down
rm -rf ./data          # die Entwicklungsdatenbank
```

Danach die Schritte aus Abschnitt 2 in Authentik ausführen, die `.env`-Dateien
mit den echten Werten füllen und mit Abschnitt 1.3 starten. Die erste Anmeldung
auf dem Server ist gleichzeitig die Probe: Kommst du als Administrator hinein,
stimmen Redirect-URI, Client-Secret und Rollen-Mapping.

---

## 4. Kurzcheckliste

**Server**

- [ ] Docker und Compose vorhanden
- [ ] Repo ausgecheckt, `.env.privat` und `.env.arbeit` aus den Vorlagen erzeugt
- [ ] Je ein `DATA_ENCRYPTION_KEY` erzeugt
- [ ] `TRUSTED_PROXY_CIDRS` passend zum Proxy gesetzt
- [ ] Zwei DNS-Namen zeigen auf den Server
- [ ] Reverse Proxy mit TLS und `X-Forwarded-Proto`
- [ ] `docker compose up -d --build`, `/readyz` antwortet `200`
- [ ] Sicherungsskript eingerichtet und **einmal zurückgeprüft**
- [ ] Überwachung auf `/readyz`

**Authentik**

- [ ] Zwei Anwendungen mit je einem vertraulichen OAuth2/OIDC-Provider
- [ ] Redirect-URIs exakt eingetragen
- [ ] Client-ID und Secret in die jeweilige `.env` übernommen
- [ ] Rollen-Mapping angelegt (eigener Claim oder Gruppen)
- [ ] Scope dem Provider zugewiesen, falls eigener Claim
- [ ] Du selbst in der Admin-Gruppe der jeweiligen Instanz
- [ ] Anmeldung mit einem Konto **ohne** Rolle liefert 403
