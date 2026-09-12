# REST-API der Prompt-Bibliothek

Diese Datei ist als Referenz gedacht, die sich einem Skript oder einem
Assistenten wie Claude Code direkt vorlegen lässt.

Jede Instanz (privat, arbeit) hat ihre eigene Basisadresse, ihre eigene
Datenbank und ihre eigenen Keys. Ein Key der einen Instanz wird von der anderen
abgewiesen, bevor sie überhaupt in die Datenbank schaut.

---

## Authentifizierung

Für Skripte gibt es genau einen Weg:

```
Authorization: Bearer plk_<instanz>_<key-id>_<geheimnis>
```

* Keys werden **in der Oberfläche** unter „API-Keys" erzeugt, von angemeldeten
  Bearbeitern oder Administratoren.
* Der Klartext wird **einmal** bei der Erstellung angezeigt und danach nie wieder.
  Verloren heißt: widerrufen und neu ausstellen.
* Ein Key als Query-Parameter (`?api_key=…`) wird **nicht** akzeptiert — dort
  landete er in Zugriffsprotokollen und Proxy-Zwischenspeichern.

### Was ein Key darf

Jeder Key hat eine von zwei Rollen:

| Rolle    | Darf |
|----------|------|
| `viewer` | Prompts lesen, suchen, Revisionen ansehen |
| `editor` | zusätzlich anlegen, ändern, löschen, wiederherstellen |

Zwei Regeln gelten immer, unabhängig von der Rolle:

1. **Ein Key kann nie mehr als die Person, die ihn ausgestellt hat.** Wird deren
   Rolle im Anmeldedienst herabgestuft, verliert der Key dieselben Rechte —
   ohne Zutun. Verliert sie den Zugang ganz, antwortet der Key mit `401`
   (`owner_inactive`); er ist dann inaktiv, aber nicht widerrufen, und lebt
   wieder auf, wenn die Person zurückkommt.
2. **Ein Key kann weder Keys noch Nutzer verwalten.** Alle Endpunkte unter
   `/api/v1/api-keys` und `/api/v1/admin/` antworten einem Key mit `403`
   (`forbidden_for_api_key`), auch einem Key eines Administrators. Verwaltung
   findet ausschließlich nach Anmeldung im Browser statt.

### Sichtbarkeit

Ein Key sieht genau die Bibliothek seines Besitzers: alle geteilten Einträge
plus dessen eigene private. Fremde private Einträge sind für einen Key nie
sichtbar, auch nicht über die Suche oder die Tag-Liste.

---

## Endpunkte

Basis: `{BASE_URL}/api/v1`

| Methode  | Pfad                       | Rolle    | Zweck |
|----------|----------------------------|----------|-------|
| `GET`    | `/me`                      | beide    | Wer bin ich, was darf ich |
| `GET`    | `/prompts`                 | `viewer` | Auflisten und suchen |
| `POST`   | `/prompts`                 | `editor` | Anlegen |
| `GET`    | `/prompts/{id}`            | `viewer` | Einzelabruf |
| `PATCH`  | `/prompts/{id}`            | `editor` | Teilweise ändern |
| `PUT`    | `/prompts/{id}`            | `editor` | Wie PATCH |
| `DELETE` | `/prompts/{id}`            | `editor` | Löschen (weich, wiederherstellbar) |
| `GET`    | `/prompts/{id}/revisions`  | `viewer` | Versionshistorie |
| `POST`   | `/prompts/{id}/restore`    | `editor` | Wiederherstellen |
| `GET`    | `/tags`                    | `viewer` | Tags mit Häufigkeit |

| `GET` | `/me/audit` | beide | Was mit den eigenen Inhalten geschehen ist |

Nur im Browser erreichbar (für Keys immer `403`):
`/api-keys`, `/admin/users`, `/admin/users/{id}/footprint`, `/admin/audit`,
`/admin/prompts/{id}/reveal`.

Ohne Anmeldung: `GET /healthz`, `GET /readyz`.

---

## Objekte

```json
{
  "id": "0193c5f2-8a41-7b02-9c3d-4e5f6a7b8c9d",
  "title": "Code-Review",
  "body": "Prüfe den folgenden Diff auf …",
  "tags": ["code", "review"],
  "visibility": "shared",
  "owner":     { "id": "…", "name": "Anna Beispiel" },
  "revision": 3,
  "createdAt": "2026-09-12T10:04:11Z",
  "updatedAt": "2026-09-12T11:20:03Z",
  "updatedBy": { "id": "…", "name": "Anna Beispiel" }
}
```

`visibility` ist `shared` oder `private`. Beim Anlegen ohne Angabe gilt `shared`.

---

## Beispiele

Der Übersichtlichkeit halber vorab:

```bash
export PL=https://prompts.example.org
export PL_KEY=plk_privat_9f3k2md7qa4x_…
```

### Prüfen, ob der Key funktioniert

```bash
curl -s -H "Authorization: Bearer $PL_KEY" "$PL/api/v1/me"
```

```json
{
  "principal": "apikey",
  "role": "viewer",
  "roleLabel": "Betrachter",
  "capabilities": ["prompts:read"],
  "user": { "id": "…", "name": "Anna Beispiel", "email": "anna@example.org" },
  "key":  { "id": "9f3k2md7qa4x", "role": "viewer" },
  "instance": { "title": "Prompt-Bibliothek (privat)", "name": "privat" }
}
```

`role` ist die **wirksame** Rolle (bereits mit der Rolle des Besitzers
verrechnet), `key.role` die ursprünglich vergebene. Weichen beide voneinander
ab, wurde der Besitzer herabgestuft.

### Auflisten und suchen

```bash
curl -s -H "Authorization: Bearer $PL_KEY" "$PL/api/v1/prompts"

# Volltextsuche über Titel, Tags und Text
curl -s -H "Authorization: Bearer $PL_KEY" \
     --get --data-urlencode "q=zusammenfassung" "$PL/api/v1/prompts"

# Nach Tags eingrenzen (mehrfach = UND-Verknüpfung)
curl -s -H "Authorization: Bearer $PL_KEY" \
     "$PL/api/v1/prompts?tag=code&tag=review"

# Nur eigene private Einträge, seitenweise
curl -s -H "Authorization: Bearer $PL_KEY" \
     "$PL/api/v1/prompts?visibility=private&limit=20&offset=20"
```

Parameter: `q`, `tag` (mehrfach), `visibility` (`shared`|`private`),
`limit` (1–200, Vorgabe 50), `offset`.

Zur Suche: gesucht wird über einen Volltextindex **und** zusätzlich als
Teilzeichenkette. `zusammenfass` findet „Zusammenfassung", `fassung` ebenfalls,
und Umlaute werden normalisiert (`ubersetz` findet „Übersetzung").

Antwort:

```json
{ "prompts": [ … ], "count": 12, "limit": 50, "offset": 0 }
```

### Anlegen

```bash
curl -s -X POST "$PL/api/v1/prompts" \
  -H "Authorization: Bearer $PL_WRITE_KEY" \
  -H "Content-Type: application/json" \
  -d '{
        "title": "Code-Review",
        "body": "Prüfe den folgenden Diff auf Korrektheit …",
        "tags": ["code", "review"],
        "visibility": "shared"
      }'
```

Antwort `201` mit dem angelegten Objekt. Pflicht sind `title` und `body`.

Mehrzeiliger Text geht als normales JSON (`\n`). Aus einer Datei:

```bash
jq -n --arg t "Code-Review" --rawfile b ./prompt.txt \
   '{title:$t, body:$b, tags:["code"]}' \
| curl -s -X POST "$PL/api/v1/prompts" \
    -H "Authorization: Bearer $PL_WRITE_KEY" \
    -H "Content-Type: application/json" --data-binary @-
```

### Ändern

Nur die genannten Felder werden angefasst:

```bash
curl -s -X PATCH "$PL/api/v1/prompts/$ID" \
  -H "Authorization: Bearer $PL_WRITE_KEY" \
  -H "Content-Type: application/json" \
  -d '{"title": "Code-Review (streng)"}'
```

`tags` ersetzt die Liste vollständig; weglassen lässt sie unverändert.

### Löschen und wiederherstellen

```bash
curl -s -X DELETE "$PL/api/v1/prompts/$ID" \
  -H "Authorization: Bearer $PL_WRITE_KEY"      # 204

curl -s "$PL/api/v1/prompts/$ID/revisions" \
  -H "Authorization: Bearer $PL_KEY"

# Ohne Rumpf: letzter Stand. Mit revision: dieser Stand.
curl -s -X POST "$PL/api/v1/prompts/$ID/restore" \
  -H "Authorization: Bearer $PL_WRITE_KEY" \
  -H "Content-Type: application/json" -d '{"revision": 2}'
```

Gelöscht wird weich: der Eintrag verschwindet aus Listen und Suche, bleibt aber
über die Revisionen wiederherstellbar.

### Tags

```bash
curl -s -H "Authorization: Bearer $PL_KEY" "$PL/api/v1/tags"
```

```json
{ "tags": [ { "name": "code", "count": 7 }, { "name": "review", "count": 3 } ] }
```

---

## Fehler

Alle Fehler haben dieselbe Form:

```json
{ "error": { "code": "forbidden", "message": "Dieser Key darf nur lesen. …" } }
```

| Status | `code`                  | Bedeutung |
|--------|-------------------------|-----------|
| 400    | `bad_request`           | Eingabe unvollständig oder unzulässig |
| 401    | `unauthorized`          | Kein oder falsch geformter Authorization-Header |
| 401    | `invalid_key`           | Key unbekannt, verfälscht oder von einer anderen Instanz |
| 401    | `key_revoked`           | Key wurde widerrufen (endgültig) |
| 401    | `key_expired`           | Ablaufdatum überschritten |
| 401    | `owner_inactive`        | Besitzer hat gerade keinen Zugang — Key ist inaktiv, nicht tot |
| 403    | `forbidden`             | Rolle reicht nicht (etwa Schreiben mit einem Lese-Key) |
| 403    | `forbidden_for_api_key` | Nur im Browser erreichbar (Verwaltung) |
| 404    | `not_found`             | Nicht vorhanden **oder** für diesen Aufrufer nicht sichtbar |
| 429    | `rate_limited`          | Zu viele Anfragen |
| 503    | `provider_unavailable`  | Anmeldedienst nicht erreichbar |

`404` steht bewusst auch für „existiert, aber gehört jemand anderem und ist
privat" — sonst verriete die Antwort die Existenz fremder Einträge.

---

## Rate-Limit

Jede Antwort trägt:

```
RateLimit-Limit:     120
RateLimit-Remaining: 118
RateLimit-Reset:     31
```

Bei Überschreitung: `429` mit `Retry-After` in Sekunden. Wer `RateLimit-Remaining`
auswertet, läuft gar nicht erst hinein. Ein einfaches, geduldiges Muster:

```bash
while :; do
  code=$(curl -s -o /tmp/out -w '%{http_code}' \
         -H "Authorization: Bearer $PL_KEY" "$PL/api/v1/prompts")
  [[ "$code" == "429" ]] || break
  sleep 5
done
```

---

## Hinweise für den Einsatz in Skripten und Assistenten

* **Für Automatisierung reicht fast immer ein Lese-Key.** Er kann bei einem
  Fehler nichts kaputt machen. Einen Schreib-Key nur dort, wo wirklich
  geschrieben wird.
* **Je Zweck ein eigener Key**, mit sprechendem Namen („Claude Code – lesend").
  Dann lässt sich einer widerrufen, ohne die anderen zu treffen.
* **Rotation** braucht keine Ausfallzeit: neuen Key anlegen, einsetzen, alten
  widerrufen. Mehrere gültige Keys nebeneinander sind vorgesehen.
* **Nie in ein Repository committen.** Der Präfix `plk_` macht Keys greppbar —
  das hilft beim Suchen, aber eben auch anderen.
* Ein Key hat immer ein Ablaufdatum (Vorgabe 365 Tage). `GET /me` verrät nicht,
  wann es soweit ist; die Oberfläche zeigt es unter „API-Keys".
