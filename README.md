# Prompt-Bibliothek

Eine selbst gehostete Sammlung von Prompts mit Anmeldung über OIDC und
rollenbasierten Rechten. Läuft als ein Container je Instanz, überall wo Docker
läuft — ohne Dienste eines bestimmten Anbieters.

* **[API.md](API.md)** — REST-Referenz mit curl-Beispielen, gedacht zum direkten
  Vorlegen an Skripte oder Claude Code
* **[DEPLOY.md](DEPLOY.md)** — Serverbetrieb, Einrichtung in Authentik, lokales
  Durchtesten, Sicherungen

---

## Was die Anwendung tut

Einträge mit Titel, Tags und mehrzeiligem Text; anlegen, ändern, löschen;
Volltextsuche über alles; Kopieren mit einem Klick. Einträge sind geteilt oder
privat. Jede Änderung wird versioniert, Löschen ist weich und umkehrbar.

Zwei getrennte Instanzen (privat, arbeit) aus demselben Image, mit je eigener
Konfiguration und eigener SQLite-Datei. Keine gemeinsamen Daten.

## Zwei Wege hinein, eine Rechteprüfung

**Menschen** melden sich über OIDC an (Authorization Code Flow mit PKCE). Der
Ablauf liegt vollständig im Server; im Browser landet nur ein Sitzungs-Cookie.

**Skripte** schicken `Authorization: Bearer plk_<instanz>_<id>_<geheimnis>`.

Beides mündet in denselben Principal, und ab da gibt es genau eine Ableitung
von Rechten:

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

Die Prüfung auf `Session` ist die vollständige Umsetzung von „API-Keys können
keine Keys verwalten". Zwei weitere Ebenen sorgen dafür, dass niemand daran
vorbeikommt: jede Route muss beim Registrieren ihren Schutz nennen (sonst
startet der Prozess nicht), und ein Test läuft über die gesamte Routentabelle
und weist nach, dass kein Endpunkt einem Key ein Verwaltungsrecht gibt.

## Entscheidungen, und warum

**Rollen kommen ausschließlich aus dem Anmeldedienst.** Es gibt keine Nutzer-
oder Rechteverwaltung in der App — eine zweite Stelle, an der Rollen stehen,
wäre eine zweite Stelle, die man vergessen kann. Der Claim ist frei
konfigurierbar (eigener Claim oder Gruppen, auch verschachtelt), damit die
Anwendung nicht an einen Provider gebunden ist. Wer keinen passenden Wert hat,
kommt nicht hinein, und es wird auch kein Konto angelegt.

**Während der Sitzung wird nachgefragt.** Alle 15 Minuten holt die App die
Claims neu. Wichtig ist dabei die Unterscheidung der Fehlerfälle: ein nicht
erreichbarer Anmeldedienst ist *keine Auskunft* und entzieht niemandem etwas —
sonst würde ein kurzer Ausfall alle Sitzungen beenden. Nur eine echte Antwort
ohne passende Rolle beendet die Sitzung.

**Ein Key kann nie mehr als sein Besitzer.** Die wirksame Rolle ist
`min(Rolle des Keys, aktuelle Rolle des Besitzers)`. Wird jemand herabgestuft,
verliert sein Schreib-Key das Schreibrecht von selbst. Damit das auch für
jemanden gilt, der sich nie wieder anmeldet, verfällt die zwischengespeicherte
Rolle nach `OWNER_STALE_AFTER` (Vorgabe 30 Tage) — der Key wird dann inaktiv
statt mit veralteten Rechten weiterzulaufen.

**Keys werden gehasht, aber mit SHA-256.** Langsame Hashes wie bcrypt schützen
schwache, von Menschen gewählte Passwörter. Ein Geheimnis mit 32 Byte Entropie
ist nicht ratbar — ein langsamer Hash würde nur jeden API-Request verteuern.

**Ein gelöschter Nutzer wird zum Grabstein.** Alle Fremdschlüssel zeigen auf
einen internen Surrogatschlüssel, nicht auf die `sub`. Beim Löschen werden
`sub`, E-Mail und Name geleert, die Zeile bleibt stehen: geteilte Einträge und
die Versionshistorie überleben, die Person ist trotzdem weg. Meldet sie sich
später erneut an, bekommt sie ein frisches, leeres Konto.

**„Privat" heißt privat.** Administratoren sehen von fremden privaten Einträgen
nur Kennzahlen. Für den Verdachtsfall gibt es eine ausdrückliche, protokollierte
Einzelfreigabe. Und in jeder Einstellung gilt: die Oberfläche sagt am
Sichtbarkeits-Schalter die Wahrheit darüber, wer mitlesen kann.

## Aufbau

```
cmd/server/        Start, Healthcheck-Modus, geordnetes Beenden
internal/config/   .env laden und vollständig prüfen (Fehler = Startfehler)
internal/auth/     Rollen, Fähigkeiten, API-Keys, OIDC, Claim-Mapping
internal/store/    SQLite: Schema, Migrationen, sämtliche Abfragen
internal/httpapi/  Routen mit deklariertem Schutz, Middleware, Handler
internal/ratelimit/
web/               Oberfläche, per go:embed in die Binary gebacken
```

Vier direkte Abhängigkeiten: `coreos/go-oidc`, `golang.org/x/oauth2`,
`modernc.org/sqlite` (cgo-frei → statische Binary) und die Standardbibliothek.
Routing kommt aus `net/http`, Migrationen aus eingebetteten `.sql`-Dateien.

## Entwickeln

```bash
docker compose -f docker-compose.dev.yml up -d   # nachgebildeter Anmeldedienst
./scripts/dev.sh                                 # Anwendung auf :8080
go test ./...
./scripts/test-api.sh http://localhost:8080 <lese-key> <schreib-key>
```

`STATIC_DIR=./web` (in `dev.sh` gesetzt) lädt die Oberfläche von der Platte —
Änderungen an HTML, CSS und JS wirken ohne Neuübersetzen.

## Stand

Die Oberfläche ist bewusst schlicht gehalten und noch nicht durchgestaltet.
