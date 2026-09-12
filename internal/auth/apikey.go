package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// Aufbau eines API-Keys:
//
//	plk_privat_9f3k2md7qa4x_Sx7Qv3nR8tL0wB2yE5uH1jK4pD6gZ9aC3fM8sN0
//	└┬┘ └──┬─┘ └─────┬────┘ └──────────────────┬──────────────────┘
//	 │     │         │                         └ Geheimnis, nur als SHA-256 gespeichert
//	 │     │         └ Key-ID: Klartext in der Datenbank, indiziert, in der UI sichtbar
//	 │     └ Instanz aus APP_INSTANCE
//	 └ fester, in Logs und Konfigdateien wiedererkennbarer Präfix
//
// Die Zweiteilung in ID und Geheimnis erlaubt einen Index-Zugriff statt eines
// Scans über alle Keys — und die ID darf man gefahrlos anzeigen und protokollieren.
const (
	keyPrefix     = "plk"
	keyIDLength   = 12
	keySecretSize = 32
)

// Alphabet ohne l, o, 0 und 1, damit vorgelesene oder abgetippte IDs eindeutig sind.
const keyIDAlphabet = "abcdefghijkmnpqrstuvwxyz23456789"

var ErrMalformedKey = errors.New("API-Key hat ein unbekanntes Format")

// NewKey erzeugt einen Key für die angegebene Instanz. Der Klartext wird nur
// einmal zurückgegeben und nirgends gespeichert.
func NewKey(instance string) (plaintext, id string, hash []byte, err error) {
	idBytes := make([]byte, keyIDLength)
	if _, err = rand.Read(idBytes); err != nil {
		return "", "", nil, err
	}
	var sb strings.Builder
	for _, b := range idBytes {
		sb.WriteByte(keyIDAlphabet[int(b)%len(keyIDAlphabet)])
	}
	id = sb.String()

	secretBytes := make([]byte, keySecretSize)
	if _, err = rand.Read(secretBytes); err != nil {
		return "", "", nil, err
	}
	secret := base64.RawURLEncoding.EncodeToString(secretBytes)

	plaintext = fmt.Sprintf("%s_%s_%s_%s", keyPrefix, instance, id, secret)
	return plaintext, id, HashSecret(secret), nil
}

// ParseKey zerlegt einen vorgelegten Key und prüft dabei Präfix und Instanz.
// Ein Key der falschen Instanz wird hier abgewiesen, bevor die Datenbank
// überhaupt angefasst wird.
func ParseKey(instance, raw string) (id, secret string, err error) {
	parts := strings.Split(strings.TrimSpace(raw), "_")
	if len(parts) != 4 {
		return "", "", ErrMalformedKey
	}
	if parts[0] != keyPrefix || parts[1] != instance {
		return "", "", ErrMalformedKey
	}
	if len(parts[2]) != keyIDLength || parts[3] == "" {
		return "", "", ErrMalformedKey
	}
	return parts[2], parts[3], nil
}

// HashSecret hasht den geheimen Teil eines Keys.
//
// Bewusst SHA-256 und nicht bcrypt/argon2: langsame Hashes existieren, um
// schwache, von Menschen gewählte Passwörter gegen Brute Force zu schützen.
// Ein Geheimnis mit 32 Byte Entropie ist nicht ratbar — ein langsamer Hash
// würde nur jeden einzelnen API-Request verteuern.
func HashSecret(secret string) []byte {
	sum := sha256.Sum256([]byte(secret))
	return sum[:]
}

// SecretMatches vergleicht in konstanter Zeit.
func SecretMatches(secret string, stored []byte) bool {
	return subtle.ConstantTimeCompare(HashSecret(secret), stored) == 1
}

// MaskKeyID kürzt eine Key-ID für Log-Ausgaben.
func MaskKeyID(id string) string {
	if len(id) <= 4 {
		return id
	}
	return id[:4] + "…"
}
