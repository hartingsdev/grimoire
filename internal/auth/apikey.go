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

// API key layout:
//
//	plk_privat_9f3k2md7qa4x_Sx7Qv3nR8tL0wB2yE5uH1jK4pD6gZ9aC3fM8sN0
//	└┬┘ └──┬─┘ └─────┬────┘ └──────────────────┬──────────────────┘
//	 │     │         │                         └ secret, stored only as SHA-256
//	 │     │         └ key id: plaintext in the database, indexed, shown in the UI
//	 │     └ instance from APP_INSTANCE
//	 └ fixed prefix, recognizable in logs and config files
//
// Splitting id from secret buys an index lookup instead of a scan over every
// key, and the id is safe to display and log.
const (
	keyPrefix     = "plk"
	keyIDLength   = 12
	keySecretSize = 32
)

// No l, o, 0 or 1, so ids stay unambiguous when read aloud or typed.
const keyIDAlphabet = "abcdefghijkmnpqrstuvwxyz23456789"

var ErrMalformedKey = errors.New("API key has an unknown format")

// NewKey mints a key for the given instance. The plaintext is returned once
// and stored nowhere.
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

// ParseKey splits a presented key and checks prefix and instance. A key from
// another instance is rejected here, before any database access.
func ParseKey(instance, raw string) (id, secret string, err error) {
	// SplitN, not Split: the base64url secret may itself contain underscores.
	parts := strings.SplitN(strings.TrimSpace(raw), "_", 4)
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

// HashSecret hashes the secret half of a key.
//
// SHA-256 rather than bcrypt/argon2 on purpose: slow hashes exist to protect
// weak, human-chosen passwords from brute force. A 32-byte random secret is
// not guessable, so a slow hash would only tax every API request.
func HashSecret(secret string) []byte {
	sum := sha256.Sum256([]byte(secret))
	return sum[:]
}

func SecretMatches(secret string, stored []byte) bool {
	return subtle.ConstantTimeCompare(HashSecret(secret), stored) == 1
}

func MaskKeyID(id string) string {
	if len(id) <= 4 {
		return id
	}
	return id[:4] + "…"
}
