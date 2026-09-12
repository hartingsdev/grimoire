package store

import (
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/hartingsdev/solid-bassoon/internal/auth"
)

// TombstoneName steht in der Oberfläche, wo ein gelöschter Nutzer als Autor
// auftaucht. Die Zeile bleibt erhalten, damit die Historie nicht zerreißt.
const TombstoneName = "Gelöschter Nutzer"

type User struct {
	ID           string
	Sub          string // leer bei einer Grabstein-Zeile
	Email        string
	DisplayName  string
	CachedRole   auth.Role // Cache aus dem IdP, nicht autoritativ
	CachedRoleAt time.Time
	CreatedAt    time.Time
	LastLoginAt  time.Time
	DeletedAt    time.Time
}

func (u User) Deleted() bool { return !u.DeletedAt.IsZero() }

// Name liefert die Anzeige für Autorenfelder.
func (u User) Name() string {
	switch {
	case u.Deleted():
		return TombstoneName
	case u.DisplayName != "":
		return u.DisplayName
	case u.Email != "":
		return u.Email
	default:
		return u.ID
	}
}

const (
	VisibilityShared  = "shared"
	VisibilityPrivate = "private"
)

type Prompt struct {
	ID            string
	Title         string
	Body          string
	Visibility    string
	OwnerID       string
	OwnerName     string
	Tags          []string
	CreatedAt     time.Time
	CreatedBy     string
	UpdatedAt     time.Time
	UpdatedBy     string
	UpdatedByName string
	DeletedAt     time.Time
	Revision      int
}

type Revision struct {
	Revision      int
	Title         string
	Body          string
	Visibility    string
	Tags          []string
	Kind          string
	ChangedAt     time.Time
	ChangedBy     string
	ChangedByName string
}

type APIKey struct {
	ID            string
	Name          string
	Role          auth.Role
	OwnerID       string
	OwnerName     string
	CreatedAt     time.Time
	ExpiresAt     time.Time
	LastUsedAt    time.Time
	RevokedAt     time.Time
	RevokedReason string

	// EffectiveRole ist min(Rolle des Keys, aktuelle Rolle des Besitzers).
	// Steht hier RoleNone, obwohl der Key nicht widerrufen ist, hat der
	// Besitzer seinen Zugang verloren — der Key ist inaktiv, aber nicht tot.
	EffectiveRole auth.Role
}

func (k APIKey) Revoked() bool { return !k.RevokedAt.IsZero() }
func (k APIKey) Expired(now time.Time) bool {
	return !k.ExpiresAt.IsZero() && now.After(k.ExpiresAt)
}

type Session struct {
	ID              string
	UserID          string
	Role            auth.Role
	CSRFToken       string
	CreatedAt       time.Time
	ExpiresAt       time.Time
	LastSeenAt      time.Time
	RevalidateAfter time.Time
	AccessToken     string
	RefreshToken    string
	TokenExpiry     time.Time
}

type AuditEntry struct {
	At         time.Time
	ActorID    string
	ActorName  string
	ActorKind  string
	Action     string
	TargetType string
	TargetID   string
	Reason     string
	DetailJSON string
}

// newID erzeugt eine UUIDv7: zeitlich sortierbar, damit Einfügungen in SQLite
// am Index-Ende landen, und gleichzeitig kollisionsfrei über Instanzgrenzen —
// damit lassen sich Prompts zwischen privat und arbeit exportieren.
func newID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("Zufallsquelle nicht verfügbar: " + err.Error())
	}
	ms := uint64(time.Now().UnixMilli())
	b[0] = byte(ms >> 40)
	b[1] = byte(ms >> 32)
	b[2] = byte(ms >> 24)
	b[3] = byte(ms >> 16)
	b[4] = byte(ms >> 8)
	b[5] = byte(ms)
	b[6] = (b[6] & 0x0f) | 0x70 // Version 7
	b[8] = (b[8] & 0x3f) | 0x80 // Variante RFC 4122
	return hex.EncodeToString(b[0:4]) + "-" + hex.EncodeToString(b[4:6]) + "-" +
		hex.EncodeToString(b[6:8]) + "-" + hex.EncodeToString(b[8:10]) + "-" +
		hex.EncodeToString(b[10:16])
}

// NewToken erzeugt einen opaken Zufallswert für Sessions und CSRF-Token.
func NewToken() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("Zufallsquelle nicht verfügbar: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}
