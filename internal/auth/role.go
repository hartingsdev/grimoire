// Package auth enthält Rollen, Fähigkeiten, den OIDC-Ablauf und API-Keys.
// Die Rechteableitung in capability.go ist die einzige Stelle im Projekt,
// an der aus einer Identität Rechte werden.
package auth

import "strings"

// Role ist die Rolle eines Principals. Für Menschen kommt sie ausschließlich
// aus dem IdP; in der Datenbank steht sie nur als ausdrücklich markierter Cache.
type Role string

const (
	RoleNone   Role = ""
	RoleViewer Role = "viewer"
	RoleEditor Role = "editor"
	RoleAdmin  Role = "admin"
)

// Rank ordnet die Rollen. Wird für MinRole und für "höchste gewinnt" beim
// Claim-Mapping gebraucht.
func (r Role) Rank() int {
	switch r {
	case RoleViewer:
		return 1
	case RoleEditor:
		return 2
	case RoleAdmin:
		return 3
	default:
		return 0
	}
}

func (r Role) Valid() bool { return r.Rank() > 0 }

// Label ist die Beschriftung in der Oberfläche.
func (r Role) Label() string {
	switch r {
	case RoleViewer:
		return "Betrachter"
	case RoleEditor:
		return "Bearbeiter"
	case RoleAdmin:
		return "Administrator"
	default:
		return "kein Zugriff"
	}
}

// ParseRole nimmt einen Rollennamen entgegen, wie er in der Datenbank oder in
// einem Claim steht.
func ParseRole(s string) Role {
	switch Role(strings.ToLower(strings.TrimSpace(s))) {
	case RoleViewer:
		return RoleViewer
	case RoleEditor:
		return RoleEditor
	case RoleAdmin:
		return RoleAdmin
	default:
		return RoleNone
	}
}

// MinRole liefert die schwächere von zwei Rollen. Damit wird die Rolle eines
// API-Keys mit der aktuellen Rolle seines Besitzers verrechnet: ein Key kann
// nie mehr dürfen als der Mensch, der ihn ausgestellt hat.
func MinRole(a, b Role) Role {
	if a.Rank() <= b.Rank() {
		return a
	}
	return b
}
