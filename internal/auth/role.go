// Package auth holds roles, capabilities, the OIDC flow and API keys.
// Capabilities() in capability.go is the only place where an identity turns
// into permissions.
package auth

import "strings"

// Role is a principal's role. For people it comes from the IdP only; the
// database keeps it as an explicitly marked cache.
type Role string

const (
	RoleNone   Role = ""
	RoleViewer Role = "viewer"
	RoleEditor Role = "editor"
	RoleAdmin  Role = "admin"
)

// Rank orders roles, for MinRole and for "highest wins" in claim mapping.
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

func (r Role) Label() string {
	switch r {
	case RoleViewer:
		return "Viewer"
	case RoleEditor:
		return "Editor"
	case RoleAdmin:
		return "Administrator"
	default:
		return "no access"
	}
}

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

// MinRole returns the weaker of two roles. Used to combine an API key's role
// with its owner's current role: a key can never outrank the person who issued it.
func MinRole(a, b Role) Role {
	if a.Rank() <= b.Rank() {
		return a
	}
	return b
}
