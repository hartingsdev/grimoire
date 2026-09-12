package auth

import (
	"context"
	"time"
)

// Principal ist das Ergebnis der Authentifizierung — egal ob per Cookie-Session
// oder per API-Key. Ab hier kennt kein Handler mehr den Unterschied.
type Principal struct {
	Kind        Kind
	UserID      string // interne users.id, auch bei API-Keys die des Besitzers
	Subject     string // OIDC sub, leer bei Service-Keys
	Email       string
	DisplayName string
	Role        Role // bei Keys bereits min(Key-Rolle, Besitzer-Rolle)

	SessionID string
	CSRFToken string
	KeyID     string
	KeyRole   Role // ursprüngliche Rolle des Keys, nur zur Anzeige/Diagnose

	caps CapSet
}

// Can prüft ein einzelnes Recht.
func (p *Principal) Can(cap Capability) bool {
	if p == nil {
		return false
	}
	if p.caps == nil {
		p.caps = Capabilities(*p)
	}
	return p.caps.Has(cap)
}

// CapabilityList liefert die Rechte als sortierbare Liste für /api/v1/me.
func (p *Principal) CapabilityList() []Capability {
	if p == nil {
		return nil
	}
	if p.caps == nil {
		p.caps = Capabilities(*p)
	}
	out := make([]Capability, 0, len(p.caps))
	for _, cap := range []Capability{
		CapPromptsRead, CapPromptsWrite, CapKeysManage,
		CapAdminRead, CapAdminUsers, CapAuditRead,
	} {
		if p.caps.Has(cap) {
			out = append(out, cap)
		}
	}
	return out
}

type ctxKey struct{}

func WithPrincipal(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, ctxKey{}, p)
}

// FromContext liefert den Principal des laufenden Requests, oder nil.
func FromContext(ctx context.Context) *Principal {
	p, _ := ctx.Value(ctxKey{}).(*Principal)
	return p
}

// OwnerStale meldet, ob die zwischengespeicherte Rolle des Key-Besitzers zu alt
// ist, um ihr noch zu trauen. Meldet sich jemand nie wieder an, laufen seine
// Keys dadurch aus, statt mit einer veralteten Rolle weiterzulaufen.
func OwnerStale(cachedAt time.Time, maxAge time.Duration, now time.Time) bool {
	if maxAge <= 0 {
		return false
	}
	return cachedAt.IsZero() || now.Sub(cachedAt) > maxAge
}
