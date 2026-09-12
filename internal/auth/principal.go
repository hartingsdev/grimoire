package auth

import (
	"context"
	"time"
)

// Principal is the result of authentication, by cookie session or API key.
// Past this point no handler knows the difference.
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
	KeyRole   Role // the key's own role, for display and diagnosis only

	caps CapSet
}

func (p *Principal) Can(cap Capability) bool {
	if p == nil {
		return false
	}
	if p.caps == nil {
		p.caps = Capabilities(*p)
	}
	return p.caps.Has(cap)
}

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

func FromContext(ctx context.Context) *Principal {
	p, _ := ctx.Value(ctxKey{}).(*Principal)
	return p
}

// OwnerStale reports whether a key owner's cached role is too old to trust.
// Without it, the keys of someone who never signs in again would keep running
// on a stale role.
func OwnerStale(cachedAt time.Time, maxAge time.Duration, now time.Time) bool {
	if maxAge <= 0 {
		return false
	}
	return cachedAt.IsZero() || now.Sub(cachedAt) > maxAge
}
