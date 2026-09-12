package auth

type Capability string

const (
	CapPromptsRead  Capability = "prompts:read"
	CapPromptsWrite Capability = "prompts:write"
	CapKeysManage   Capability = "keys:manage"
	CapAdminRead    Capability = "admin:read"
	CapAdminUsers   Capability = "admin:users"
	CapAuditRead    Capability = "audit:read"
)

// ManagementCapabilities must never be granted to an API key. routes_test.go
// checks every route against exactly this list.
var ManagementCapabilities = []Capability{
	CapKeysManage, CapAdminRead, CapAdminUsers, CapAuditRead,
}

type Kind string

const (
	KindSession Kind = "session"
	KindAPIKey  Kind = "apikey"
)

type CapSet map[Capability]struct{}

func (c CapSet) add(caps ...Capability) {
	for _, cap := range caps {
		c[cap] = struct{}{}
	}
}

func (c CapSet) Has(cap Capability) bool {
	_, ok := c[cap]
	return ok
}

// Capabilities derives permissions from a principal — the only place this
// happens, for browser sessions and API keys alike.
//
// The KindSession check is the whole of "API keys cannot manage keys": a key
// is denied management rights even if someone hand-writes role='admin' into
// its database row. The startup check and routes_test.go only make sure
// nothing later routes around this function.
func Capabilities(p Principal) CapSet {
	caps := CapSet{}
	switch p.Role {
	case RoleViewer:
		caps.add(CapPromptsRead)
	case RoleEditor:
		caps.add(CapPromptsRead, CapPromptsWrite)
		if p.Kind == KindSession {
			// Editors manage their own keys; the "own" part lives in the
			// queries, not in the capability.
			caps.add(CapKeysManage)
		}
	case RoleAdmin:
		caps.add(CapPromptsRead, CapPromptsWrite)
		if p.Kind == KindSession {
			caps.add(CapKeysManage, CapAdminRead, CapAdminUsers, CapAuditRead)
		}
	}
	return caps
}
