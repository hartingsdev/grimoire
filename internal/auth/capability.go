package auth

// Capability ist ein einzelnes Recht. Routen deklarieren, welche sie brauchen;
// Principals bekommen sie über Capabilities() zugeteilt.
type Capability string

const (
	CapPromptsRead  Capability = "prompts:read"
	CapPromptsWrite Capability = "prompts:write"
	CapKeysManage   Capability = "keys:manage"
	CapAdminRead    Capability = "admin:read"
	CapAdminUsers   Capability = "admin:users"
	CapAuditRead    Capability = "audit:read"
)

// ManagementCapabilities sind die Rechte, die ein API-Key niemals erhalten darf.
// routes_test.go prüft gegen genau diese Liste, dass keine Route sie an einen
// Key ausgibt.
var ManagementCapabilities = []Capability{
	CapKeysManage, CapAdminRead, CapAdminUsers, CapAuditRead,
}

// Kind unterscheidet, wie sich ein Principal ausgewiesen hat.
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

// Capabilities leitet aus einem Principal seine Rechte ab. Das ist die einzige
// Stelle, an der das passiert — für Browser-Sessions wie für API-Keys.
//
// Die Prüfung auf KindSession im Admin-Zweig ist die vollständige Umsetzung von
// "API-Keys können keine Keys verwalten": ein Key bekommt die Verwaltungsrechte
// selbst dann nicht, wenn jemand ihm von Hand role='admin' in die Datenbank
// schreibt. Die Startprüfung in httpapi und routes_test.go sorgen nur dafür,
// dass niemand später an dieser Funktion vorbei routet.
func Capabilities(p Principal) CapSet {
	caps := CapSet{}
	switch p.Role {
	case RoleViewer:
		caps.add(CapPromptsRead)
	case RoleEditor:
		caps.add(CapPromptsRead, CapPromptsWrite)
		if p.Kind == KindSession {
			// Bearbeiter verwalten ihre eigenen Keys; die Einschränkung auf die
			// eigenen liegt in den Abfragen, nicht in der Fähigkeit.
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
