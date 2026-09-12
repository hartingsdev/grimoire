package auth

import (
	"fmt"
	"strings"
)

// RoleMapper bildet einen Claim aus dem IdP auf eine Rolle ab.
//
// Der Claim-Pfad darf verschachtelt sein, damit die App nicht an einen Provider
// gebunden ist:
//
//	groups                          Authentik, Authelia
//	prompt_library_role             eigener Claim, pro Anwendung vergeben
//	resource_access.prompt-lib.roles Keycloak
//
// Ist Map leer, gilt der Claim-Wert unmittelbar als Rollenname. Liefert der
// Claim mehrere Werte, gewinnt die höchste Rolle.
type RoleMapper struct {
	Path []string
	Map  map[string]Role
}

// NewRoleMapper baut den Mapper aus OIDC_ROLE_CLAIM und OIDC_ROLE_MAP.
// Die Map hat die Form "gruppe-a:admin,gruppe-b:editor".
func NewRoleMapper(claimPath, rawMap string) (*RoleMapper, error) {
	path := strings.Split(strings.TrimSpace(claimPath), ".")
	if len(path) == 0 || path[0] == "" {
		return nil, fmt.Errorf("OIDC_ROLE_CLAIM ist leer")
	}
	m := &RoleMapper{Path: path}

	if strings.TrimSpace(rawMap) == "" {
		return m, nil
	}
	m.Map = map[string]Role{}
	for _, pair := range strings.Split(rawMap, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		claimValue, roleName, ok := strings.Cut(pair, ":")
		if !ok {
			return nil, fmt.Errorf("OIDC_ROLE_MAP: %q ist kein Paar der Form claim-wert:rolle", pair)
		}
		role := ParseRole(roleName)
		if !role.Valid() {
			return nil, fmt.Errorf("OIDC_ROLE_MAP: %q ist keine gültige Rolle (viewer, editor, admin)", roleName)
		}
		m.Map[strings.TrimSpace(claimValue)] = role
	}
	if len(m.Map) == 0 {
		return nil, fmt.Errorf("OIDC_ROLE_MAP enthält keine verwertbaren Paare")
	}
	return m, nil
}

// Resolve liest den Claim und liefert die höchste zutreffende Rolle.
// Kein Treffer bedeutet RoleNone und damit kein Zugriff.
func (m *RoleMapper) Resolve(claims map[string]any) Role {
	best := RoleNone
	for _, value := range m.lookup(claims) {
		var candidate Role
		if m.Map == nil {
			candidate = ParseRole(value)
		} else {
			candidate = m.Map[value]
		}
		if candidate.Rank() > best.Rank() {
			best = candidate
		}
	}
	return best
}

// lookup folgt dem Claim-Pfad und gibt alle gefundenen Werte als Strings zurück.
func (m *RoleMapper) lookup(claims map[string]any) []string {
	var current any = claims
	for _, segment := range m.Path {
		obj, ok := current.(map[string]any)
		if !ok {
			return nil
		}
		current, ok = obj[segment]
		if !ok {
			return nil
		}
	}
	return flatten(current)
}

func flatten(v any) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
	case []string:
		return t
	case []any:
		var out []string
		for _, item := range t {
			out = append(out, flatten(item)...)
		}
		return out
	default:
		return nil
	}
}
