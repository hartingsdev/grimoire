package auth

import (
	"fmt"
	"strings"
)

// RoleMapper maps an IdP claim onto a role. The claim path may be nested, so
// the app is not tied to one provider:
//
//	groups                           Authentik, Authelia
//	grimoire_role                   custom claim, granted per application
//	resource_access.grimoire.roles  Keycloak
//
// With an empty Map the claim value is taken as the role name directly. If the
// claim carries several values, the highest role wins.
type RoleMapper struct {
	Path []string
	Map  map[string]Role
}

// NewRoleMapper builds the mapper from OIDC_ROLE_CLAIM and OIDC_ROLE_MAP,
// the latter shaped like "group-a:admin,group-b:editor".
func NewRoleMapper(claimPath, rawMap string) (*RoleMapper, error) {
	path := strings.Split(strings.TrimSpace(claimPath), ".")
	if len(path) == 0 || path[0] == "" {
		return nil, fmt.Errorf("OIDC_ROLE_CLAIM is empty")
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
			return nil, fmt.Errorf("OIDC_ROLE_MAP: %q is not a claim-value:role pair", pair)
		}
		role := ParseRole(roleName)
		if !role.Valid() {
			return nil, fmt.Errorf("OIDC_ROLE_MAP: %q is not a valid role (viewer, editor, admin)", roleName)
		}
		m.Map[strings.TrimSpace(claimValue)] = role
	}
	if len(m.Map) == 0 {
		return nil, fmt.Errorf("OIDC_ROLE_MAP contains no usable pairs")
	}
	return m, nil
}

// Resolve reads the claim and returns the highest matching role. No match
// means RoleNone, which means no access.
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
