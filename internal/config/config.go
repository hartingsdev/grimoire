// Package config loads and validates one instance's configuration from the
// environment. Each instance gets its own .env file; the process itself only
// ever sees environment variables.
package config

import (
	"encoding/base64"
	"fmt"
	"net/netip"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// AdminPrivateAccess controls whether admins can reach other people's private prompts.
type AdminPrivateAccess string

const (
	AdminPrivateNone       AdminPrivateAccess = "none"
	AdminPrivateBreakGlass AdminPrivateAccess = "break-glass"
	AdminPrivateFull       AdminPrivateAccess = "full"
)

// ClaimsSource decides where role-mapping claims come from. Many providers
// expose groups only at userinfo, not in the ID token.
type ClaimsSource string

const (
	ClaimsIDToken  ClaimsSource = "id_token"
	ClaimsUserinfo ClaimsSource = "userinfo"
	ClaimsBoth     ClaimsSource = "both"
)

type OIDC struct {
	Issuer             string
	ClientID           string
	ClientSecret       string
	RedirectURI        string
	Scopes             []string
	RoleClaim          string // Pfad, z.B. "groups" oder "resource_access.app.roles"
	RoleMap            string // roh, ausgewertet in internal/auth
	ClaimsSource       ClaimsSource
	PostLogoutRedirect string
}

type Config struct {
	AppTitle    string
	AppInstance string // Teil des API-Key-Präfix, daher unveränderlich nach Ausgabe
	BaseURL     string
	ListenAddr  string
	DBPath      string
	StaticDir   string // leer = eingebettetes Frontend
	LogLevel    string

	TrustedProxies    []netip.Prefix
	DataEncryptionKey []byte
	CookieSecure      bool

	SessionMaxAge      time.Duration
	RevalidateInterval time.Duration
	OwnerStaleAfter    time.Duration

	OIDC OIDC

	PrivatePrompts     bool
	AdminPrivateAccess AdminPrivateAccess
	APIKeyMaxLifetime  time.Duration
	RateLimitPerMin    int
}

var instanceRe = regexp.MustCompile(`^[a-z0-9]{1,16}$`)

// Load reads and fully validates the configuration before the process does
// anything else. Misconfiguration is a startup failure, not a runtime surprise.
func Load() (*Config, error) {
	var errs []string
	fail := func(format string, a ...any) { errs = append(errs, fmt.Sprintf(format, a...)) }

	c := &Config{
		AppTitle:    env("APP_TITLE", "Promptory"),
		AppInstance: env("APP_INSTANCE", ""),
		BaseURL:     strings.TrimRight(env("BASE_URL", ""), "/"),
		ListenAddr:  env("LISTEN_ADDR", ":8080"),
		DBPath:      env("DB_PATH", "/data/prompts.db"),
		StaticDir:   env("STATIC_DIR", ""),
		LogLevel:    env("LOG_LEVEL", "info"),
	}

	if !instanceRe.MatchString(c.AppInstance) {
		fail("APP_INSTANCE muss gesetzt sein und aus 1-16 Kleinbuchstaben/Ziffern bestehen (z.B. privat, arbeit) — er ist Teil jedes API-Keys")
	}
	if c.BaseURL == "" {
		fail("BASE_URL muss gesetzt sein (z.B. https://prompts.example.org)")
	}

	for _, raw := range splitList(env("TRUSTED_PROXY_CIDRS", "")) {
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			fail("TRUSTED_PROXY_CIDRS: %q ist kein gültiges Netz (z.B. 172.16.0.0/12)", raw)
			continue
		}
		c.TrustedProxies = append(c.TrustedProxies, p)
	}

	key, err := base64.StdEncoding.DecodeString(env("DATA_ENCRYPTION_KEY", ""))
	switch {
	case err != nil:
		fail("DATA_ENCRYPTION_KEY ist kein gültiges base64 — erzeugen mit: openssl rand -base64 32")
	case len(key) != 32:
		fail("DATA_ENCRYPTION_KEY muss 32 Byte lang sein (base64-kodiert), ist %d — erzeugen mit: openssl rand -base64 32", len(key))
	default:
		c.DataEncryptionKey = key
	}

	c.CookieSecure = envBool("COOKIE_SECURE", true, &errs)
	c.SessionMaxAge = envDur("SESSION_MAX_AGE", 12*time.Hour, &errs)
	c.RevalidateInterval = envDur("AUTH_REVALIDATE_INTERVAL", 15*time.Minute, &errs)
	c.OwnerStaleAfter = envDur("OWNER_STALE_AFTER", 720*time.Hour, &errs)
	c.APIKeyMaxLifetime = envDur("API_KEY_MAX_LIFETIME", 8760*time.Hour, &errs)

	c.OIDC = OIDC{
		Issuer:             strings.TrimRight(env("OIDC_ISSUER", ""), "/"),
		ClientID:           env("OIDC_CLIENT_ID", ""),
		ClientSecret:       env("OIDC_CLIENT_SECRET", ""),
		RedirectURI:        env("OIDC_REDIRECT_URI", ""),
		Scopes:             splitList(env("OIDC_SCOPES", "openid,profile,email")),
		RoleClaim:          env("OIDC_ROLE_CLAIM", "groups"),
		RoleMap:            env("OIDC_ROLE_MAP", ""),
		ClaimsSource:       ClaimsSource(env("OIDC_CLAIMS_SOURCE", string(ClaimsBoth))),
		PostLogoutRedirect: env("OIDC_POST_LOGOUT_REDIRECT", ""),
	}
	// A slice, not a map: the error list should read the same on every start.
	for _, required := range []struct{ name, value string }{
		{"OIDC_ISSUER", c.OIDC.Issuer},
		{"OIDC_CLIENT_ID", c.OIDC.ClientID},
		{"OIDC_CLIENT_SECRET", c.OIDC.ClientSecret},
		{"OIDC_REDIRECT_URI", c.OIDC.RedirectURI},
	} {
		if required.value == "" {
			fail("%s muss gesetzt sein", required.name)
		}
	}
	switch c.OIDC.ClaimsSource {
	case ClaimsIDToken, ClaimsUserinfo, ClaimsBoth:
	default:
		fail("OIDC_CLAIMS_SOURCE muss id_token, userinfo oder both sein, ist %q", c.OIDC.ClaimsSource)
	}
	if c.OIDC.RoleClaim == "" {
		fail("OIDC_ROLE_CLAIM muss gesetzt sein — ohne Rollen-Claim kommt niemand hinein")
	}

	c.PrivatePrompts = envBool("PRIVATE_PROMPTS", true, &errs)
	c.AdminPrivateAccess = AdminPrivateAccess(env("ADMIN_PRIVATE_ACCESS", string(AdminPrivateBreakGlass)))
	switch c.AdminPrivateAccess {
	case AdminPrivateNone, AdminPrivateBreakGlass, AdminPrivateFull:
	default:
		fail("ADMIN_PRIVATE_ACCESS muss none, break-glass oder full sein, ist %q", c.AdminPrivateAccess)
	}

	c.RateLimitPerMin = envInt("RATE_LIMIT_PER_MIN", 120, &errs)
	if c.RateLimitPerMin < 1 {
		fail("RATE_LIMIT_PER_MIN muss mindestens 1 sein")
	}

	if len(errs) > 0 {
		return nil, fmt.Errorf("Konfiguration unvollständig:\n  - %s", strings.Join(errs, "\n  - "))
	}
	return c, nil
}

func env(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return def
}

func splitList(s string) []string {
	var out []string
	for _, part := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' }) {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

func envBool(key string, def bool, errs *[]string) bool {
	raw := env(key, "")
	if raw == "" {
		return def
	}
	switch strings.ToLower(raw) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	}
	*errs = append(*errs, fmt.Sprintf("%s muss true/false sein, ist %q", key, raw))
	return def
}

func envDur(key string, def time.Duration, errs *[]string) time.Duration {
	raw := env(key, "")
	if raw == "" {
		return def
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		*errs = append(*errs, fmt.Sprintf("%s muss eine positive Dauer sein (z.B. 12h, 15m), ist %q", key, raw))
		return def
	}
	return d
}

func envInt(key string, def int, errs *[]string) int {
	raw := env(key, "")
	if raw == "" {
		return def
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		*errs = append(*errs, fmt.Sprintf("%s muss eine ganze Zahl sein, ist %q", key, raw))
		return def
	}
	return n
}
