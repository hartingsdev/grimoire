package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/hartingsdev/solid-bassoon/internal/auth"
	"github.com/hartingsdev/solid-bassoon/internal/store"
)

type apiKeyJSON struct {
	ID            string     `json:"id"`
	Name          string     `json:"name"`
	Role          string     `json:"role"`
	EffectiveRole string     `json:"effectiveRole"`
	Owner         userRef    `json:"owner"`
	CreatedAt     time.Time  `json:"createdAt"`
	ExpiresAt     time.Time  `json:"expiresAt"`
	LastUsedAt    *time.Time `json:"lastUsedAt"`
	RevokedAt     *time.Time `json:"revokedAt"`
	Status        string     `json:"status"`
	StatusNote    string     `json:"statusNote"`
}

func toKeyJSON(k store.APIKey, now time.Time) apiKeyJSON {
	out := apiKeyJSON{
		ID: k.ID, Name: k.Name, Role: string(k.Role), EffectiveRole: string(k.EffectiveRole),
		Owner:     userRef{ID: k.OwnerID, Name: k.OwnerName},
		CreatedAt: k.CreatedAt, ExpiresAt: k.ExpiresAt,
	}
	if !k.LastUsedAt.IsZero() {
		t := k.LastUsedAt
		out.LastUsedAt = &t
	}
	if k.Revoked() {
		t := k.RevokedAt
		out.RevokedAt = &t
	}
	switch {
	case k.Revoked():
		out.Status, out.StatusNote = "revoked", "Widerrufen."
	case k.Expired(now):
		out.Status, out.StatusNote = "expired", "Abgelaufen."
	case !k.EffectiveRole.Valid():
		// Nicht widerrufen, aber wirkungslos: der Besitzer hat gerade keinen
		// Zugang oder war zu lange nicht angemeldet. Reversibel.
		out.Status = "inactive"
		out.StatusNote = "Inaktiv – der Besitzer hat derzeit keinen Zugang."
	case k.EffectiveRole != k.Role:
		out.Status = "reduced"
		out.StatusNote = "Eingeschränkt auf " + k.EffectiveRole.Label() +
			", weil der Besitzer nur noch diese Rolle hat."
	default:
		out.Status, out.StatusNote = "active", ""
	}
	return out
}

// handleListKeys zeigt Metadaten, nie den Key selbst. Bearbeiter sehen ihre
// eigenen, Admins auf Wunsch alle.
func (s *Server) handleListKeys(w http.ResponseWriter, r *http.Request) {
	p := auth.FromContext(r.Context())
	ownerFilter := p.UserID
	if r.URL.Query().Get("all") == "1" {
		if !p.Can(auth.CapAdminRead) {
			writeError(w, http.StatusForbidden, "forbidden",
				"Nur Administratoren sehen fremde Keys.")
			return
		}
		ownerFilter = ""
	}
	now := time.Now()
	keys, err := s.store.ListAPIKeys(r.Context(), ownerFilter, s.cfg.OwnerStaleAfter, now)
	if err != nil {
		s.writeStoreError(w, r, err)
		return
	}
	out := make([]apiKeyJSON, 0, len(keys))
	for _, k := range keys {
		out = append(out, toKeyJSON(k, now))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"keys": out, "scope": map[string]bool{"all": ownerFilter == ""},
	})
}

// handleCreateKey stellt einen Key aus. Der Klartext steht genau in dieser
// einen Antwort und danach nirgends mehr.
func (s *Server) handleCreateKey(w http.ResponseWriter, r *http.Request) {
	p := auth.FromContext(r.Context())
	var in struct {
		Name          string `json:"name"`
		Role          string `json:"role"`
		ExpiresInDays int    `json:"expiresInDays"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || len(in.Name) > 120 {
		writeError(w, http.StatusBadRequest, "bad_request",
			"name ist ein Pflichtfeld (höchstens 120 Zeichen) — er soll den Zweck erkennen lassen.")
		return
	}
	role := auth.ParseRole(in.Role)
	switch {
	case !role.Valid():
		writeError(w, http.StatusBadRequest, "bad_request", "role muss 'viewer' oder 'editor' sein.")
		return
	case role == auth.RoleAdmin:
		// Es gibt keine Admin-Keys. Verwaltung findet ausschließlich im Browser statt.
		writeError(w, http.StatusBadRequest, "bad_request",
			"Für Keys gibt es die Rolle 'admin' nicht: Keys können weder Keys noch Nutzer verwalten.")
		return
	case role.Rank() > p.Role.Rank():
		writeError(w, http.StatusForbidden, "forbidden",
			"Ein Key kann nicht mehr dürfen als du selbst. Deine Rolle: "+p.Role.Label()+".")
		return
	}

	now := time.Now()
	maxDays := int(s.cfg.APIKeyMaxLifetime.Hours() / 24)
	if in.ExpiresInDays <= 0 {
		in.ExpiresInDays = maxDays
	}
	if in.ExpiresInDays > maxDays {
		writeError(w, http.StatusBadRequest, "bad_request",
			"expiresInDays überschreitet die für diese Instanz erlaubte Höchstdauer.")
		return
	}
	expiresAt := now.AddDate(0, 0, in.ExpiresInDays)

	plaintext, key, err := s.store.CreateAPIKey(r.Context(), s.cfg.AppInstance,
		in.Name, role, p.UserID, expiresAt, now)
	if err != nil {
		s.writeStoreError(w, r, err)
		return
	}
	detail, _ := json.Marshal(map[string]string{"name": in.Name, "role": string(role)})
	s.audit(r, store.AuditEntry{
		Action: store.ActionKeyCreated, TargetType: "api_key", TargetID: key.ID,
		DetailJSON: string(detail),
	})
	key.OwnerName = p.DisplayName
	key.EffectiveRole = auth.MinRole(role, p.Role)

	writeJSON(w, http.StatusCreated, map[string]any{
		"key": toKeyJSON(key, now),
		// Einzige Stelle, an der der Klartext die Anwendung verlässt.
		"plaintext": plaintext,
		"hinweis":   "Dieser Key wird nur jetzt angezeigt. Danach ist er nicht mehr abrufbar.",
	})
}

func (s *Server) handleRevokeKey(w http.ResponseWriter, r *http.Request) {
	p := auth.FromContext(r.Context())
	ownerFilter := p.UserID
	if p.Can(auth.CapAdminUsers) {
		ownerFilter = "" // Admins dürfen jeden Key widerrufen
	}
	reason := strings.TrimSpace(r.URL.Query().Get("reason"))
	if reason == "" {
		reason = "über die Oberfläche widerrufen"
	}
	id := r.PathValue("id")
	if err := s.store.RevokeAPIKey(r.Context(), id, ownerFilter, reason, time.Now()); err != nil {
		s.writeStoreError(w, r, err)
		return
	}
	s.audit(r, store.AuditEntry{
		Action: store.ActionKeyRevoked, TargetType: "api_key", TargetID: id, Reason: reason,
	})
	w.WriteHeader(http.StatusNoContent)
}

// audit hängt einen Protokolleintrag an und füllt den Handelnden aus dem Request.
func (s *Server) audit(r *http.Request, e store.AuditEntry) {
	if p := auth.FromContext(r.Context()); p != nil {
		e.ActorID, e.ActorKind = p.UserID, string(p.Kind)
	}
	if err := s.store.Audit(r.Context(), e); err != nil {
		s.log.Error("Protokolleintrag nicht geschrieben", "aktion", e.Action, "fehler", err)
	}
}
