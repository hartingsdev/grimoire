package httpapi

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/hartingsdev/solid-bassoon/internal/auth"
	"github.com/hartingsdev/solid-bassoon/internal/config"
	"github.com/hartingsdev/solid-bassoon/internal/store"
)

// handleMe beantwortet "wer bin ich und was darf ich" — die Grundlage dafür,
// dass die Oberfläche nur anbietet, was auch durchgeht.
func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	p := auth.FromContext(r.Context())
	caps := make([]string, 0, 6)
	for _, c := range p.CapabilityList() {
		caps = append(caps, string(c))
	}
	body := map[string]any{
		"user": map[string]any{
			"id": p.UserID, "name": p.DisplayName, "email": p.Email, "subject": p.Subject,
		},
		"principal":    string(p.Kind),
		"role":         string(p.Role),
		"roleLabel":    p.Role.Label(),
		"capabilities": caps,
		"instance": map[string]any{
			"title":              s.cfg.AppTitle,
			"name":               s.cfg.AppInstance,
			"privatePrompts":     s.cfg.PrivatePrompts,
			"adminPrivateAccess": string(s.cfg.AdminPrivateAccess),
			// Damit die Oberfläche am Sichtbarkeits-Schalter die Wahrheit sagt.
			"privateVisibleToAdmins": s.cfg.AdminPrivateAccess == config.AdminPrivateFull,
		},
	}
	if p.Kind == auth.KindAPIKey {
		body["key"] = map[string]any{"id": p.KeyID, "role": string(p.KeyRole)}
	}
	if p.CSRFToken != "" {
		body["csrfToken"] = p.CSRFToken
	}
	writeJSON(w, http.StatusOK, body)
}

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.store.ListUsers(r.Context())
	if err != nil {
		s.writeStoreError(w, r, err)
		return
	}
	out := make([]map[string]any, 0, len(users))
	for _, u := range users {
		out = append(out, map[string]any{
			"id": u.ID, "name": u.Name(), "email": u.Email, "subject": u.Sub,
			// Ausdrücklich als Cache gekennzeichnet: die Wahrheit steht im IdP.
			"lastSeenRole":   string(u.CachedRole),
			"lastSeenRoleAt": u.CachedRoleAt,
			"lastLoginAt":    u.LastLoginAt,
			"createdAt":      u.CreatedAt,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"users": out,
		"hinweis": "Rollen stammen aus dem Anmeldedienst und werden hier nur " +
			"zwischengespeichert. Zugang entziehen geschieht im IdP, nicht hier.",
	})
}

// handleUserFootprint zählt, was an einem Nutzer hängt — die Grundlage für den
// Bestätigungsdialog. Inhalte werden dabei nicht gelesen.
func (s *Server) handleUserFootprint(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	user, err := s.store.GetUser(r.Context(), id)
	if err != nil {
		s.writeStoreError(w, r, err)
		return
	}
	fp, err := s.store.UserFootprint(r.Context(), id)
	if err != nil {
		s.writeStoreError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"user": map[string]any{"id": user.ID, "name": user.Name(), "email": user.Email},
		"footprint": map[string]int{
			"sharedPrompts": fp.SharedPrompts, "privatePrompts": fp.PrivatePrompts,
			"activeKeys": fp.ActiveKeys, "sessions": fp.Sessions,
		},
		"transferAllowed": s.cfg.AdminPrivateAccess != config.AdminPrivateNone,
		"warnung": "Das Löschen entzieht NICHT den Zugang. Entferne die Person zuerst " +
			"im Anmeldedienst, sonst legt der nächste Login ein neues, leeres Konto an.",
	})
}

// handleDeleteUser entfernt einen Nutzer aus dieser Instanz.
//
// Geteilte Prompts bleiben erhalten und werden dem Grabstein zugeschrieben —
// das ist Teamwissen. Private Prompts werden gelöscht; sie stattdessen zu
// übernehmen verschafft dem Admin Lesezugriff und ist deshalb dieselbe
// Einzelfallentscheidung wie das Freischalten, mit Pflichtbegründung im Protokoll.
func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	p := auth.FromContext(r.Context())
	id := r.PathValue("id")
	if id == p.UserID {
		writeError(w, http.StatusBadRequest, "self_delete",
			"Du kannst dein eigenes Konto hier nicht löschen.")
		return
	}
	var in struct {
		PrivatePrompts string `json:"privatePrompts"` // "delete" (Vorgabe) oder "transfer"
		Reason         string `json:"reason"`
	}
	if r.ContentLength > 0 && !decodeJSON(w, r, &in) {
		return
	}

	opts := store.DeleteUserOptions{}
	if in.PrivatePrompts == "transfer" {
		if s.cfg.AdminPrivateAccess == config.AdminPrivateNone {
			writeError(w, http.StatusForbidden, "private_access_disabled",
				"Diese Instanz steht auf ADMIN_PRIVATE_ACCESS=none; private Einträge "+
					"können nicht übernommen werden.")
			return
		}
		if strings.TrimSpace(in.Reason) == "" {
			writeError(w, http.StatusBadRequest, "reason_required",
				"Für die Übernahme privater Einträge ist eine Begründung erforderlich. "+
					"Sie wird protokolliert und ist für alle Administratoren sichtbar.")
			return
		}
		opts.TransferPrivateTo = p.UserID
	}

	now := time.Now()
	fp, _ := s.store.UserFootprint(r.Context(), id)
	if err := s.store.DeleteUser(r.Context(), id, opts, now); err != nil {
		s.writeStoreError(w, r, err)
		return
	}
	detail, _ := json.Marshal(map[string]any{
		"privatePrompts": map[bool]string{true: "übernommen", false: "gelöscht"}[opts.TransferPrivateTo != ""],
		"anzahlPrivat":   fp.PrivatePrompts,
		"anzahlGeteilt":  fp.SharedPrompts,
		"anzahlKeys":     fp.ActiveKeys,
	})
	s.audit(r, store.AuditEntry{
		Action: store.ActionUserDeleted, TargetType: "user", TargetID: id,
		Reason: in.Reason, DetailJSON: string(detail),
	})
	if opts.TransferPrivateTo != "" {
		s.audit(r, store.AuditEntry{
			Action: store.ActionPrivateTransfer, TargetType: "user", TargetID: id,
			Reason: in.Reason,
		})
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleRevealPrivate schaltet einen einzelnen fremden privaten Eintrag für
// einen Administrator frei.
//
// Das ist die Antwort auf den Verdachtsfall, ohne "privat" zu einer leeren
// Zusage zu machen: es ist ein ausdrücklicher Einzelakt, er verlangt eine
// Begründung, er landet unveränderlich im Protokoll — und der Besitzer sieht
// ihn in seiner eigenen Oberfläche. Heimlich geht es in keiner Einstellung.
func (s *Server) handleRevealPrivate(w http.ResponseWriter, r *http.Request) {
	p := auth.FromContext(r.Context())
	if s.cfg.AdminPrivateAccess == config.AdminPrivateNone {
		writeError(w, http.StatusForbidden, "private_access_disabled",
			"Diese Instanz steht auf ADMIN_PRIVATE_ACCESS=none. Private Einträge "+
				"anderer sind hier für niemanden einsehbar.")
		return
	}
	var in struct {
		Reason string `json:"reason"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if strings.TrimSpace(in.Reason) == "" {
		writeError(w, http.StatusBadRequest, "reason_required",
			"Eine Begründung ist erforderlich. Sie wird protokolliert und ist für "+
				"den Besitzer des Eintrags sichtbar.")
		return
	}

	id := r.PathValue("id")
	prompt, err := s.store.GetPrompt(r.Context(), store.Scope{
		ViewerID: p.UserID, SeeAllPrivate: true,
	}, id)
	if err != nil {
		s.writeStoreError(w, r, err)
		return
	}
	// Eigene und geteilte Einträge sind ohnehin sichtbar; dafür braucht es
	// keinen Protokolleintrag.
	if prompt.Visibility != store.VisibilityPrivate || prompt.OwnerID == p.UserID {
		writeJSON(w, http.StatusOK, toPromptJSON(prompt))
		return
	}
	detail, _ := json.Marshal(map[string]string{"owner": prompt.OwnerID, "title": prompt.Title})
	s.audit(r, store.AuditEntry{
		Action: store.ActionPrivateRevealed, TargetType: "prompt", TargetID: id,
		Reason: in.Reason, DetailJSON: string(detail),
	})
	s.log.Warn("privater Eintrag freigeschaltet",
		"admin", p.UserID, "eintrag", id, "besitzer", prompt.OwnerID, "begruendung", in.Reason)
	writeJSON(w, http.StatusOK, toPromptJSON(prompt))
}

// handleMyAudit zeigt, was mit den eigenen Inhalten geschehen ist.
func (s *Server) handleMyAudit(w http.ResponseWriter, r *http.Request) {
	p := auth.FromContext(r.Context())
	entries, err := s.store.ListAudit(r.Context(), p.UserID, 50, 0)
	if err != nil {
		s.writeStoreError(w, r, err)
		return
	}
	out := make([]map[string]any, 0, len(entries))
	for _, e := range entries {
		out = append(out, map[string]any{
			"at": e.At, "actor": userRef{ID: e.ActorID, Name: e.ActorName},
			"action": e.Action, "targetId": e.TargetID, "reason": e.Reason,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": out})
}

func (s *Server) handleListAudit(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	entries, err := s.store.ListAudit(r.Context(), "", limit, offset)
	if err != nil {
		s.writeStoreError(w, r, err)
		return
	}
	out := make([]map[string]any, 0, len(entries))
	for _, e := range entries {
		out = append(out, map[string]any{
			"at": e.At, "actor": userRef{ID: e.ActorID, Name: e.ActorName},
			"actorKind": e.ActorKind, "action": e.Action,
			"targetType": e.TargetType, "targetId": e.TargetID,
			"reason": e.Reason, "detail": json.RawMessage(e.DetailJSON),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": out})
}
