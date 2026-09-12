package httpapi

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/hartingsdev/grimoire/internal/auth"
	"github.com/hartingsdev/grimoire/internal/config"
	"github.com/hartingsdev/grimoire/internal/store"
)

// handleMe answers "who am I and what may I do", so the UI only offers what
// would actually pass.
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
			// So the UI can tell the truth at the visibility toggle.
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
			// Marked as a cache on purpose: the truth lives in the IdP.
			"lastSeenRole":   string(u.CachedRole),
			"lastSeenRoleAt": u.CachedRoleAt,
			"lastLoginAt":    u.LastLoginAt,
			"createdAt":      u.CreatedAt,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"users": out,
		"note": "Roles come from the identity provider and are only cached here. " +
			"Access is withdrawn at the IdP, not in this app.",
	})
}

// handleUserFootprint counts what hangs off a user for the confirmation
// dialog. No content is read.
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
		"warning": "Deleting does NOT withdraw access. Remove the person at the identity " +
			"provider first, or their next sign-in creates a fresh, empty account.",
	})
}

// handleDeleteUser removes a user from this instance.
//
// Shared prompts stay and are attributed to the tombstone — that is team
// knowledge. Private prompts are deleted; taking them over instead grants the
// admin read access and is therefore the same deliberate act as a reveal, with
// a mandatory reason in the audit log.
func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	p := auth.FromContext(r.Context())
	id := r.PathValue("id")
	if id == p.UserID {
		writeError(w, http.StatusBadRequest, "self_delete",
			"You cannot delete your own account here.")
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
				"This instance runs with ADMIN_PRIVATE_ACCESS=none; private prompts "+
					"cannot be taken over.")
			return
		}
		if strings.TrimSpace(in.Reason) == "" {
			writeError(w, http.StatusBadRequest, "reason_required",
				"Taking over private prompts requires a reason. It is recorded in the "+
					"audit log and visible to the owner.")
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
		"privatePrompts": map[bool]string{true: "transferred", false: "deleted"}[opts.TransferPrivateTo != ""],
		"privateCount":   fp.PrivatePrompts,
		"sharedCount":    fp.SharedPrompts,
		"keyCount":       fp.ActiveKeys,
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

// handleRevealPrivate opens one other person's private prompt to an admin.
//
// This answers the suspicion case without making "private" an empty promise:
// one deliberate act, a mandatory reason, an immutable audit entry — and the
// owner sees it in their own UI. In no configuration is it silent.
func (s *Server) handleRevealPrivate(w http.ResponseWriter, r *http.Request) {
	p := auth.FromContext(r.Context())
	if s.cfg.AdminPrivateAccess == config.AdminPrivateNone {
		writeError(w, http.StatusForbidden, "private_access_disabled",
			"This instance runs with ADMIN_PRIVATE_ACCESS=none. Other people's "+
				"private prompts are visible to nobody here.")
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
			"A reason is required. It is recorded in the audit log and shown to "+
				"the owner of the prompt.")
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
	// Own and shared prompts are visible anyway; no audit entry needed.
	if prompt.Visibility != store.VisibilityPrivate || prompt.OwnerID == p.UserID {
		writeJSON(w, http.StatusOK, toPromptJSON(prompt))
		return
	}
	detail, _ := json.Marshal(map[string]string{"owner": prompt.OwnerID, "title": prompt.Title})
	s.audit(r, store.AuditEntry{
		Action: store.ActionPrivateRevealed, TargetType: "prompt", TargetID: id,
		Reason: in.Reason, DetailJSON: string(detail),
	})
	s.log.Warn("private prompt revealed",
		"admin", p.UserID, "prompt", id, "owner", prompt.OwnerID, "reason", in.Reason)
	writeJSON(w, http.StatusOK, toPromptJSON(prompt))
}

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
