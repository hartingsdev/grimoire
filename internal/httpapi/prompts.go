package httpapi

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/hartingsdev/solid-bassoon/internal/auth"
	"github.com/hartingsdev/solid-bassoon/internal/config"
	"github.com/hartingsdev/solid-bassoon/internal/store"
)

const (
	maxTitleLength = 300
	maxBodyLength  = 200_000
	maxTags        = 32
)

type userRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type promptJSON struct {
	ID         string    `json:"id"`
	Title      string    `json:"title"`
	Body       string    `json:"body"`
	Tags       []string  `json:"tags"`
	Visibility string    `json:"visibility"`
	Owner      userRef   `json:"owner"`
	Revision   int       `json:"revision"`
	CreatedAt  time.Time `json:"createdAt"`
	UpdatedAt  time.Time `json:"updatedAt"`
	UpdatedBy  userRef   `json:"updatedBy"`
}

func toPromptJSON(p store.Prompt) promptJSON {
	tags := p.Tags
	if tags == nil {
		tags = []string{}
	}
	return promptJSON{
		ID: p.ID, Title: p.Title, Body: p.Body, Tags: tags, Visibility: p.Visibility,
		Owner:     userRef{ID: p.OwnerID, Name: p.OwnerName},
		Revision:  p.Revision,
		CreatedAt: p.CreatedAt, UpdatedAt: p.UpdatedAt,
		UpdatedBy: userRef{ID: p.UpdatedBy, Name: p.UpdatedByName},
	}
}

// scope decides which prompts a principal may see.
//
// An API key carries its owner's user id and so inherits exactly their view,
// with no special rule. Other people's private prompts are visible only to a
// signed-in admin, and only under ADMIN_PRIVATE_ACCESS=full; break-glass goes
// through the deliberate, audited single reveal.
func (s *Server) scope(p *auth.Principal) store.Scope {
	return store.Scope{
		ViewerID: p.UserID,
		SeeAllPrivate: p.Kind == auth.KindSession && p.Role == auth.RoleAdmin &&
			s.cfg.AdminPrivateAccess == config.AdminPrivateFull,
	}
}

func (s *Server) handleListPrompts(w http.ResponseWriter, r *http.Request) {
	p := auth.FromContext(r.Context())
	q := r.URL.Query()

	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))
	opts := store.ListOptions{
		Query:      q.Get("q"),
		Tags:       q["tag"],
		Visibility: q.Get("visibility"),
		Limit:      limit,
		Offset:     offset,
	}
	switch opts.Visibility {
	case "", store.VisibilityShared, store.VisibilityPrivate:
	default:
		writeError(w, http.StatusBadRequest, "bad_request",
			"visibility must be 'shared' or 'private'.")
		return
	}

	// Normalize like the store does, so the response reports the values used.
	if opts.Limit <= 0 || opts.Limit > 200 {
		opts.Limit = 50
	}
	if opts.Offset < 0 {
		opts.Offset = 0
	}

	prompts, err := s.store.ListPrompts(r.Context(), s.scope(p), opts)
	if err != nil {
		s.writeStoreError(w, r, err)
		return
	}
	out := make([]promptJSON, 0, len(prompts))
	for _, item := range prompts {
		out = append(out, toPromptJSON(item))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"prompts": out, "count": len(out), "limit": opts.Limit, "offset": opts.Offset,
	})
}

func (s *Server) handleGetPrompt(w http.ResponseWriter, r *http.Request) {
	p := auth.FromContext(r.Context())
	prompt, err := s.store.GetPrompt(r.Context(), s.scope(p), r.PathValue("id"))
	if err != nil {
		s.writeStoreError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toPromptJSON(prompt))
}

type promptInput struct {
	Title      *string   `json:"title"`
	Body       *string   `json:"body"`
	Tags       *[]string `json:"tags"`
	Visibility *string   `json:"visibility"`
}

func (s *Server) handleCreatePrompt(w http.ResponseWriter, r *http.Request) {
	p := auth.FromContext(r.Context())
	var in promptInput
	if !decodeJSON(w, r, &in) {
		return
	}
	if in.Title == nil || strings.TrimSpace(*in.Title) == "" ||
		in.Body == nil || strings.TrimSpace(*in.Body) == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "title and body are required.")
		return
	}
	visibility := store.VisibilityShared
	if in.Visibility != nil {
		visibility = *in.Visibility
	}
	prompt := store.Prompt{
		Title: strings.TrimSpace(*in.Title), Body: *in.Body, Visibility: visibility,
	}
	if in.Tags != nil {
		prompt.Tags = *in.Tags
	}
	if msg, ok := s.validatePrompt(prompt); !ok {
		writeError(w, http.StatusBadRequest, "bad_request", msg)
		return
	}
	created, err := s.store.CreatePrompt(r.Context(), prompt, p.UserID, time.Now())
	if err != nil {
		s.writeStoreError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, toPromptJSON(created))
}

func (s *Server) handleUpdatePrompt(w http.ResponseWriter, r *http.Request) {
	p := auth.FromContext(r.Context())
	var in promptInput
	if !decodeJSON(w, r, &in) {
		return
	}
	patch := store.Prompt{}
	if in.Title != nil {
		patch.Title = strings.TrimSpace(*in.Title)
		if patch.Title == "" {
			writeError(w, http.StatusBadRequest, "bad_request", "title must not be empty.")
			return
		}
	}
	if in.Body != nil {
		patch.Body = *in.Body
		if strings.TrimSpace(patch.Body) == "" {
			writeError(w, http.StatusBadRequest, "bad_request", "body must not be empty.")
			return
		}
	}
	if in.Visibility != nil {
		patch.Visibility = *in.Visibility
	}
	if in.Tags != nil {
		patch.Tags = *in.Tags
	}
	if msg, ok := s.validatePrompt(patch); !ok {
		writeError(w, http.StatusBadRequest, "bad_request", msg)
		return
	}
	updated, err := s.store.UpdatePrompt(r.Context(), s.scope(p), r.PathValue("id"),
		patch, p.UserID, time.Now())
	if err != nil {
		s.writeStoreError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toPromptJSON(updated))
}

func (s *Server) handleDeletePrompt(w http.ResponseWriter, r *http.Request) {
	p := auth.FromContext(r.Context())
	if err := s.store.DeletePrompt(r.Context(), s.scope(p), r.PathValue("id"),
		p.UserID, time.Now()); err != nil {
		s.writeStoreError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleRestorePrompt(w http.ResponseWriter, r *http.Request) {
	p := auth.FromContext(r.Context())
	var in struct {
		Revision int `json:"revision"`
	}
	if r.ContentLength > 0 && !decodeJSON(w, r, &in) {
		return
	}
	restored, err := s.store.RestorePrompt(r.Context(), s.scope(p), r.PathValue("id"),
		in.Revision, p.UserID, time.Now())
	if err != nil {
		s.writeStoreError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toPromptJSON(restored))
}

func (s *Server) handleListRevisions(w http.ResponseWriter, r *http.Request) {
	p := auth.FromContext(r.Context())
	revisions, err := s.store.ListRevisions(r.Context(), s.scope(p), r.PathValue("id"))
	if err != nil {
		s.writeStoreError(w, r, err)
		return
	}
	out := make([]map[string]any, 0, len(revisions))
	for _, rev := range revisions {
		tags := rev.Tags
		if tags == nil {
			tags = []string{}
		}
		out = append(out, map[string]any{
			"revision": rev.Revision, "title": rev.Title, "body": rev.Body,
			"tags": tags, "visibility": rev.Visibility, "kind": rev.Kind,
			"changedAt": rev.ChangedAt,
			"changedBy": userRef{ID: rev.ChangedBy, Name: rev.ChangedByName},
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"revisions": out})
}

func (s *Server) handleListTags(w http.ResponseWriter, r *http.Request) {
	p := auth.FromContext(r.Context())
	tags, err := s.store.ListTags(r.Context(), s.scope(p))
	if err != nil {
		s.writeStoreError(w, r, err)
		return
	}
	out := make([]map[string]any, 0, len(tags))
	for _, t := range tags {
		out = append(out, map[string]any{"name": t.Name, "count": t.Count})
	}
	writeJSON(w, http.StatusOK, map[string]any{"tags": out})
}

func (s *Server) validatePrompt(p store.Prompt) (string, bool) {
	if len(p.Title) > maxTitleLength {
		return "title is too long (at most " + strconv.Itoa(maxTitleLength) + " characters).", false
	}
	if len(p.Body) > maxBodyLength {
		return "body is too long (at most " + strconv.Itoa(maxBodyLength) + " characters).", false
	}
	if len(p.Tags) > maxTags {
		return "at most " + strconv.Itoa(maxTags) + " tags per prompt.", false
	}
	switch p.Visibility {
	case "", store.VisibilityShared:
	case store.VisibilityPrivate:
		if !s.cfg.PrivatePrompts {
			return "This instance runs with PRIVATE_PROMPTS=off; only shared " +
				"prompts are possible.", false
		}
	default:
		return "visibility must be 'shared' or 'private'.", false
	}
	return "", true
}
