package httpapi

import (
	"io/fs"
	"net/http"
	"strings"
)

// handleStatic serves the UI, embedded in the binary and overridable via
// STATIC_DIR while developing. The UI learns title, role and instance policy
// from /api/v1/me, so no templating is needed here.
func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/")
	if path == "" {
		path = "index.html"
	}
	// Unknown paths fall back to the UI, API paths do not: answering a JSON
	// call with HTML would be misleading.
	if _, err := fs.Stat(s.static, path); err != nil {
		if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/auth/") {
			writeError(w, http.StatusNotFound, "not_found", "Unbekannter Endpunkt.")
			return
		}
		path = "index.html"
	}
	w.Header().Set("Cache-Control", "no-cache")
	http.ServeFileFS(w, r, s.static, path)
}
