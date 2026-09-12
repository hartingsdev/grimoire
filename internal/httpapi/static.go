package httpapi

import (
	"io/fs"
	"net/http"
	"strings"
)

// handleStatic liefert die Oberfläche aus. Sie wird per go:embed in die Binary
// gebacken; STATIC_DIR überschreibt das für die Entwicklung.
//
// Die Oberfläche erfährt Titel, Rolle und Richtlinien der Instanz über
// /api/v1/me — deshalb braucht es hier keine Templates.
func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/")
	if path == "" {
		path = "index.html"
	}
	// Unbekannte Pfade führen zur Oberfläche zurück, API-Pfade nicht: dort wäre
	// eine HTML-Antwort auf einen JSON-Aufruf irreführend.
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
