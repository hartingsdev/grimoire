package httpapi

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/hartingsdev/solid-bassoon/internal/store"
)

// apiError ist die einheitliche Fehlerform der API. Skripte können sich auf
// code verlassen, message ist für Menschen.
type apiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type errorBody struct {
	Error apiError `json:"error"`
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if body == nil {
		return
	}
	if err := json.NewEncoder(w).Encode(body); err != nil {
		slog.Default().Error("Antwort konnte nicht geschrieben werden", "fehler", err)
	}
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, errorBody{apiError{Code: code, Message: message}})
}

// writeStoreError übersetzt Fehler der Datenbankschicht. ErrNotFound wird auch
// dann gemeldet, wenn ein Eintrag zwar existiert, aber für den Aufrufer nicht
// sichtbar ist — sonst verriete die Antwort die Existenz fremder privater Einträge.
func (s *Server) writeStoreError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "Nicht gefunden.")
	default:
		s.log.Error("Anfrage fehlgeschlagen",
			"pfad", r.URL.Path, "methode", r.Method, "fehler", err)
		writeError(w, http.StatusInternalServerError, "internal",
			"Unerwarteter Fehler. Details stehen im Server-Log.")
	}
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	defer r.Body.Close()
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request",
			"Anfrage konnte nicht gelesen werden: "+err.Error())
		return false
	}
	return true
}
