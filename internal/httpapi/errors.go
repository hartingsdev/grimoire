package httpapi

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/hartingsdev/solid-bassoon/internal/store"
)

// apiError is the API's single error shape: scripts rely on code, message is
// for people.
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
		slog.Default().Error("could not write response", "error", err)
	}
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, errorBody{apiError{Code: code, Message: message}})
}

// writeStoreError translates store errors. ErrNotFound also covers a prompt
// that exists but is invisible to the caller, so the response cannot confirm
// the existence of other people's private entries.
func (s *Server) writeStoreError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "Not found.")
	default:
		s.log.Error("request failed",
			"path", r.URL.Path, "method", r.Method, "error", err)
		writeError(w, http.StatusInternalServerError, "internal",
			"Unexpected error. Details are in the server log.")
	}
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	defer r.Body.Close()
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request",
			"Could not read the request: "+err.Error())
		return false
	}
	return true
}
