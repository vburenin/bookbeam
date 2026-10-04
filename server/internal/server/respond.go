package server

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
)

// maxJSONBody bounds API request bodies.
const maxJSONBody = 64 << 10

// writeJSON sends v as JSON with the given status.
func writeJSON(w http.ResponseWriter, status int, v any) {
	h := w.Header()
	h.Set("Content-Type", "application/json; charset=utf-8")
	if h.Get("Cache-Control") == "" {
		h.Set("Cache-Control", "no-store")
	}
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v) // the client went away; nothing useful to do
}

// writeError sends {"error": msg}.
func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

var errEmptyBody = errors.New("empty body")

// decodeJSON reads a bounded JSON body into v. An empty body yields
// errEmptyBody so callers with optional bodies can accept it.
func decodeJSON(w http.ResponseWriter, r *http.Request, v any) error {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxJSONBody))
	if err := dec.Decode(v); err != nil {
		if errors.Is(err, io.EOF) {
			return errEmptyBody
		}
		return err
	}
	return nil
}

// readJSON decodes a required JSON body, answering 400 on failure. It
// reports whether the handler should continue.
func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := decodeJSON(w, r, v); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return false
	}
	return true
}

// etagMatches implements If-None-Match's weak comparison against etag.
func etagMatches(header, etag string) bool {
	if header == "" {
		return false
	}
	want := strings.TrimPrefix(etag, "W/")
	for _, cand := range strings.Split(header, ",") {
		cand = strings.TrimSpace(cand)
		if cand == "*" || strings.TrimPrefix(cand, "W/") == want {
			return true
		}
	}
	return false
}

// redirectRelative sends a 303 with a relative Location (http.Redirect
// would make it absolute, which breaks deployments under a URL prefix).
func redirectRelative(w http.ResponseWriter, location string) {
	w.Header().Set("Location", location)
	w.WriteHeader(http.StatusSeeOther)
}
