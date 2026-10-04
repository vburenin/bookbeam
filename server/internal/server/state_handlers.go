package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/vburenin/bookbeam/server/internal/auth"
	"github.com/vburenin/bookbeam/server/internal/store"
)

// progressEvent is the SSE "progress" payload (Progress nil = forgotten).
type progressEvent struct {
	BookID   string          `json:"bookId"`
	Progress *store.Progress `json:"progress"`
	ClientID string          `json:"clientId"`
	// MovedTo is set (with a nil Progress) when re-linking moved the entry
	// to another book id after a rescan: the place lives on there.
	MovedTo string `json:"movedTo,omitempty"`
}

// bookmarksEvent is the SSE "bookmarks" payload.
type bookmarksEvent struct {
	BookID    string           `json:"bookId"`
	Bookmarks []store.Bookmark `json:"bookmarks"`
}

// storeError maps store errors to HTTP responses.
func (s *Server) storeError(w http.ResponseWriter, err error) {
	var in *store.InputError
	switch {
	case errors.As(err, &in):
		writeError(w, http.StatusBadRequest, in.Msg)
	case store.IsNotFound(err):
		writeError(w, http.StatusNotFound, err.Error())
	default:
		s.log.Error("user data", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
	}
}

// originClient identifies the tab that made a change so the change is not
// echoed back to it over SSE (body field, else ?clientId=).
func originClient(r *http.Request, fromBody string) string {
	if fromBody != "" {
		return fromBody
	}
	return r.URL.Query().Get("clientId")
}

func (s *Server) handleState(w http.ResponseWriter, _ *http.Request, sess auth.Session) {
	st, err := s.store.State(sess.User, s.lib.Index())
	if err != nil {
		s.storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) handleProgressPut(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	var upd store.ProgressUpdate
	if !readJSON(w, r, &upd) {
		return
	}
	bookID := r.PathValue("id")
	res, err := s.store.UpdateProgress(sess.User, s.lib.Index(), bookID, upd)
	if err != nil {
		s.storeError(w, err)
		return
	}
	if res.ClaimedPlayback {
		s.hub.publish(sess.User, upd.ClientID, "playing", map[string]string{
			"clientId": upd.ClientID, "bookId": bookID, "deviceName": sess.Name,
		})
	}
	s.hub.publish(sess.User, upd.ClientID, "progress", progressEvent{BookID: bookID, Progress: &res.Progress, ClientID: upd.ClientID})
	writeJSON(w, http.StatusOK, map[string]any{"progress": res.Progress, "activeClient": res.ActiveClient})
}

func (s *Server) handleProgressPatch(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	var body struct {
		Finished *bool  `json:"finished"`
		ClientID string `json:"clientId"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	if body.Finished == nil {
		writeError(w, http.StatusBadRequest, "finished is required")
		return
	}
	bookID := r.PathValue("id")
	p, err := s.store.SetFinished(sess.User, s.lib.Index(), bookID, *body.Finished)
	if err != nil {
		s.storeError(w, err)
		return
	}
	client := originClient(r, body.ClientID)
	s.hub.publish(sess.User, client, "progress", progressEvent{BookID: bookID, Progress: &p, ClientID: client})
	writeJSON(w, http.StatusOK, map[string]any{"progress": p})
}

func (s *Server) handleProgressDelete(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	bookID := r.PathValue("id")
	if err := s.store.DeleteProgress(sess.User, s.lib.Index(), bookID); err != nil {
		s.storeError(w, err)
		return
	}
	client := originClient(r, "")
	s.hub.publish(sess.User, client, "progress", progressEvent{BookID: bookID, ClientID: client})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleBookmarkAdd(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	var body struct {
		store.NewBookmark
		ClientID string `json:"clientId"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	bookID := r.PathValue("id")
	bm, all, err := s.store.AddBookmark(sess.User, s.lib.Index(), bookID, body.NewBookmark)
	if err != nil {
		s.storeError(w, err)
		return
	}
	s.hub.publish(sess.User, originClient(r, body.ClientID), "bookmarks", bookmarksEvent{BookID: bookID, Bookmarks: all})
	writeJSON(w, http.StatusCreated, bm)
}

func (s *Server) handleBookmarkUpdate(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	var body struct {
		Note     *string `json:"note"`
		ClientID string  `json:"clientId"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	if body.Note == nil {
		writeError(w, http.StatusBadRequest, "note is required")
		return
	}
	bookID := r.PathValue("id")
	bm, all, err := s.store.UpdateBookmark(sess.User, s.lib.Index(), bookID, r.PathValue("bmId"), *body.Note)
	if err != nil {
		s.storeError(w, err)
		return
	}
	s.hub.publish(sess.User, originClient(r, body.ClientID), "bookmarks", bookmarksEvent{BookID: bookID, Bookmarks: all})
	writeJSON(w, http.StatusOK, bm)
}

func (s *Server) handleBookmarkDelete(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	bookID := r.PathValue("id")
	all, err := s.store.DeleteBookmark(sess.User, s.lib.Index(), bookID, r.PathValue("bmId"))
	if err != nil {
		s.storeError(w, err)
		return
	}
	s.hub.publish(sess.User, originClient(r, ""), "bookmarks", bookmarksEvent{BookID: bookID, Bookmarks: all})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	var patch map[string]json.RawMessage
	if !readJSON(w, r, &patch) {
		return
	}
	st, err := s.store.PatchSettings(sess.User, s.lib.Index(), patch)
	if err != nil {
		s.storeError(w, err)
		return
	}
	s.hub.publish(sess.User, originClient(r, ""), "settings", st)
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	tz := 0
	if v := r.URL.Query().Get("tzOffset"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			writeError(w, http.StatusBadRequest, "tzOffset must be an integer (minutes)")
			return
		}
		tz = n
	}
	st, err := s.store.Stats(sess.User, s.lib.Index(), tz)
	if err != nil {
		s.storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}
