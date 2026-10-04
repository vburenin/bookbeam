package server

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vburenin/bookbeam/server/internal/store"
)

func TestProgressAPI(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	c := h.client().login("vlad", "test")
	lev := h.book("Expanse/Leviathan Wakes")
	base := "/api/progress/" + lev.ID

	r := c.do("PUT", base, map[string]any{
		"trackIndex": 1, "position": 12.5, "bookPosition": 112.5, "speed": 1.25, "playing": true,
		"clientId": "tab-1", "listened": 500, "tzOffset": -120, "event": "play",
	})
	expectStatus(t, r, 200)
	var res struct {
		Progress     store.Progress `json:"progress"`
		ActiveClient string         `json:"activeClient"`
	}
	r.json(t, &res)
	p := res.Progress
	if res.ActiveClient != "tab-1" || p.BookPosition != 112.5 || p.Listened != 120 || p.Speed != 1.25 ||
		p.TrackPath != lev.Tracks[1].Path || p.Path != lev.Path || p.Duration != 600 || p.UpdatedAt == 0 {
		t.Fatalf("PUT result = %+v", res)
	}

	// Validation.
	expectStatus(t, c.do("PUT", "/api/progress/b_000000000000", map[string]any{}), 404)
	expectStatus(t, c.do("PUT", base, map[string]any{"trackIndex": 9}), 400)
	expectStatus(t, c.do("PUT", base, map[string]any{"event": "bogus"}), 400)
	expectStatus(t, c.request("PUT", base, strings.NewReader("{"), "application/json"), 400)

	r = c.do("PATCH", base, map[string]any{"finished": true})
	expectStatus(t, r, 200)
	var pr struct {
		Progress store.Progress `json:"progress"`
	}
	r.json(t, &pr)
	if !pr.Progress.Finished || pr.Progress.Position != 12.5 {
		t.Fatalf("PATCH finished = %+v", pr.Progress)
	}
	expectStatus(t, c.do("PATCH", base, map[string]any{}), 400)

	var st struct {
		Settings   store.Settings              `json:"settings"`
		Progress   map[string]store.Progress   `json:"progress"`
		Bookmarks  map[string][]store.Bookmark `json:"bookmarks"`
		ServerTime int64                       `json:"serverTime"`
	}
	c.do("GET", "/api/state", nil).json(t, &st)
	if !st.Progress[lev.ID].Finished || st.ServerTime == 0 || st.Settings != store.DefaultSettings() || st.Bookmarks == nil {
		t.Fatalf("state = %+v", st)
	}

	var stats store.StatsView
	c.do("GET", "/api/stats?tzOffset=-120", nil).json(t, &stats)
	if stats.Today != 120 || stats.BooksFinished != 1 || len(stats.Week) != 7 || stats.Streak != 1 {
		t.Fatalf("stats = %+v", stats)
	}
	expectStatus(t, c.do("GET", "/api/stats?tzOffset=abc", nil), 400)

	expectStatus(t, c.do("DELETE", base, nil), 200)
	st.Progress = nil
	c.do("GET", "/api/state", nil).json(t, &st)
	if _, ok := st.Progress[lev.ID]; ok {
		t.Fatal("progress not deleted")
	}
	// Other users have their own state.
	var kid struct {
		Progress map[string]store.Progress `json:"progress"`
	}
	h.client().login("kid", "test2").do("GET", "/api/state", nil).json(t, &kid)
	if len(kid.Progress) != 0 {
		t.Fatalf("kid sees %v", kid.Progress)
	}
}

func TestBookmarksAPI(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	c := h.client().login("vlad", "test")
	lev := h.book("Expanse/Leviathan Wakes")
	base := "/api/books/" + lev.ID + "/bookmarks"

	r := c.do("POST", base, map[string]any{"trackIndex": 2, "position": 30, "note": "great line"})
	expectStatus(t, r, http.StatusCreated)
	var bm store.Bookmark
	r.json(t, &bm)
	if bm.ID == "" || bm.BookPosition != 330 || bm.Note != "great line" || bm.CreatedAt == 0 {
		t.Fatalf("bookmark = %+v", bm)
	}
	expectStatus(t, c.do("POST", base, map[string]any{"trackIndex": 7}), 400)
	expectStatus(t, c.do("POST", "/api/books/b_000000000000/bookmarks", map[string]any{}), 404)

	r = c.do("PATCH", base+"/"+bm.ID, map[string]any{"note": "edited"})
	expectStatus(t, r, 200)
	r.json(t, &bm)
	if bm.Note != "edited" {
		t.Fatalf("patched = %+v", bm)
	}
	expectStatus(t, c.do("PATCH", base+"/"+bm.ID, map[string]any{}), 400)
	expectStatus(t, c.do("PATCH", base+"/kmissing", map[string]any{"note": ""}), 404)
	expectStatus(t, h.client().login("kid", "test2").do("DELETE", base+"/"+bm.ID, nil), 404)

	expectStatus(t, c.do("DELETE", base+"/"+bm.ID, nil), 200)
	expectStatus(t, c.do("DELETE", base+"/"+bm.ID, nil), 404)
}

func TestSettingsAPI(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	c := h.client().login("vlad", "test")
	r := c.do("PATCH", "/api/settings", map[string]any{"skipBack": 30, "theme": "auto"})
	expectStatus(t, r, 200)
	var st store.Settings
	r.json(t, &st)
	if st.SkipBack != 30 || st.Theme != "auto" || st.SkipForward != 30 {
		t.Fatalf("settings = %+v", st)
	}
	for _, bad := range []map[string]any{{"skipBack": 7}, {"theme": 1}, {"defaultSpeed": 9}, {"unknown": true}} {
		r := c.do("PATCH", "/api/settings", bad)
		if r.StatusCode != 400 || !strings.Contains(string(r.body), `"error"`) {
			t.Errorf("%v: %d %s", bad, r.StatusCode, r.body)
		}
	}
}

func TestLegacyStateMigratedThroughAPI(t *testing.T) {
	h := newHarness(t, harnessOpts{setup: func(root string) {
		defaultLibrary(t, root)
		writeTestFile(t, root, "state/vlad.json", []byte(`{
			"currentUrl": "Expanse/Leviathan Wakes/02 - The Storm.mp3",
			"currentTime": 42.5, "playbackRate": 1.5,
			"listened": ["/media/Expanse/Leviathan%20Wakes/01%20-%20Prologue.mp3", "/media/Single/Hail%20Mary.m4b"]
		}`))
	}})
	mtime := time.Date(2025, 8, 1, 10, 0, 0, 0, time.UTC)
	if err := os.Chtimes(filepath.Join(h.root, "state/vlad.json"), mtime, mtime); err != nil {
		t.Fatal(err)
	}
	c := h.client().login("vlad", "test")
	var st struct {
		Settings store.Settings            `json:"settings"`
		Progress map[string]store.Progress `json:"progress"`
	}
	c.do("GET", "/api/state", nil).json(t, &st)
	lev := h.book("Expanse/Leviathan Wakes")
	hail := h.book("Single/Hail Mary.m4b")
	if p := st.Progress[lev.ID]; p.TrackIndex != 1 || p.Position != 42.5 || p.BookPosition != 142.5 || p.UpdatedAt != mtime.UnixMilli() {
		t.Fatalf("current book = %+v", p)
	}
	if !st.Progress[hail.ID].Finished || st.Settings.DefaultSpeed != 1.5 {
		t.Fatalf("state = %+v", st)
	}
	raw, err := os.ReadFile(filepath.Join(h.state, "users", "vlad.json"))
	if err != nil {
		t.Fatal(err)
	}
	var saved map[string]json.RawMessage
	if err := json.Unmarshal(raw, &saved); err != nil || string(saved["version"]) != "2" {
		t.Fatalf("users/vlad.json = %s", raw)
	}
	if _, pending := saved["legacyPending"]; pending {
		t.Fatal("migration still pending")
	}
}
