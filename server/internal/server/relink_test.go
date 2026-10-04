package server

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/vburenin/bookbeam/server/internal/store"
)

// Renaming a book folder carries everyone's place along, and connected
// devices are told right after the scan.
func TestFolderRenameKeepsPlace(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	phone := h.client().login("vlad", "test")
	lev := h.book("Expanse/Leviathan Wakes")
	expectStatus(t, phone.do("PUT", "/api/progress/"+lev.ID, map[string]any{
		"trackIndex": 1, "trackPath": lev.Tracks[1].Path, "position": 42, "clientId": "phone", "event": "pause"}), 200)
	expectStatus(t, phone.do("POST", "/api/books/"+lev.ID+"/bookmarks", map[string]any{"trackIndex": 2, "position": 5}), 201)
	car := h.client().login("vlad", "test")
	events := car.openEvents("car")

	if err := os.Rename(filepath.Join(h.root, "Expanse"), filepath.Join(h.root, "James S. A. Corey")); err != nil {
		t.Fatal(err)
	}
	h.rescan()
	moved := h.book("James S. A. Corey/Leviathan Wakes")

	got := map[string]string{}
	for range 4 { // progress gone + moved, bookmarks moved + emptied
		ev := events.next(t)
		var body struct {
			BookID    string            `json:"bookId"`
			Progress  *store.Progress   `json:"progress"`
			MovedTo   string            `json:"movedTo"`
			Bookmarks *[]store.Bookmark `json:"bookmarks"`
		}
		if err := json.Unmarshal([]byte(ev.data), &body); err != nil {
			t.Fatal(err)
		}
		switch {
		case ev.name == "progress" && body.Progress == nil:
			got[ev.name+":"+body.BookID] = "gone to " + body.MovedTo
		case ev.name == "progress":
			got[ev.name+":"+body.BookID] = body.Progress.TrackPath
		case ev.name == "bookmarks" && body.Bookmarks != nil:
			got[ev.name+":"+body.BookID] = string(rune('0' + len(*body.Bookmarks)))
		}
	}
	want := map[string]string{
		"progress:" + lev.ID:    "gone to " + moved.ID,
		"progress:" + moved.ID:  moved.Tracks[1].Path,
		"bookmarks:" + lev.ID:   "0",
		"bookmarks:" + moved.ID: "1",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("event %s = %q, want %q (all: %v)", k, got[k], v, got)
		}
	}

	var st store.StateView
	phone.do("GET", "/api/state", nil).json(t, &st)
	if p, ok := st.Progress[moved.ID]; !ok || p.Position != 42 || p.TrackIndex != 1 || len(st.Progress) != 1 {
		t.Fatalf("state after rename = %+v", st.Progress)
	}
}
