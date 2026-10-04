package server

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLibraryAPI(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	c := h.client().login("vlad", "test")

	r := c.do("GET", "/api/library", nil)
	expectStatus(t, r, 200)
	var lib struct {
		Version   string           `json:"version"`
		ScannedAt int64            `json:"scannedAt"`
		Scanning  bool             `json:"scanning"`
		Books     []map[string]any `json:"books"`
	}
	r.json(t, &lib)
	if lib.Version == "" || lib.ScannedAt == 0 || lib.Scanning || len(lib.Books) != 3 {
		t.Fatalf("library = %+v", lib)
	}
	etag := r.Header.Get("ETag")
	if !strings.HasPrefix(etag, `"`+lib.Version+".") || strings.Contains(etag, "scanning") {
		t.Fatalf("ETag = %q", etag)
	}
	lev := h.book("Expanse/Leviathan Wakes")
	var summary map[string]any
	for _, b := range lib.Books {
		if b["id"] == lev.ID {
			summary = b
		}
	}
	want := map[string]any{
		"path": "Expanse/Leviathan Wakes", "folder": "Expanse", "title": "Leviathan Wakes",
		"author": "James S. A. Corey", "narrator": "Jefferson Mays", "duration": 600.0,
		"trackCount": 3.0, "chapterCount": 3.0, "cover": "api/books/" + lev.ID + "/cover?v=" + lev.Cover.Version,
	}
	for k, v := range want {
		if summary[k] != v {
			t.Errorf("summary[%s] = %v, want %v", k, summary[k], v)
		}
	}
	for _, k := range []string{"addedAt", "size"} {
		if _, ok := summary[k]; !ok {
			t.Errorf("summary lacks %s", k)
		}
	}
	for _, b := range lib.Books {
		if _, ok := b["cover"]; !ok {
			t.Errorf("book %v lacks cover field", b["id"])
		}
	}

	// Clients echo the ETag they received.
	c.headers["If-None-Match"] = etag
	expectStatus(t, c.do("GET", "/api/library", nil), http.StatusNotModified)
	delete(c.headers, "If-None-Match")

	r = c.do("GET", "/api/books/"+lev.ID, nil)
	expectStatus(t, r, 200)
	var d bookDetail
	r.json(t, &d)
	if len(d.Tracks) != 3 || d.Tracks[1].Title != "The Storm" || d.Tracks[1].Start != 100 ||
		d.Tracks[1].URL != "api/books/"+lev.ID+"/tracks/1/audio?v="+lev.Tracks[1].Fingerprint || d.Tracks[1].Format != "mp3" || d.Tracks[2].Index != 2 {
		t.Fatalf("tracks = %+v", d.Tracks)
	}
	if len(d.Chapters) != 3 || d.Chapters[2].BookStart != 300 || d.Chapters[2].End != 300 || d.Chapters[2].Index != 2 {
		t.Fatalf("chapters = %+v", d.Chapters)
	}

	martian := h.book("Single/Martian.m4b")
	var md bookDetail
	c.do("GET", "/api/books/"+martian.ID, nil).json(t, &md)
	if md.Title != "The Martian" || md.Folder != "Single" || len(md.Chapters) != 2 || md.Chapters[1].Title != "Sol 7" || md.Chapters[1].Start != 300 {
		t.Fatalf("single-file detail = %+v", md)
	}
	expectStatus(t, c.do("GET", "/api/books/b_000000000000", nil), 404)
}

func TestCovers(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	c := h.client().login("vlad", "test")
	lev := h.book("Expanse/Leviathan Wakes")
	r := c.do("GET", "/api/books/"+lev.ID+"/cover?v="+lev.Cover.Version, nil)
	expectStatus(t, r, 200)
	if string(r.body) != testJPEG || r.Header.Get("Content-Type") != "image/jpeg" ||
		r.Header.Get("Cache-Control") != "private, max-age=31536000, immutable" {
		t.Fatalf("file cover: %v %q", r.Header, r.body)
	}
	martian := h.book("Single/Martian.m4b")
	r = c.do("GET", "/api/books/"+martian.ID+"/cover", nil)
	expectStatus(t, r, 200)
	if string(r.body) != testPNG || r.Header.Get("Content-Type") != "image/png" {
		t.Fatalf("embedded cover: %v %q", r.Header, r.body)
	}
	hail := h.book("Single/Hail Mary.m4b")
	expectStatus(t, c.do("GET", "/api/books/"+hail.ID+"/cover", nil), 404)

	// A cover deleted since the scan is a 404 that must not be cached.
	if err := os.Remove(filepath.Join(h.root, "Expanse/Leviathan Wakes/cover.jpg")); err != nil {
		t.Fatal(err)
	}
	r = c.do("GET", "/api/books/"+lev.ID+"/cover", nil)
	expectStatus(t, r, 404)
	if cc := r.Header.Get("Cache-Control"); strings.Contains(cc, "immutable") {
		t.Fatalf("404 cached: %q", cc)
	}
}

func TestAudioStreaming(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	c := h.client().login("vlad", "test")
	lev := h.book("Expanse/Leviathan Wakes")
	want, err := os.ReadFile(filepath.Join(h.root, filepath.FromSlash(lev.Tracks[1].Path)))
	if err != nil {
		t.Fatal(err)
	}
	url := "/api/books/" + lev.ID + "/tracks/1/audio?v=" + lev.Tracks[1].Fingerprint

	c.headers["Accept-Encoding"] = "gzip"
	r := c.do("GET", url, nil)
	expectStatus(t, r, 200)
	if string(r.body) != string(want) || r.Header.Get("Content-Type") != "audio/mpeg" ||
		r.Header.Get("Cache-Control") != "private, max-age=31536000, immutable" || r.Header.Get("Accept-Ranges") != "bytes" ||
		r.Header.Get("Content-Encoding") != "" || r.Header.Get("ETag") == "" {
		t.Fatalf("audio: %v", r.Header)
	}

	c.headers["Range"] = "bytes=2-9"
	r = c.do("GET", url, nil)
	expectStatus(t, r, http.StatusPartialContent)
	if string(r.body) != string(want[2:10]) || !strings.HasPrefix(r.Header.Get("Content-Range"), "bytes 2-9/") {
		t.Fatalf("range: %v %q", r.Header, r.body)
	}
	delete(c.headers, "Range")
	r = c.do("HEAD", url, nil)
	if r.StatusCode != 200 || len(r.body) != 0 || r.ContentLength != int64(len(want)) {
		t.Fatalf("HEAD: %d %d", r.StatusCode, r.ContentLength)
	}

	martian := h.book("Single/Martian.m4b")
	r = c.do("GET", "/api/books/"+martian.ID+"/tracks/0/audio", nil)
	if r.StatusCode != 200 || r.Header.Get("Content-Type") != "audio/mp4" {
		t.Fatalf("m4b: %d %v", r.StatusCode, r.Header)
	}

	// Only indexed files are reachable.
	for _, p := range []string{
		"/api/books/" + lev.ID + "/tracks/3/audio",
		"/api/books/" + lev.ID + "/tracks/-1/audio",
		"/api/books/" + lev.ID + "/tracks/x/audio",
		"/api/books/b_000000000000/tracks/0/audio",
		"/api/books/" + lev.ID + "/tracks/0/audio/../../../../session_secret",
		"/media/session_secret",
		"/session_secret",
		"/Expanse/Leviathan%20Wakes/01%20-%20Prologue.mp3",
		"/.bookbeam/secret.key",
	} {
		r := c.do("GET", p, nil)
		if r.StatusCode == 200 || strings.Contains(string(r.body), "\x07\x07\x07") {
			t.Errorf("%s served: %d", p, r.StatusCode)
		}
	}
	expectStatus(t, h.client().do("GET", url, nil), 401)
}

func TestRescanEndpoint(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	c := h.client().login("vlad", "test")
	events := c.openEvents("tab")
	r := c.do("POST", "/api/library/rescan", nil)
	expectStatus(t, r, http.StatusAccepted)
	if strings.TrimSpace(string(r.body)) != `{"scanning":true}` {
		t.Fatalf("rescan = %s", r.body)
	}
	if ev := events.next(t); ev.name != "library" || !strings.Contains(ev.data, `"scanning":true`) {
		t.Fatalf("event = %+v", ev)
	}
	// While a rescan is queued the ETag differs, so a client that cached
	// the in-progress listing refetches once it is done.
	var lib struct {
		Version  string `json:"version"`
		Scanning bool   `json:"scanning"`
	}
	r = c.do("GET", "/api/library", nil)
	r.json(t, &lib)
	scanningTag := r.Header.Get("ETag")
	if !lib.Scanning || !strings.HasSuffix(scanningTag, `.scanning"`) || !strings.HasPrefix(scanningTag, `"`+lib.Version+".") {
		t.Fatalf("scanning listing: %+v %q", lib, scanningTag)
	}
}

// A rescan of a library folder that suddenly holds no audio (the share is
// not mounted) keeps the books and says so; only a forced rescan publishes
// an empty library.
func TestRescanOfEmptyLibrary(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	c := h.client().login("vlad", "test")
	events := c.openEvents("tab")
	for _, dir := range []string{"Expanse", "Single"} {
		if err := os.RemoveAll(filepath.Join(h.root, dir)); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		h.lib.Run(ctx, 0)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	before := h.lib.Index().Version

	// next returns the next library event once its scan is over.
	next := func() libraryEvent {
		t.Helper()
		for {
			ev := events.next(t)
			var e libraryEvent
			if err := json.Unmarshal([]byte(ev.data), &e); err != nil || ev.name != "library" {
				t.Fatalf("event = %+v", ev)
			}
			if !e.Scanning {
				return e
			}
		}
	}

	expectStatus(t, c.do("POST", "/api/library/rescan", nil), http.StatusAccepted)
	if e := next(); e.Refused != "empty" || e.Version != before {
		t.Fatalf("rescan of an empty folder: event %+v, want refused with version %s", e, before)
	}
	if n := h.lib.Index().Len(); n != 3 {
		t.Fatalf("books after a refused rescan = %d, want 3 kept", n)
	}

	expectStatus(t, c.do("POST", "/api/library/rescan", map[string]any{"force": "yes"}), http.StatusBadRequest)
	expectStatus(t, c.do("POST", "/api/library/rescan", map[string]any{"force": true}), http.StatusAccepted)
	if e := next(); e.Refused != "" || e.Version == before {
		t.Fatalf("forced rescan: event %+v, want a new version", e)
	}
	if n := h.lib.Index().Len(); n != 0 {
		t.Fatalf("books after a forced rescan = %d, want 0", n)
	}
}
