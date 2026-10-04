package server

import (
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/vburenin/bookbeam/server/internal/media"
)

// Track URLs carry the file's fingerprint: the audio is cached for good
// under the current one, and revalidated otherwise.
func TestAudioCaching(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	c := h.client().login("vlad", "test")
	lev := h.book("Expanse/Leviathan Wakes")
	base := "/api/books/" + lev.ID + "/tracks/0/audio"

	for _, v := range []string{"", "?v=0123456789ab", "?v=" + lev.Tracks[1].Fingerprint} {
		r := c.do("GET", base+v, nil)
		expectStatus(t, r, 200)
		if cc := r.Header.Get("Cache-Control"); cc != "private, no-cache" {
			t.Errorf("%q: Cache-Control = %q", v, cc)
		}
	}
	current := base + "?v=" + lev.Tracks[0].Fingerprint
	r := c.do("GET", current, nil)
	if cc := r.Header.Get("Cache-Control"); cc != "private, max-age=31536000, immutable" {
		t.Fatalf("current fingerprint: Cache-Control = %q", cc)
	}
	c.headers["If-None-Match"] = r.Header.Get("ETag")
	expectStatus(t, c.do("GET", base, nil), http.StatusNotModified)
	delete(c.headers, "If-None-Match")

	// The file is replaced before the next scan: the old URL must not be
	// cached with the new content.
	writeTestAudio(t, h.root, lev.Tracks[0].Path, fakeAudio{Info: media.Info{Format: "mp3", Duration: 99, Title: "New prologue"}})
	r = c.do("GET", current, nil)
	if cc := r.Header.Get("Cache-Control"); r.StatusCode != 200 || cc != "private, no-cache" {
		t.Fatalf("replaced file: %d %q", r.StatusCode, cc)
	}
	// After the scan the track has a new URL.
	h.rescan()
	if fresh := h.book("Expanse/Leviathan Wakes"); fresh.Tracks[0].Fingerprint == lev.Tracks[0].Fingerprint {
		t.Fatal("fingerprint unchanged after the file changed")
	}
}

// A symlink swapped into the library after a scan must not expose
// BookBeam's own files (or v1's).
func TestMediaServeTimePathCheck(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	c := h.client().login("vlad", "test")
	lev := h.book("Expanse/Leviathan Wakes")
	swap := func(rel, target string) {
		t.Helper()
		p := filepath.Join(h.root, filepath.FromSlash(rel))
		if err := os.Remove(p); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, p); err != nil {
			t.Skip("symlinks unsupported:", err)
		}
	}
	for i, target := range []string{
		filepath.Join(h.state, "secret.key"),
		filepath.Join(h.state, "sessions.json"),
		filepath.Join(h.root, "session_secret"),
	} {
		swap(lev.Tracks[i].Path, target)
		r := c.do("GET", "/api/books/"+lev.ID+"/tracks/"+string(rune('0'+i))+"/audio", nil)
		if r.StatusCode != 404 {
			t.Errorf("track -> %s: %d %q", target, r.StatusCode, r.body)
		}
	}
	swap(lev.Cover.Source, filepath.Join(h.state, "secret.key"))
	expectStatus(t, c.do("GET", "/api/books/"+lev.ID+"/cover", nil), 404)

	// Extracted art lives inside the state dir and is still served.
	martian := h.book("Single/Martian.m4b")
	expectStatus(t, c.do("GET", "/api/books/"+martian.ID+"/cover", nil), 200)

	// Symlinks within the library keep working.
	hail := h.book("Single/Hail Mary.m4b")
	swap(hail.Tracks[0].Path, filepath.Join(h.root, filepath.FromSlash(martian.Tracks[0].Path)))
	expectStatus(t, c.do("GET", "/api/books/"+hail.ID+"/tracks/0/audio", nil), 200)
}

var versionedWeb = fstest.MapFS{
	"index.html": {Data: []byte(`<!doctype html><link rel="stylesheet" href="assets/app.css">` +
		`<link rel="preload" href="./assets/fonts/a.woff2" as="font">` +
		`<script type="module" src="assets/js/main.js"></script><a href="myassets/x">x</a>`)},
	"assets/app.css":         {Data: []byte("@font-face{src:url(fonts/a.woff2)}")},
	"assets/fonts/a.woff2":   {Data: []byte("font")},
	"assets/js/main.js":      {Data: []byte("import './ui.js';")},
	"assets/js/ui.js":        {Data: []byte("export {};")},
	"sw.js":                  {Data: []byte("")},
	"manifest.webmanifest":   {Data: []byte("{}")},
	"favicon.ico":            {Data: []byte("ico")},
	"icons/apple-touch.png":  {Data: []byte("png")},
	"assets/js/sub/deep.mjs": {Data: []byte("export {};")},
}

var assetsRefRE = regexp.MustCompile(`assets-([0-9a-f]{12})/`)

// index.html points at versioned asset URLs, which browsers may cache for
// good; any change to an asset changes every URL.
func TestVersionedAssets(t *testing.T) {
	h := newHarness(t, harnessOpts{web: versionedWeb})
	c := h.client()
	r := c.do("GET", "/", nil)
	expectStatus(t, r, 200)
	body := string(r.body)
	m := assetsRefRE.FindAllStringSubmatch(body, -1)
	if len(m) != 3 || m[0][1] != m[1][1] || m[1][1] != m[2][1] ||
		!strings.Contains(body, `href="./assets-`+m[0][1]+`/fonts/a.woff2"`) || !strings.Contains(body, `href="myassets/x"`) {
		t.Fatalf("index = %s", body)
	}
	ver := m[0][1]

	for _, p := range []string{"js/main.js", "app.css", "fonts/a.woff2", "js/sub/deep.mjs"} {
		r := c.do("GET", "/assets-"+ver+"/"+p, nil)
		plain := c.do("GET", "/assets/"+p, nil)
		if r.StatusCode != 200 || string(r.body) != string(plain.body) ||
			r.Header.Get("Cache-Control") != "public, max-age=31536000, immutable" {
			t.Errorf("%s: %d %v", p, r.StatusCode, r.Header)
		}
		if cc := plain.Header.Get("Cache-Control"); cc != "no-cache" || plain.Header.Get("ETag") == "" {
			t.Errorf("plain %s: %q", p, cc)
		}
	}
	// Another version (an old cached index.html) still gets the files, but
	// revalidated.
	r = c.do("GET", "/assets-0123456789ab/js/main.js", nil)
	if r.StatusCode != 200 || r.Header.Get("Cache-Control") != "no-cache" {
		t.Fatalf("old version: %d %v", r.StatusCode, r.Header)
	}
	for _, p := range []string{"/assets-/app.css", "/assets-XYZ/app.css", "/assets-" + ver + "/missing.js", "/assets-" + ver} {
		expectStatus(t, c.do("GET", p, nil), 404)
	}

	// Changing one asset changes the version.
	changed := fstest.MapFS{}
	for k, v := range versionedWeb {
		changed[k] = v
	}
	changed["assets/js/ui.js"] = &fstest.MapFile{Data: []byte("export const x = 2;")}
	h2 := newHarness(t, harnessOpts{web: changed})
	m2 := assetsRefRE.FindStringSubmatch(string(h2.client().do("GET", "/", nil).body))
	if m2 == nil || m2[1] == ver {
		t.Fatalf("version did not change: %v", m2)
	}

	// A live (development) directory is re-hashed per index request and
	// never cached for good.
	dir := t.TempDir()
	for name, f := range versionedWeb {
		writeTestFile(t, dir, name, f.Data)
	}
	h3 := newHarness(t, harnessOpts{web: os.DirFS(dir), webLive: true})
	c3 := h3.client()
	v1 := assetsRefRE.FindStringSubmatch(string(c3.do("GET", "/", nil).body))[1]
	if cc := c3.do("GET", "/assets-"+v1+"/app.css", nil).Header.Get("Cache-Control"); cc != "no-cache" {
		t.Fatalf("live asset Cache-Control = %q", cc)
	}
	writeTestFile(t, dir, "assets/app.css", []byte("body{}"))
	if v2 := assetsRefRE.FindStringSubmatch(string(c3.do("GET", "/", nil).body))[1]; v2 == v1 {
		t.Fatal("live version not recomputed")
	}
}

// The library's ETag describes the whole body, so a client that cached a
// "scanning" listing does not keep it after a scan that changed nothing.
func TestLibraryETagFollowsScans(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	c := h.client().login("vlad", "test")
	before := c.do("GET", "/api/library", nil).Header.Get("ETag")
	time.Sleep(2 * time.Millisecond)
	h.rescan()
	c.headers["If-None-Match"] = before
	r := c.do("GET", "/api/library", nil)
	if r.StatusCode != 200 || r.Header.Get("ETag") == before {
		t.Fatalf("after a no-change scan: %d %q", r.StatusCode, r.Header.Get("ETag"))
	}
}
