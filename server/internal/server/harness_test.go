package server

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/vburenin/bookbeam/server/internal/auth"
	"github.com/vburenin/bookbeam/server/internal/library"
	"github.com/vburenin/bookbeam/server/internal/media"
	"github.com/vburenin/bookbeam/server/internal/store"
)

// fakeAudio is the content of test "audio" files: the Info a fake prober
// returns (see fakeProbe).
type fakeAudio struct {
	media.Info
	PicMIME string `json:"picMime,omitempty"`
	PicData []byte `json:"picData,omitempty"`
}

func fakeProbe(path string, o media.Options) (*media.Info, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var fa fakeAudio
	if err := json.Unmarshal(b, &fa); err != nil {
		return nil, errors.New("not audio")
	}
	info := fa.Info
	if len(fa.PicData) > 0 {
		info.HasPicture = true
		if o.WantPicture {
			info.Picture = &media.Picture{MIME: fa.PicMIME, Data: fa.PicData}
		}
	}
	return &info, nil
}

// Covers are recognised by content, so test images start like real ones.
const (
	testJPEG = "\xff\xd8\xff\xe0 jpeg-bytes"
	testPNG  = "\x89PNG\r\n\x1a\n png-bytes"
)

type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

var testWeb = fstest.MapFS{
	"index.html":           {Data: []byte("<!doctype html><title>BookBeam</title>" + strings.Repeat("<!-- padding -->", 100))},
	"sw.js":                {Data: []byte("self.addEventListener('install', () => self.skipWaiting());")},
	"manifest.webmanifest": {Data: []byte(`{"name":"BookBeam"}`)},
	"favicon.ico":          {Data: []byte("\x00\x00\x01\x00")},
	"assets/app.js":        {Data: []byte("export const x = 1;" + strings.Repeat("// pad\n", 200))},
	"assets/app.css":       {Data: []byte("body{color:#000}")},
	"icons/icon.svg":       {Data: []byte("<svg xmlns='http://www.w3.org/2000/svg'/>")},
}

type harness struct {
	t     *testing.T
	root  string
	state string
	clock *testClock
	auth  *auth.Service
	lib   *library.Library
	store *store.Store
	srv   *Server
	ts    *httptest.Server
}

type harnessOpts struct {
	basePath   string
	trustProxy ProxyTrust
	setup      func(root string) // populate the library before the first scan
	web        fs.FS             // defaults to testWeb
	webLive    bool
}

func writeTestFile(t *testing.T, root, rel string, data []byte) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeTestAudio(t *testing.T, root, rel string, fa fakeAudio) {
	t.Helper()
	b, err := json.Marshal(fa)
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, root, rel, b)
}

// defaultLibrary is a small library: a three-track book with a cover, a
// single-file book with chapters and embedded art, and a second book.
func defaultLibrary(t *testing.T, root string) {
	for i, title := range []string{"Prologue", "The Storm", "Epilogue"} {
		writeTestAudio(t, root, "Expanse/Leviathan Wakes/0"+string(rune('1'+i))+" - "+title+".mp3", fakeAudio{Info: media.Info{
			Format: "mp3", Duration: float64(100 * (i + 1)), Title: title, Album: "Leviathan Wakes",
			AlbumArtist: "James S. A. Corey", Composer: "Jefferson Mays",
		}})
	}
	writeTestFile(t, root, "Expanse/Leviathan Wakes/cover.jpg", []byte(testJPEG))
	writeTestAudio(t, root, "Single/Martian.m4b", fakeAudio{
		Info: media.Info{Format: "mp4", Duration: 900, Title: "The Martian", Artist: "Andy Weir", Chapters: []media.Chapter{
			{Title: "Sol 6", Start: 0, End: 300}, {Title: "Sol 7", Start: 300, End: 900},
		}},
		PicMIME: "image/png", PicData: []byte(testPNG),
	})
	writeTestAudio(t, root, "Single/Hail Mary.m4b", fakeAudio{Info: media.Info{Format: "mp4", Duration: 50, Title: "Project Hail Mary"}})
	writeTestFile(t, root, "session_secret", bytes.Repeat([]byte{7}, 32))
}

func newHarness(t *testing.T, o harnessOpts) *harness {
	t.Helper()
	root := t.TempDir()
	h := &harness{t: t, root: root, state: filepath.Join(root, ".bookbeam"),
		clock: &testClock{t: time.Now()}}
	if o.setup != nil {
		o.setup(root)
	} else {
		defaultLibrary(t, root)
	}
	users, err := auth.ParseUsers([]string{"vlad:test", "kid:test2"})
	if err != nil {
		t.Fatal(err)
	}
	h.auth, err = auth.NewService(auth.Config{StateDir: h.state, LegacySecretPath: filepath.Join(root, "session_secret"),
		Users: users, Now: h.clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	h.lib, err = library.Open(library.Options{Root: root, StateDir: h.state, Probe: fakeProbe})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.lib.Scan(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	h.store, err = store.New(store.Options{Dir: filepath.Join(h.state, "users"), LegacyDir: filepath.Join(root, "state")})
	if err != nil {
		t.Fatal(err)
	}
	web := o.web
	if web == nil {
		web = testWeb
	}
	h.srv = New(Config{Auth: h.auth, Library: h.lib, Store: h.store, Web: web, WebLive: o.webLive,
		BasePath: o.basePath, TrustProxy: o.trustProxy, Version: "test-1"})
	h.ts = httptest.NewServer(h.srv)
	t.Cleanup(func() {
		h.srv.CloseStreams()
		h.ts.Close()
	})
	return h
}

// rescan scans the library and lets the server react, as after a periodic
// scan.
func (h *harness) rescan() {
	h.t.Helper()
	changed, err := h.lib.Scan(context.Background(), false)
	if err != nil {
		h.t.Fatal(err)
	}
	h.srv.onScan(library.ScanEvent{Version: h.lib.Index().Version, Changed: changed})
}

func (h *harness) book(path string) *library.Book {
	h.t.Helper()
	for _, b := range h.lib.Index().Books {
		if b.Path == path {
			return b
		}
	}
	h.t.Fatalf("no book %q", path)
	return nil
}

// client is a browser-like client with its own cookie jar.
type client struct {
	h       *harness
	http    *http.Client
	ua      string
	noCSRF  bool
	headers map[string]string
}

func (h *harness) client() *client {
	jar, _ := cookiejar.New(nil)
	return &client{h: h, ua: "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) Mobile Safari/604.1",
		headers: map[string]string{},
		http: &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}}}
}

type response struct {
	*http.Response
	body []byte
}

func (r response) json(t *testing.T, v any) {
	t.Helper()
	if err := json.Unmarshal(r.body, v); err != nil {
		t.Fatalf("decoding %s: %v", r.body, err)
	}
}

func (c *client) request(method, path string, body io.Reader, contentType string) response {
	c.h.t.Helper()
	req, err := http.NewRequest(method, c.h.ts.URL+path, body)
	if err != nil {
		c.h.t.Fatal(err)
	}
	req.Header.Set("User-Agent", c.ua)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if method != http.MethodGet && method != http.MethodHead && !c.noCSRF {
		req.Header.Set("X-BookBeam", "1")
	}
	for k, v := range c.headers {
		req.Header.Set(k, v)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		c.h.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		c.h.t.Fatal(err)
	}
	return response{Response: resp, body: b}
}

func (c *client) do(method, path string, body any) response {
	c.h.t.Helper()
	if body == nil {
		return c.request(method, path, nil, "")
	}
	b, err := json.Marshal(body)
	if err != nil {
		c.h.t.Fatal(err)
	}
	return c.request(method, path, bytes.NewReader(b), "application/json")
}

func (c *client) form(path string, vals url.Values) response {
	c.h.t.Helper()
	return c.request(http.MethodPost, path, strings.NewReader(vals.Encode()), "application/x-www-form-urlencoded")
}

func (c *client) login(user, pass string) *client {
	c.h.t.Helper()
	r := c.do("POST", "/login", map[string]string{"username": user, "password": pass})
	if r.StatusCode != http.StatusOK {
		c.h.t.Fatalf("login %s: %d %s", user, r.StatusCode, r.body)
	}
	return c
}

func expectStatus(t *testing.T, r response, want int) {
	t.Helper()
	if r.StatusCode != want {
		t.Fatalf("%s %s: status %d, want %d; body %s", r.Request.Method, r.Request.URL.Path, r.StatusCode, want, r.body)
	}
}

// --- Server-Sent Events test client ---

type sseEvent struct {
	name string
	data string
}

type sseStream struct {
	events chan sseEvent
	cancel context.CancelFunc
	hello  sseEvent // the first event, always "hello"
}

func (c *client) openEvents(clientID string) *sseStream {
	t := c.h.t
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, "GET", c.h.ts.URL+"/api/events?clientId="+clientID, nil)
	resp, err := c.http.Do(req)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "text/event-stream" ||
		resp.Header.Get("X-Accel-Buffering") != "no" || resp.Header.Get("Cache-Control") != "no-cache" {
		cancel()
		t.Fatalf("events: %d %v", resp.StatusCode, resp.Header)
	}
	s := &sseStream{events: make(chan sseEvent, 100), cancel: cancel}
	go func() {
		defer close(s.events)
		defer resp.Body.Close()
		sc := bufio.NewScanner(resp.Body)
		var ev sseEvent
		for sc.Scan() {
			line := sc.Text()
			switch {
			case line == "":
				if ev.name != "" {
					s.events <- ev
				}
				ev = sseEvent{}
			case strings.HasPrefix(line, "event: "):
				ev.name = strings.TrimPrefix(line, "event: ")
			case strings.HasPrefix(line, "data: "):
				ev.data = strings.TrimPrefix(line, "data: ")
			}
		}
	}()
	t.Cleanup(cancel)
	if s.hello = s.next(t); s.hello.name != "hello" {
		t.Fatalf("first event = %+v, want hello", s.hello)
	}
	return s
}

func (s *sseStream) next(t *testing.T) sseEvent {
	t.Helper()
	select {
	case ev, ok := <-s.events:
		if !ok {
			t.Fatal("event stream closed")
		}
		return ev
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for an event")
	}
	return sseEvent{}
}

// expectNone asserts no event arrives within a short window.
func (s *sseStream) expectNone(t *testing.T) {
	t.Helper()
	select {
	case ev, ok := <-s.events:
		if ok {
			t.Fatalf("unexpected event %+v", ev)
		}
	case <-time.After(150 * time.Millisecond):
	}
}

// expectClosed waits for the server to end the stream.
func (s *sseStream) expectClosed(t *testing.T) {
	t.Helper()
	select {
	case ev, ok := <-s.events:
		if ok {
			t.Fatalf("expected closed stream, got %+v", ev)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("stream not closed")
	}
}
