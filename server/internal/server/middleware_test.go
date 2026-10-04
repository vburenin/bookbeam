package server

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestStaticFilesAndSecurityHeaders(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	c := h.client()

	r := c.do("GET", "/", nil)
	expectStatus(t, r, 200)
	hdr := r.Header
	if hdr.Get("Content-Type") != "text/html; charset=utf-8" || hdr.Get("Cache-Control") != "no-cache" ||
		!strings.Contains(hdr.Get("Content-Security-Policy"), "script-src 'self'") ||
		hdr.Get("X-Content-Type-Options") != "nosniff" || hdr.Get("X-Frame-Options") != "DENY" ||
		hdr.Get("Referrer-Policy") != "same-origin" {
		t.Fatalf("index headers: %v", hdr)
	}
	etag := hdr.Get("ETag")
	if len(etag) != 66 || etag[0] != '"' {
		t.Fatalf("ETag = %q", etag)
	}
	expectStatus(t, c.do("GET", "/index.html", nil), 200)

	c.headers["If-None-Match"] = etag
	expectStatus(t, c.do("GET", "/", nil), http.StatusNotModified)
	c.headers["If-None-Match"] = "W/" + etag
	expectStatus(t, c.do("GET", "/", nil), http.StatusNotModified)
	delete(c.headers, "If-None-Match")

	r = c.do("GET", "/sw.js", nil)
	if r.Header.Get("Service-Worker-Allowed") != "./" || r.Header.Get("Content-Type") != "text/javascript; charset=utf-8" {
		t.Fatalf("sw.js: %v", r.Header)
	}
	for path, ctype := range map[string]string{
		"/assets/app.js":        "text/javascript; charset=utf-8",
		"/assets/app.css":       "text/css; charset=utf-8",
		"/icons/icon.svg":       "image/svg+xml",
		"/manifest.webmanifest": "application/manifest+json",
		"/favicon.ico":          "image/x-icon",
	} {
		r := c.do("GET", path, nil)
		if r.StatusCode != 200 || r.Header.Get("Content-Type") != ctype || r.Header.Get("Content-Security-Policy") != "" {
			t.Errorf("%s: %d %v", path, r.StatusCode, r.Header)
		}
	}
	for _, p := range []string{"/nope", "/assets/", "/assets/missing.js", "/icons/", "/index.htm", "/index.html/x"} {
		r := c.do("GET", p, nil)
		if r.StatusCode != 404 || r.Header.Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s: %d %v", p, r.StatusCode, r.Header)
		}
	}
	r = c.do("GET", "/healthz", nil)
	if r.StatusCode != 200 || string(r.body) != "ok" {
		t.Fatalf("healthz: %d %q", r.StatusCode, r.body)
	}
}

func TestGzip(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	c := h.client().login("vlad", "test")
	c.headers["Accept-Encoding"] = "gzip, deflate"
	for _, p := range []string{"/", "/assets/app.js", "/api/library"} {
		r := c.do("GET", p, nil)
		if r.Header.Get("Content-Encoding") != "gzip" || !strings.Contains(r.Header.Get("Vary"), "Accept-Encoding") ||
			(r.ContentLength >= 0 && r.ContentLength != int64(len(r.body))) {
			t.Fatalf("%s not gzipped: %v", p, r.Header)
		}
		zr, err := gzip.NewReader(bytes.NewReader(r.body))
		if err != nil {
			t.Fatal(err)
		}
		plain, err := io.ReadAll(zr)
		if err != nil || len(plain) == 0 {
			t.Fatalf("%s: bad gzip body: %v", p, err)
		}
	}
	c.headers["Accept-Encoding"] = "gzip;q=0, identity"
	if r := c.do("GET", "/", nil); r.Header.Get("Content-Encoding") != "" {
		t.Fatal("gzip;q=0 ignored")
	}
	c.headers["Accept-Encoding"] = "gzip"
	lev := h.book("Expanse/Leviathan Wakes")
	if r := c.do("GET", "/api/books/"+lev.ID+"/cover", nil); r.Header.Get("Content-Encoding") != "" {
		t.Fatal("image gzipped")
	}
	c.headers["If-None-Match"] = c.do("GET", "/", nil).Header.Get("ETag")
	if r := c.do("GET", "/", nil); r.StatusCode != 304 || r.Header.Get("Content-Encoding") != "" {
		t.Fatalf("304 with encoding: %d %v", r.StatusCode, r.Header)
	}
}

func TestCSRFHeader(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	c := h.client().login("vlad", "test")
	c.noCSRF = true
	lev := h.book("Expanse/Leviathan Wakes")
	for _, req := range []struct{ method, path string }{
		{"POST", "/api/logout"},
		{"PUT", "/api/progress/" + lev.ID},
		{"PATCH", "/api/settings"},
		{"POST", "/api/library/rescan"},
		{"DELETE", "/api/sessions/x"},
		{"POST", "/api/books/" + lev.ID + "/bookmarks"},
	} {
		r := c.do(req.method, req.path, map[string]any{})
		if r.StatusCode != http.StatusForbidden || !strings.Contains(string(r.body), "X-BookBeam") {
			t.Errorf("%s %s without header: %d", req.method, req.path, r.StatusCode)
		}
	}
	// Exempt: native login form and the unauthenticated pairing calls.
	expectStatus(t, c.form("/login", url.Values{"username": {"vlad"}, "password": {"test"}}), http.StatusSeeOther)
	expectStatus(t, c.do("POST", "/api/pair/start", nil), 200)
	expectStatus(t, c.do("POST", "/api/pair/poll", map[string]string{"pollToken": "x"}), 200)
	// A wrong value is rejected too.
	c.noCSRF = false
	c.headers["X-BookBeam"] = "yes"
	expectStatus(t, c.do("PATCH", "/api/settings", map[string]any{}), http.StatusForbidden)
	c.headers["X-BookBeam"] = "1"
	expectStatus(t, c.do("PATCH", "/api/settings", map[string]any{}), 200)
}

func TestPrefixStripAndCookiePath(t *testing.T) {
	h := newHarness(t, harnessOpts{basePath: "/books/"}) // proxy trust: auto (the test client is on loopback)
	c := h.client()

	r := c.do("GET", "/books", nil)
	if r.StatusCode != http.StatusSeeOther || r.Header.Get("Location") != "books/" {
		t.Fatalf("bare prefix: %d %v", r.StatusCode, r.Header)
	}
	expectStatus(t, c.do("GET", "/books/", nil), 200)
	expectStatus(t, c.do("GET", "/books/assets/app.js", nil), 200)
	expectStatus(t, c.do("GET", "/books/healthz", nil), 200)
	expectStatus(t, c.do("GET", "/", nil), 200) // a stripping proxy also works

	r = c.form("/books/login", url.Values{"username": {"vlad"}, "password": {"test"}})
	ck := cookieNamed(r, "ab_session")
	if r.Header.Get("Location") != "./" || ck == nil || ck.Path != "/books/" {
		t.Fatalf("prefixed login: %v %+v", r.Header, ck)
	}
	expectStatus(t, c.do("GET", "/books/api/me", nil), 200)

	// The same server reached directly (the LAN URL) serves the app at "/":
	// the cookie must be scoped to "/" too, or it is never sent back.
	lan := h.client()
	r = lan.form("/login", url.Values{"username": {"vlad"}, "password": {"test"}})
	if ck := cookieNamed(r, "ab_session"); ck == nil || ck.Path != "/" {
		t.Fatalf("un-prefixed login cookie: %+v", ck)
	}
	expectStatus(t, lan.do("GET", "/api/me", nil), 200)

	// A stripping proxy announces the prefix; it wins over -base-path.
	p := h.client()
	p.headers["X-Forwarded-Prefix"] = "/audio/"
	p.headers["X-Forwarded-Proto"] = "https"
	r = p.form("/login", url.Values{"username": {"vlad"}, "password": {"test"}})
	ck = cookieNamed(r, "ab_session")
	if ck == nil || ck.Path != "/audio/" || !ck.Secure {
		t.Fatalf("forwarded prefix cookie: %+v", ck)
	}
	p.headers["Forwarded"] = "for=1.2.3.4;proto=https"
	delete(p.headers, "X-Forwarded-Proto")
	r = p.do("POST", "/login", map[string]string{"username": "vlad", "password": "test"})
	if ck := cookieNamed(r, "ab_session"); ck == nil || !ck.Secure {
		t.Fatalf("Forwarded proto=https: %+v", ck)
	}
}

func TestUntrustedProxyHeadersIgnored(t *testing.T) {
	h := newHarness(t, harnessOpts{trustProxy: TrustProxyNever})
	c := h.client()
	c.headers["X-Forwarded-Prefix"] = "/evil"
	c.headers["X-Forwarded-Proto"] = "https"
	c.headers["X-Forwarded-For"] = "6.6.6.6"
	r := c.form("/login", url.Values{"username": {"vlad"}, "password": {"test"}})
	ck := cookieNamed(r, "ab_session")
	if ck == nil || ck.Path != "/" || ck.Secure {
		t.Fatalf("cookie = %+v", ck)
	}
	var list []sessionDTO
	c.do("GET", "/api/sessions", nil).json(t, &list)
	if len(list) != 1 || list[0].IP != "127.0.0.1" {
		t.Fatalf("spoofed IP recorded: %+v", list)
	}
}

func TestAcceptsGzip(t *testing.T) {
	for ae, want := range map[string]bool{
		"gzip": true, "gzip, deflate, br": true, "deflate, gzip;q=0.5": true, "GZIP": true,
		"": false, "br": false, "gzip;q=0": false, "gzip; q=0.0": false, "identity;q=1, *;q=0": false,
	} {
		if got := acceptsGzip(ae); got != want {
			t.Errorf("acceptsGzip(%q) = %v", ae, got)
		}
	}
}

func TestIsHTTPS(t *testing.T) {
	s := &Server{trustProxy: TrustProxyAlways}
	for hdr, want := range map[[2]string]bool{
		{"X-Forwarded-Proto", "https"}:                     true,
		{"X-Forwarded-Proto", "HTTPS, http"}:               true,
		{"X-Forwarded-Proto", "http"}:                      false,
		{"Forwarded", `for=192.0.2.60;proto=https;by=x`}:   true,
		{"Forwarded", `for="[2001:db8::1]";proto="https"`}: true,
		{"Forwarded", `for=1.2.3.4;proto=http`}:            false,
	} {
		r, _ := http.NewRequest("GET", "/", nil)
		r.Header.Set(hdr[0], hdr[1])
		if got := s.isHTTPS(r); got != want {
			t.Errorf("%s: %s -> %v", hdr[0], hdr[1], got)
		}
		s.trustProxy = TrustProxyNever
		if s.isHTTPS(r) {
			t.Errorf("untrusted %s: %s honoured", hdr[0], hdr[1])
		}
		s.trustProxy = TrustProxyAlways
	}
}

// With -trust-proxy auto, proxy headers count only from peers that can be
// a reverse proxy of this server: loopback and private networks.
func TestTrustProxyAuto(t *testing.T) {
	s := &Server{trustProxy: TrustProxyAuto}
	for addr, want := range map[string]bool{
		"127.0.0.1:5000":        true,
		"[::1]:5000":            true,
		"10.1.2.3:5000":         true,
		"172.17.0.1:5000":       true, // Docker's bridge
		"192.168.1.20:5000":     true,
		"[fd7a:115c::1]:5000":   true, // unique-local
		"[fe80::1%eth0]:5000":   true, // link-local
		"169.254.0.9:5000":      true,
		"[::ffff:10.0.0.1]:500": true, // IPv4-mapped
		"8.8.8.8:5000":          false,
		"100.64.0.1:5000":       false, // carrier-grade NAT is not a private network
		"[2001:db8::1]:5000":    false,
		"garbage":               false,
	} {
		r, _ := http.NewRequest("GET", "/", nil)
		r.RemoteAddr = addr
		r.Header.Set("X-Forwarded-For", "6.6.6.6")
		r.Header.Set("X-Forwarded-Proto", "https")
		if got := s.trustsProxy(r); got != want {
			t.Errorf("trustsProxy(%s) = %v, want %v", addr, got, want)
		}
		if got := s.clientIP(r) == "6.6.6.6"; got != want {
			t.Errorf("clientIP from %s honoured X-Forwarded-For: %v", addr, got)
		}
		if got := s.isHTTPS(r); got != want {
			t.Errorf("isHTTPS from %s honoured X-Forwarded-Proto: %v", addr, got)
		}
	}
	for v, want := range map[string]ProxyTrust{"auto": TrustProxyAuto, "true": TrustProxyAlways, "0": TrustProxyNever} {
		if got, err := ParseProxyTrust(v); err != nil || got != want || got.String() == "" {
			t.Errorf("ParseProxyTrust(%q) = %v, %v", v, got, err)
		}
	}
	if _, err := ParseProxyTrust("perhaps"); err == nil {
		t.Error("ParseProxyTrust accepted garbage")
	}
}
