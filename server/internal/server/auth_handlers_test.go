package server

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

func cookieNamed(r response, name string) *http.Cookie {
	for _, c := range r.Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func TestV1CookieWorks(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	// Exactly how BookBeam 1.x minted cookies, with the legacy secret.
	secret := bytes.Repeat([]byte{7}, 32)
	exp := strconv.FormatInt(time.Now().AddDate(9, 0, 0).Unix(), 10)
	nonce := "00112233445566778899aabbccddeeff"
	mac := hmac.New(sha256.New, secret)
	for _, p := range []string{"vlad", exp, nonce} {
		mac.Write([]byte("|" + p))
	}
	token := strings.Join([]string{"vlad", exp, nonce, hex.EncodeToString(mac.Sum(nil))}, "|")

	c := h.client()
	c.ua = teslaUA
	c.headers["Cookie"] = "ab_session=" + token
	r := c.do("GET", "/api/me", nil)
	expectStatus(t, r, 200)
	var me map[string]string
	r.json(t, &me)
	if me["username"] != "vlad" || me["sessionId"] != nonce || me["deviceName"] != "Tesla" || me["version"] != "test-1" {
		t.Fatalf("me = %v", me)
	}
}

const teslaUA = "Mozilla/5.0 (X11; GNU/Linux) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0 Safari/537.36 Tesla/2020.16.2.1-e99c70fff409"

func TestLoginFormAndJSON(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	c := h.client()

	r := c.form("/login", url.Values{"username": {"vlad"}, "password": {"nope"}})
	if r.StatusCode != http.StatusSeeOther || r.Header.Get("Location") != "./?login=failed" || cookieNamed(r, "ab_session") != nil {
		t.Fatalf("failed form login: %d %v", r.StatusCode, r.Header)
	}
	r = c.form("/login", url.Values{"username": {"vlad"}, "password": {"test"}})
	if r.StatusCode != http.StatusSeeOther || r.Header.Get("Location") != "./" {
		t.Fatalf("form login: %d %v", r.StatusCode, r.Header)
	}
	ck := cookieNamed(r, "ab_session")
	if ck == nil || ck.Path != "/" || !ck.HttpOnly || ck.SameSite != http.SameSiteLaxMode || ck.MaxAge < 9*365*24*3600 || ck.Secure {
		t.Fatalf("cookie = %+v", ck)
	}
	expectStatus(t, c.do("GET", "/api/me", nil), 200)

	j := h.client()
	r = j.do("POST", "/login", map[string]string{"username": "kid", "password": "bad"})
	expectStatus(t, r, http.StatusUnauthorized)
	r = j.do("POST", "/login", map[string]string{"username": "kid", "password": "test2"})
	expectStatus(t, r, 200)
	var ok map[string]any
	r.json(t, &ok)
	if ok["ok"] != true || ok["username"] != "kid" {
		t.Fatalf("json login = %v", ok)
	}

	// GET /login just bounces to the app.
	r = h.client().do("GET", "/login", nil)
	if r.StatusCode != http.StatusSeeOther || r.Header.Get("Location") != "./" {
		t.Fatalf("GET /login: %d %v", r.StatusCode, r.Header)
	}
}

func TestLoginRateLimitHTTP(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	c := h.client()
	for range 10 {
		expectStatus(t, c.do("POST", "/login", map[string]string{"username": "vlad", "password": "x"}), 401)
	}
	r := c.do("POST", "/login", map[string]string{"username": "vlad", "password": "test"})
	expectStatus(t, r, http.StatusTooManyRequests)
	if ra, _ := strconv.Atoi(r.Header.Get("Retry-After")); ra < 1 || ra > 60 {
		t.Fatalf("Retry-After = %q", r.Header.Get("Retry-After"))
	}
	r = c.form("/login", url.Values{"username": {"vlad"}, "password": {"test"}})
	if r.Header.Get("Location") != "./?login=ratelimited" {
		t.Fatalf("form while limited: %v", r.Header)
	}
	h.clock.Advance(61 * time.Second)
	expectStatus(t, c.do("POST", "/login", map[string]string{"username": "vlad", "password": "test"}), 200)
}

func TestUnauthorizedAndUnknownAPI(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	c := h.client()
	for _, p := range []string{"/api/me", "/api/library", "/api/state", "/api/sessions", "/api/events"} {
		r := c.do("GET", p, nil)
		if r.StatusCode != 401 || strings.TrimSpace(string(r.body)) != `{"error":"unauthorized"}` {
			t.Errorf("%s: %d %s", p, r.StatusCode, r.body)
		}
	}
	c.headers["Cookie"] = "ab_session=garbage"
	expectStatus(t, c.do("GET", "/api/me", nil), 401)

	r := h.client().login("vlad", "test").do("GET", "/api/nope", nil)
	if r.StatusCode != 404 || !strings.Contains(string(r.body), `"error"`) {
		t.Errorf("unknown api: %d %s", r.StatusCode, r.body)
	}
}

func TestLogoutRevokesAndClearsCookies(t *testing.T) {
	h := newHarness(t, harnessOpts{basePath: "/books"})
	c := h.client().login("vlad", "test")
	stolen := h.client()
	for _, ck := range c.http.Jar.Cookies(mustURL(t, h.ts.URL+"/books/")) {
		stolen.headers["Cookie"] = ck.Name + "=" + ck.Value
	}
	r := c.do("POST", "/books/api/logout", nil)
	expectStatus(t, r, 200)
	paths := map[string]bool{}
	for _, ck := range r.Cookies() {
		if ck.Name == "ab_session" && ck.MaxAge < 0 {
			paths[ck.Path] = true
		}
	}
	if !paths["/books/"] || !paths["/"] {
		t.Fatalf("cleared cookie paths = %v", paths)
	}
	// The token itself is dead, not just the browser's copy.
	expectStatus(t, stolen.do("GET", "/books/api/me", nil), 401)
}

func mustURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestSessionsAPI(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	phone := h.client().login("vlad", "test")
	car := h.client()
	car.ua = teslaUA
	car.login("vlad", "test")
	laptop := h.client().login("vlad", "test")
	h.client().login("kid", "test2")

	var list []sessionDTO
	phone.do("GET", "/api/sessions", nil).json(t, &list)
	if len(list) != 3 {
		t.Fatalf("sessions = %+v", list)
	}
	var me map[string]string
	phone.do("GET", "/api/me", nil).json(t, &me)
	var carID, laptopID string
	current := 0
	for _, s := range list {
		if s.Current {
			current++
			if s.ID != me["sessionId"] {
				t.Errorf("current marker on %s", s.ID)
			}
		}
		if s.Name == "Tesla" {
			carID = s.ID
		} else if !s.Current {
			laptopID = s.ID
		}
	}
	if current != 1 || carID == "" || laptopID == "" {
		t.Fatalf("sessions = %+v", list)
	}

	r := phone.do("PATCH", "/api/sessions/"+carID, map[string]string{"name": "  Family   Tesla "})
	expectStatus(t, r, 200)
	var renamed sessionDTO
	r.json(t, &renamed)
	if renamed.Name != "Family Tesla" {
		t.Errorf("renamed = %+v", renamed)
	}
	expectStatus(t, phone.do("PATCH", "/api/sessions/"+carID, map[string]string{"name": " "}), 400)
	expectStatus(t, phone.do("PATCH", "/api/sessions/unknown", map[string]string{"name": "x"}), 404)

	carEvents := car.openEvents("car-tab")
	expectStatus(t, phone.do("DELETE", "/api/sessions/"+carID, nil), 200)
	if ev := carEvents.next(t); ev.name != "session-revoked" {
		t.Fatalf("revoked stream got %+v", ev)
	}
	carEvents.expectClosed(t)
	expectStatus(t, car.do("GET", "/api/me", nil), 401)

	r = phone.do("POST", "/api/sessions/revoke-others", nil)
	expectStatus(t, r, 200)
	var rev map[string]int
	r.json(t, &rev)
	if rev["revoked"] != 1 {
		t.Fatalf("revoke-others = %v", rev)
	}
	expectStatus(t, laptop.do("GET", "/api/me", nil), 401)
	expectStatus(t, phone.do("GET", "/api/me", nil), 200)
	phone.do("GET", "/api/sessions", nil).json(t, &list)
	if len(list) != 1 || !list[0].Current {
		t.Fatalf("after revoke-others: %+v", list)
	}
}

func TestPairingEndToEnd(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	phone := h.client().login("vlad", "test")
	car := h.client()
	car.ua = teslaUA
	car.noCSRF = true // unauthenticated pairing endpoints need no header

	var start struct {
		Code      string `json:"code"`
		PollToken string `json:"pollToken"`
		ExpiresAt int64  `json:"expiresAt"`
	}
	r := car.do("POST", "/api/pair/start", map[string]string{"deviceName": "Model Y"})
	expectStatus(t, r, 200)
	r.json(t, &start)
	if len(start.Code) != 6 || len(start.PollToken) != 32 || start.ExpiresAt <= time.Now().UnixMilli() {
		t.Fatalf("start = %+v", start)
	}
	poll := func() (string, response) {
		r := car.do("POST", "/api/pair/poll", map[string]string{"pollToken": start.PollToken})
		expectStatus(t, r, 200)
		var st map[string]string
		r.json(t, &st)
		return st["status"], r
	}
	if st, _ := poll(); st != "pending" {
		t.Fatalf("status = %s", st)
	}
	expectStatus(t, car.do("GET", "/api/me", nil), 401)

	typed := strings.ToLower(start.Code[:3]) + "-" + start.Code[3:]
	r = phone.do("GET", "/api/pair/"+typed, nil)
	expectStatus(t, r, 200)
	var info map[string]any
	r.json(t, &info)
	// The name shown to the approver comes from the User-Agent, not from the
	// (unauthenticated) requester.
	if info["code"] != start.Code || info["deviceName"] != "Tesla" || info["ua"] != teslaUA || info["ip"] != "127.0.0.1" {
		t.Fatalf("info = %v", info)
	}
	expectStatus(t, h.client().do("POST", "/api/pair/"+start.Code+"/approve", map[string]string{"name": "x"}), 401)
	expectStatus(t, phone.do("POST", "/api/pair/"+start.Code+"/approve", map[string]string{"name": "Family Tesla"}), 200)
	expectStatus(t, phone.do("POST", "/api/pair/"+start.Code+"/approve", nil), 409)

	st, r := poll()
	ck := cookieNamed(r, "ab_session")
	if dev := cookieNamed(r, "ab_device"); st != "approved" || ck == nil || !ck.HttpOnly || dev == nil || !dev.HttpOnly || len(dev.Value) != 32 {
		t.Fatalf("approved poll: %s %v", st, r.Header)
	}
	var me map[string]string
	car.do("GET", "/api/me", nil).json(t, &me)
	if me["username"] != "vlad" || me["deviceName"] != "Family Tesla" {
		t.Fatalf("paired me = %v", me)
	}
	if st, r := poll(); st != "expired" || cookieNamed(r, "ab_session") != nil {
		t.Fatalf("second redemption: %s", st)
	}

	// Deny and expiry.
	other := h.client()
	other.noCSRF = true
	other.do("POST", "/api/pair/start", nil).json(t, &start)
	expectStatus(t, phone.do("POST", "/api/pair/"+start.Code+"/deny", nil), 200)
	if st, _ := poll(); st != "denied" {
		t.Fatalf("denied: %s", st)
	}
	other.do("POST", "/api/pair/start", nil).json(t, &start)
	h.clock.Advance(11 * time.Minute)
	if st, _ := poll(); st != "expired" {
		t.Fatalf("expired: %s", st)
	}
	expectStatus(t, phone.do("GET", "/api/pair/"+start.Code, nil), 404)
	expectStatus(t, phone.do("POST", "/api/pair/"+start.Code+"/approve", nil), 404)

	expectStatus(t, car.do("POST", "/api/pair/poll", map[string]string{}), 400)
	for range 5 {
		other.do("POST", "/api/pair/start", nil)
	}
	expectStatus(t, other.do("POST", "/api/pair/start", nil), http.StatusTooManyRequests)
}

func TestPairQR(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	c := h.client()
	r := c.do("GET", "/pair-qr.svg?data="+url.QueryEscape("https://books.example/#/pair/K7P4QX"), nil)
	expectStatus(t, r, 200)
	if r.Header.Get("Content-Type") != "image/svg+xml" || !strings.HasPrefix(string(r.body), "<svg") || !strings.Contains(string(r.body), "M4 4h7") {
		t.Fatalf("qr: %v %.200s", r.Header, r.body)
	}
	for _, bad := range []string{"", "javascript:alert(1)", "ftp://x", "https://" + strings.Repeat("a", 400)} {
		expectStatus(t, c.do("GET", "/pair-qr.svg?data="+url.QueryEscape(bad), nil), 400)
	}
}
