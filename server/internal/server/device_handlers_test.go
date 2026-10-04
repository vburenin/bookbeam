package server

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

func (c *client) me() map[string]string {
	c.h.t.Helper()
	r := c.do("GET", "/api/me", nil)
	expectStatus(c.h.t, r, 200)
	var me map[string]string
	r.json(c.h.t, &me)
	return me
}

func (c *client) accounts() []deviceAccountDTO {
	c.h.t.Helper()
	r := c.do("GET", "/api/device/accounts", nil)
	expectStatus(c.h.t, r, 200)
	var list []deviceAccountDTO
	r.json(c.h.t, &list)
	return list
}

func (c *client) cookie(name string) string {
	for _, ck := range c.http.Jar.Cookies(mustURL(c.h.t, c.h.ts.URL+"/")) {
		if ck.Name == name {
			return ck.Value
		}
	}
	return ""
}

func usernames(list []deviceAccountDTO) string {
	var out []string
	for _, a := range list {
		name := a.Username
		if a.Current {
			name += "*"
		}
		out = append(out, name)
	}
	return strings.Join(out, ",")
}

// "Who's listening?": the family car keeps several people signed in and
// switches between them; signing out hands the car to the next listener.
func TestSharedDeviceListeners(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	car := h.client()
	car.ua = teslaUA
	car.login("vlad", "test")
	device := car.cookie("ab_device")
	if len(device) != 32 {
		t.Fatalf("no device cookie after sign-in: %q", device)
	}
	if got := usernames(car.accounts()); got != "vlad*" {
		t.Fatalf("accounts = %s", got)
	}

	// Adding a listener (signing in again) keeps vlad signed in.
	h.clock.Advance(time.Second)
	car.login("kid", "test2")
	if car.cookie("ab_device") != device {
		t.Fatal("device id changed on the second sign-in")
	}
	if me := car.me(); me["username"] != "kid" {
		t.Fatalf("me = %v", me)
	}
	if got := usernames(car.accounts()); got != "kid*,vlad" {
		t.Fatalf("accounts = %s", got)
	}

	// Switching needs the CSRF header like every API mutation.
	car.noCSRF = true
	expectStatus(t, car.do("POST", "/api/device/switch", map[string]string{"username": "vlad"}), http.StatusForbidden)
	car.noCSRF = false
	r := car.do("POST", "/api/device/switch", map[string]string{"username": "vlad"})
	expectStatus(t, r, 200)
	if ck := cookieNamed(r, "ab_session"); ck == nil || !ck.HttpOnly || ck.Path != "/" {
		t.Fatalf("switch cookie = %+v", ck)
	}
	if me := car.me(); me["username"] != "vlad" {
		t.Fatalf("after switch me = %v", me)
	}
	expectStatus(t, car.do("POST", "/api/device/switch", map[string]string{"username": "nobody"}), 404)

	// A phone signed in as the kid cannot reach the car's accounts, not even
	// with the car's device id planted in its cookie jar.
	phone := h.client().login("kid", "test2")
	if got := usernames(phone.accounts()); got != "kid*" {
		t.Fatalf("phone accounts = %s", got)
	}
	phone.headers["Cookie"] = "ab_session=" + phone.cookie("ab_session") + "; ab_device=" + device
	expectStatus(t, phone.do("POST", "/api/device/switch", map[string]string{"username": "vlad"}), 404)
	delete(phone.headers, "Cookie")

	// Signing out vlad hands the car to the kid...
	r = car.do("POST", "/api/logout", nil)
	expectStatus(t, r, 200)
	var out map[string]any
	r.json(t, &out)
	if out["next"] != "kid" {
		t.Fatalf("logout = %v", out)
	}
	if me := car.me(); me["username"] != "kid" {
		t.Fatalf("after logout me = %v", me)
	}
	// ...and signing out the last listener signs the car out.
	r = car.do("POST", "/api/logout", nil)
	r.json(t, &out)
	if out["next"] != "" {
		t.Fatalf("last logout = %v", out)
	}
	expectStatus(t, car.do("GET", "/api/me", nil), 401)
	// The phone's own kid session is unaffected.
	if me := phone.me(); me["username"] != "kid" {
		t.Fatalf("phone me = %v", me)
	}
}

// Pairing on a device that is already signed in adds a listener too.
func TestPairingAddsListener(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	phone := h.client().login("kid", "test2")
	car := h.client()
	car.ua = teslaUA
	car.login("vlad", "test")

	var start struct {
		Code      string `json:"code"`
		PollToken string `json:"pollToken"`
	}
	car.do("POST", "/api/pair/start", nil).json(t, &start)
	expectStatus(t, phone.do("POST", "/api/pair/"+start.Code+"/approve", map[string]string{"name": "Car"}), 200)
	expectStatus(t, car.do("POST", "/api/pair/poll", map[string]string{"pollToken": start.PollToken}), 200)
	if me := car.me(); me["username"] != "kid" || me["deviceName"] != "Car" {
		t.Fatalf("me = %v", me)
	}
	if got := usernames(car.accounts()); got != "kid*,vlad" {
		t.Fatalf("accounts = %s", got)
	}
}

// api/me renews the cookies (browsers cap their lifetime at ~400 days) and
// links sessions from before device tracking (here: a v1 cookie) to the
// browser, so they can be switched to.
func TestMeRenewsCookiesAndLinksOldSessions(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	secret := bytes.Repeat([]byte{7}, 32) // the harness library's v1 session_secret
	exp := strconv.FormatInt(time.Now().AddDate(9, 0, 0).Unix(), 10)
	nonce := "00112233445566778899aabbccddeeff"
	mac := hmac.New(sha256.New, secret)
	for _, p := range []string{"vlad", exp, nonce} {
		mac.Write([]byte("|" + p))
	}
	token := strings.Join([]string{"vlad", exp, nonce, hex.EncodeToString(mac.Sum(nil))}, "|")

	car := h.client()
	car.ua = teslaUA
	car.http.Jar.SetCookies(mustURL(t, h.ts.URL+"/"), []*http.Cookie{{Name: "ab_session", Value: token, Path: "/"}})
	r := car.do("GET", "/api/me", nil)
	expectStatus(t, r, 200)
	sess, dev := cookieNamed(r, "ab_session"), cookieNamed(r, "ab_device")
	if sess == nil || sess.Value != token || sess.MaxAge < 9*365*24*3600 || !sess.HttpOnly {
		t.Fatalf("session cookie not renewed: %+v", sess)
	}
	if dev == nil || len(dev.Value) != 32 || !dev.HttpOnly || dev.MaxAge < 9*365*24*3600 {
		t.Fatalf("device cookie = %+v", dev)
	}

	// The kid is added on the car; the old v1 session is one of its
	// listeners and can be switched back to.
	car.login("kid", "test2")
	if got := usernames(car.accounts()); got != "kid*,vlad" {
		t.Fatalf("accounts = %s", got)
	}
	expectStatus(t, car.do("POST", "/api/device/switch", map[string]string{"username": "vlad"}), 200)
	if car.cookie("ab_session") != token {
		t.Fatal("switching back did not restore the original cookie")
	}
}
