package auth

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const teslaUA = "Mozilla/5.0 (X11; GNU/Linux) AppleWebKit/537.36 (KHTML, like Gecko) Chromium/79.0.3945.130 Chrome/79.0.3945.130 Safari/537.36 Tesla/2020.16.2.1-e99c70fff409"

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *fakeClock { return &fakeClock{t: time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func mustUsers(t *testing.T, specs ...string) *Users {
	t.Helper()
	u, err := ParseUsers(specs)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func newTestService(t *testing.T, stateDir, legacy string, clk *fakeClock, specs ...string) *Service {
	t.Helper()
	if len(specs) == 0 {
		specs = []string{"vlad:pw", "kid:pw2"}
	}
	s, err := NewService(Config{
		StateDir:         stateDir,
		LegacySecretPath: legacy,
		Users:            mustUsers(t, specs...),
		Now:              clk.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// v1MakeToken reproduces BookBeam 1.x's makeToken byte for byte.
func v1MakeToken(secret []byte, username string, now time.Time) string {
	exp := now.AddDate(10, 0, 0)
	nonce := make([]byte, 16)
	_, _ = rand.Read(nonce)
	n := hex.EncodeToString(nonce)
	expUnix := strconv.FormatInt(exp.Unix(), 10)
	mac := hmac.New(sha256.New, secret)
	for _, p := range []string{username, expUnix, n} {
		mac.Write([]byte("|"))
		mac.Write([]byte(p))
	}
	sig := hex.EncodeToString(mac.Sum(nil))
	return strings.Join([]string{username, expUnix, n, sig}, "|")
}

func TestV1TokenCompatibilityAndSecretMigration(t *testing.T) {
	dataDir := t.TempDir()
	stateDir := filepath.Join(dataDir, ".bookbeam")
	legacySecret := bytes.Repeat([]byte{0xAB}, 32)
	legacyPath := filepath.Join(dataDir, "session_secret")
	if err := os.WriteFile(legacyPath, legacySecret, 0o600); err != nil {
		t.Fatal(err)
	}
	clk := newClock()
	issued := clk.Now().AddDate(-1, 0, 0) // cookie minted a year ago by v1
	tok := v1MakeToken(legacySecret, "vlad", issued)

	s := newTestService(t, stateDir, legacyPath, clk)
	got, err := os.ReadFile(filepath.Join(stateDir, "secret.key"))
	if err != nil || !bytes.Equal(got, legacySecret) {
		t.Fatalf("secret.key = %x, %v; want legacy bytes copied", got, err)
	}
	if b, _ := os.ReadFile(legacyPath); !bytes.Equal(b, legacySecret) {
		t.Fatal("legacy session_secret must be left untouched")
	}

	sess, err := s.Authenticate(tok, teslaUA, "10.0.0.12")
	if err != nil {
		t.Fatalf("v1 token rejected: %v", err)
	}
	if sess.User != "vlad" || sess.Name != "Tesla" || sess.IP != "10.0.0.12" {
		t.Fatalf("unexpected adopted session: %+v", sess)
	}
	if want := issued.Truncate(time.Second).UnixMilli(); sess.CreatedAt != want {
		t.Errorf("createdAt = %d, want issue time %d", sess.CreatedAt, want)
	}
	if list := s.Sessions().List("vlad"); len(list) != 1 || list[0].ID != sess.ID {
		t.Fatalf("legacy session not registered: %+v", list)
	}

	// A restart keeps both the key and the adopted session.
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s2 := newTestService(t, stateDir, legacyPath, clk)
	if _, err := s2.Authenticate(tok, teslaUA, "10.0.0.12"); err != nil {
		t.Fatalf("after restart: %v", err)
	}

	// Deleting secret.key after the first start signs everyone out: the v1
	// key must not be resurrected.
	if err := os.Remove(filepath.Join(stateDir, "secret.key")); err != nil {
		t.Fatal(err)
	}
	s3 := newTestService(t, stateDir, legacyPath, clk)
	if _, err := s3.Authenticate(tok, teslaUA, ""); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("token survived secret rotation: %v", err)
	}
}

func TestShortSecretRefused(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "secret.key"), []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := NewService(Config{StateDir: dir, Users: mustUsers(t, "a:b")})
	if err == nil {
		t.Fatal("expected error for truncated secret.key")
	}
}

func TestTokenRejections(t *testing.T) {
	clk := newClock()
	s := newTestService(t, t.TempDir(), "", clk)
	tok, _, err := s.Login("vlad", "pw", "curl/8", "1.2.3.4", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(tok, "", ""); err != nil {
		t.Fatalf("fresh token: %v", err)
	}
	parts := strings.Split(tok, "|")

	tampered := strings.Join([]string{"kid", parts[1], parts[2], parts[3]}, "|")
	for name, bad := range map[string]string{
		"empty":     "",
		"garbage":   "not-a-token",
		"tampered":  tampered,
		"bad sig":   strings.Join([]string{parts[0], parts[1], parts[2], strings.Repeat("0", 64)}, "|"),
		"extra":     tok + "|x",
		"truncated": strings.Join(parts[:3], "|"),
	} {
		if _, err := s.Authenticate(bad, "", ""); !errors.Is(err, ErrUnauthorized) {
			t.Errorf("%s: got %v, want ErrUnauthorized", name, err)
		}
	}

	clk.Advance(11 * 365 * 24 * time.Hour)
	if _, err := s.Authenticate(tok, "", ""); !errors.Is(err, ErrUnauthorized) {
		t.Errorf("expired token accepted: %v", err)
	}
}

func TestRemovedUserRejected(t *testing.T) {
	dir := t.TempDir()
	clk := newClock()
	s := newTestService(t, dir, "", clk, "vlad:pw", "bob:pw")
	tok, _, err := s.Login("bob", "pw", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	s2 := newTestService(t, dir, "", clk, "vlad:pw")
	if _, err := s2.Authenticate(tok, "", ""); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("removed user still authenticated: %v", err)
	}
	// Re-adding the user (even with a new password) restores the session:
	// passwords are only checked at login time.
	s3 := newTestService(t, dir, "", clk, "vlad:pw", "bob:other")
	if _, err := s3.Authenticate(tok, "", ""); err != nil {
		t.Fatalf("re-added user: %v", err)
	}
}

func TestRevokedSessions(t *testing.T) {
	dir := t.TempDir()
	clk := newClock()
	s := newTestService(t, dir, "", clk)
	tokA, a, _ := s.Login("vlad", "pw", "iPhone Safari/1", "", "")
	tokB, b, _ := s.Login("vlad", "pw", "Tesla/1", "", "")
	tokC, c, _ := s.Login("vlad", "pw", "Windows Edg/1", "", "")
	tokK, _, _ := s.Login("kid", "pw2", "", "", "")

	if err := s.Revoke("kid", a.ID); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("revoking another user's session: %v", err)
	}
	if err := s.Revoke("vlad", b.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(tokB, "", ""); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("revoked session authenticated: %v", err)
	}
	ids, err := s.RevokeOthers("vlad", a.ID)
	if err != nil || len(ids) != 1 || ids[0] != c.ID {
		t.Fatalf("RevokeOthers = %v, %v", ids, err)
	}
	if _, err := s.Authenticate(tokC, "", ""); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("RevokeOthers did not revoke")
	}
	if _, err := s.Authenticate(tokA, "", ""); err != nil {
		t.Fatalf("kept session rejected: %v", err)
	}
	if _, err := s.Authenticate(tokK, "", ""); err != nil {
		t.Fatalf("other user's session affected: %v", err)
	}

	// Revocation survives a restart.
	s2 := newTestService(t, dir, "", clk)
	if _, err := s2.Authenticate(tokB, "", ""); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("revocation lost after restart")
	}
	if list := s2.Sessions().List("vlad"); len(list) != 1 || list[0].ID != a.ID {
		t.Fatalf("List after restart = %+v", list)
	}
}

func TestSessionListRenameAndLastSeen(t *testing.T) {
	dir := t.TempDir()
	clk := newClock()
	s := newTestService(t, dir, "", clk)
	tokA, a, _ := s.Login("vlad", "pw", "", "1.1.1.1", "")
	clk.Advance(time.Minute)
	_, b, _ := s.Login("vlad", "pw", "", "2.2.2.2", "")
	clk.Advance(time.Minute)
	if _, err := s.Authenticate(tokA, "UA2", "3.3.3.3"); err != nil {
		t.Fatal(err)
	}
	list := s.Sessions().List("vlad")
	if len(list) != 2 || list[0].ID != a.ID || list[1].ID != b.ID {
		t.Fatalf("want a (most recent) then b, got %+v", list)
	}
	if list[0].IP != "3.3.3.3" || list[0].UA != "UA2" {
		t.Errorf("touch not applied: %+v", list[0])
	}
	if _, err := s.Sessions().Rename("vlad", b.ID, "Kitchen iPad"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Sessions().Rename("kid", b.ID, "x"); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("renaming other user's session: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s2 := newTestService(t, dir, "", clk)
	list = s2.Sessions().List("vlad")
	if list[0].IP != "3.3.3.3" || list[1].Name != "Kitchen iPad" {
		t.Fatalf("persisted sessions = %+v", list)
	}
}

func TestLoginRateLimitPerUser(t *testing.T) {
	clk := newClock()
	s := newTestService(t, t.TempDir(), "", clk)
	for i := range 10 {
		if _, _, err := s.Login("vlad", "wrong", "", "9.9.9."+strconv.Itoa(i), ""); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	_, _, err := s.Login("vlad", "pw", "", "8.8.8.8", "")
	var rl *RateLimitedError
	if !errors.As(err, &rl) || rl.RetryAfter <= 0 || rl.RetryAfter > time.Minute {
		t.Fatalf("11th attempt: %v, want rate limited ≤60s", err)
	}
	// Other users are unaffected.
	if _, _, err := s.Login("kid", "pw2", "", "8.8.8.8", ""); err != nil {
		t.Fatalf("other user blocked: %v", err)
	}
	clk.Advance(61 * time.Second)
	if _, _, err := s.Login("vlad", "pw", "", "8.8.8.8", ""); err != nil {
		t.Fatalf("after lockout: %v", err)
	}
	// Success reset the counter: a single new failure does not re-lock.
	if _, _, err := s.Login("vlad", "wrong", "", "8.8.8.8", ""); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("after reset: %v", err)
	}
	if _, _, err := s.Login("vlad", "pw", "", "8.8.8.8", ""); err != nil {
		t.Fatalf("counter not reset by success: %v", err)
	}
}

func TestLoginRateLimitPerIP(t *testing.T) {
	clk := newClock()
	s := newTestService(t, t.TempDir(), "", clk)
	for i := range 30 {
		// Unknown usernames: only the IP bucket counts.
		_, _, err := s.Login("guess"+strconv.Itoa(i), "x", "", "6.6.6.6", "")
		if !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	var rl *RateLimitedError
	if _, _, err := s.Login("vlad", "pw", "", "6.6.6.6", ""); !errors.As(err, &rl) || rl.RetryAfter > 5*time.Minute {
		t.Fatalf("IP not limited: %v", err)
	}
	if _, _, err := s.Login("vlad", "pw", "", "7.7.7.7", ""); err != nil {
		t.Fatalf("other IP blocked: %v", err)
	}
	clk.Advance(5*time.Minute + time.Second)
	if _, _, err := s.Login("vlad", "pw", "", "6.6.6.6", ""); err != nil {
		t.Fatalf("after IP lockout: %v", err)
	}
	if n := len(s.limiter.users); n > 1 {
		t.Errorf("unknown usernames tracked: %d buckets", n)
	}
}

func TestPairingFlow(t *testing.T) {
	clk := newClock()
	s := newTestService(t, t.TempDir(), "", clk)
	req, poll, err := s.StartPairing(teslaUA, "10.0.0.12")
	if err != nil {
		t.Fatal(err)
	}
	if len(req.Code) != 6 || strings.Trim(req.Code, pairCodeAlphabet) != "" {
		t.Fatalf("bad code %q", req.Code)
	}
	if len(poll) != 32 {
		t.Fatalf("bad poll token %q", poll)
	}
	if req.DeviceName != "Tesla" || req.ExpiresAt-req.CreatedAt != pairTTL.Milliseconds() {
		t.Fatalf("unexpected request %+v", req)
	}
	if st, _, _, _ := s.PollPairing(poll, teslaUA, "10.0.0.12", ""); st != PairPending {
		t.Fatalf("status = %s, want pending", st)
	}

	typed := strings.ToLower(req.Code[:3] + "-" + req.Code[3:])
	got, err := s.LookupPairing(" " + typed + " ")
	if err != nil || got.Code != req.Code || got.IP != "10.0.0.12" {
		t.Fatalf("lookup %q: %+v %v", typed, got, err)
	}
	if err := s.ApprovePairing(typed, "vlad", "  Family   Tesla "); err != nil {
		t.Fatal(err)
	}
	if err := s.ApprovePairing(req.Code, "kid", ""); !errors.Is(err, ErrPairingUsed) {
		t.Fatalf("double approve: %v", err)
	}

	st, tok, sess, err := s.PollPairing(poll, teslaUA, "10.0.0.12", "")
	if err != nil || st != PairApproved || tok == "" {
		t.Fatalf("poll = %s %q %v", st, tok, err)
	}
	if sess.User != "vlad" || sess.Name != "Family Tesla" {
		t.Fatalf("session = %+v", sess)
	}
	authed, err := s.Authenticate(tok, teslaUA, "10.0.0.12")
	if err != nil || authed.ID != sess.ID {
		t.Fatalf("paired token: %+v %v", authed, err)
	}
	// Single redemption.
	if st, tok, _, _ := s.PollPairing(poll, teslaUA, "", ""); st != PairExpired || tok != "" {
		t.Fatalf("second redemption: %s %q", st, tok)
	}
	if _, err := s.LookupPairing(req.Code); !errors.Is(err, ErrPairingNotFound) {
		t.Fatalf("redeemed code still visible: %v", err)
	}
}

func TestPairingDenyExpiryAndLimits(t *testing.T) {
	clk := newClock()
	s := newTestService(t, t.TempDir(), "", clk)

	// The approval screen shows a name derived from the User-Agent; the
	// requester cannot choose it.
	req, poll, _ := s.StartPairing(teslaUA, "1.1.1.1")
	if req.DeviceName != "Tesla" {
		t.Fatalf("device name = %q", req.DeviceName)
	}
	if err := s.DenyPairing(req.Code); err != nil {
		t.Fatal(err)
	}
	if st, tok, _, _ := s.PollPairing(poll, "", "", ""); st != PairDenied || tok != "" {
		t.Fatalf("denied poll = %s", st)
	}

	req, poll, _ = s.StartPairing("", "1.1.1.1")
	clk.Advance(pairTTL + time.Second)
	if st, _, _, _ := s.PollPairing(poll, "", "", ""); st != PairExpired {
		t.Fatalf("expired poll = %s", st)
	}
	if err := s.ApprovePairing(req.Code, "vlad", ""); !errors.Is(err, ErrPairingNotFound) {
		t.Fatalf("approving expired code: %v", err)
	}

	// Approval just before expiry stays redeemable for a grace period.
	req, poll, _ = s.StartPairing("", "1.1.1.1")
	clk.Advance(pairTTL - time.Second)
	if err := s.ApprovePairing(req.Code, "vlad", ""); err != nil {
		t.Fatal(err)
	}
	clk.Advance(30 * time.Second)
	if st, _, _, _ := s.PollPairing(poll, "", "", ""); st != PairApproved {
		t.Fatalf("grace redemption = %s", st)
	}

	for i := range maxPendingPerIP {
		if _, _, err := s.StartPairing("", "2.2.2.2"); err != nil {
			t.Fatalf("start %d: %v", i, err)
		}
	}
	if _, _, err := s.StartPairing("", "2.2.2.2"); !errors.Is(err, ErrTooManyPairings) {
		t.Fatalf("6th pending code: %v", err)
	}
	if _, _, err := s.StartPairing("", "3.3.3.3"); err != nil {
		t.Fatalf("other IP: %v", err)
	}
	clk.Advance(pairTTL)
	if _, _, err := s.StartPairing("", "2.2.2.2"); err != nil {
		t.Fatalf("after expiry: %v", err)
	}
}

func TestParseUsers(t *testing.T) {
	sum := sha256.Sum256([]byte("s3cret"))
	u, err := ParseUsers([]string{"mom:plain:with:colons", "dad:sha256:" + hex.EncodeToString(sum[:]), "mom:override"})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		user, pass string
		ok         bool
	}{
		{"mom", "override", true},
		{"mom", "plain:with:colons", false},
		{"dad", "s3cret", true},
		{"dad", "sha256:" + hex.EncodeToString(sum[:]), false},
		{"nobody", "", false},
	}
	for _, c := range cases {
		if got := u.Verify(c.user, c.pass); got != c.ok {
			t.Errorf("Verify(%q,%q) = %v", c.user, c.pass, got)
		}
	}
	if names := u.Names(); len(names) != 2 || names[0] != "dad" {
		t.Errorf("Names = %v", names)
	}
	for _, bad := range []string{"nopass", ":SECRET", "bad user:SECRET", "x|y:SECRET", "a:", "a:sha256:SECRET", strings.Repeat("a", 65) + ":SECRET"} {
		if _, err := ParseUsers([]string{bad}); err == nil {
			t.Errorf("ParseUsers(%q) accepted", bad)
		} else if strings.Contains(err.Error(), "SECRET") {
			t.Errorf("error leaks password: %v", err)
		}
	}

	// A password containing an entry separator is split into fragments;
	// the fragment without ':' must not be echoed, only its position.
	_, err = ParseUsers([]string{"dad:pw", "mom:correct", "horse"})
	if err == nil || strings.Contains(err.Error(), "horse") || !strings.Contains(err.Error(), "#3") {
		t.Errorf("fragment error = %v", err)
	}

	// The hash prefix is case-insensitive.
	for _, prefix := range []string{"SHA256:", "Sha256:"} {
		u, err := ParseUsers([]string{"mom:" + prefix + strings.ToUpper(hex.EncodeToString(sum[:]))})
		if err != nil || !u.Verify("mom", "s3cret") {
			t.Errorf("%s prefix: err=%v", prefix, err)
		}
	}
}

func TestMergeUsers(t *testing.T) {
	env := mustUsers(t, "mom:a", "dad:b")
	flags := mustUsers(t, "dad:c", "kid:d")
	u := env.Merge(flags)
	if names := u.Names(); strings.Join(names, ",") != "dad,kid,mom" {
		t.Fatalf("names = %v", names)
	}
	if !u.Verify("dad", "c") || u.Verify("dad", "b") || !u.Verify("mom", "a") {
		t.Fatal("later source must win")
	}
	if !env.Verify("dad", "b") {
		t.Fatal("Merge modified its receiver")
	}
}

func TestDeviceName(t *testing.T) {
	cases := map[string]string{
		teslaUA: "Tesla",
		"Mozilla/5.0 (X11; Linux) QtCarBrowser Safari/533.3":                                                           "Tesla",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Version/17.0 Mobile Safari/604.1": "iPhone · Safari",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 CriOS/120.0 Mobile Safari/604.1":  "iPhone · Chrome",
		"Mozilla/5.0 (iPad; CPU OS 16_0 like Mac OS X) AppleWebKit/605.1.15 Version/16.0 Mobile Safari/604.1":          "iPad · Safari",
		"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 Chrome/120.0 Mobile Safari/537.36":                "Android · Chrome",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/17.0 Safari/605.1.15":            "Mac · Safari",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36 Edg/120.0":            "Windows · Edge",
		"Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0":                                       "Linux · Firefox",
		"curl/8.5.0": "Unknown device",
		"":           "Unknown device",
	}
	for ua, want := range cases {
		if got := DeviceName(ua); got != want {
			t.Errorf("DeviceName(%q) = %q, want %q", ua, got, want)
		}
	}
}
