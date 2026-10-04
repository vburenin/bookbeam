package auth

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const (
	carDevice   = "0123456789abcdef0123456789abcdef"
	phoneDevice = "fedcba9876543210fedcba9876543210"
)

func TestDeviceIDs(t *testing.T) {
	id, err := NewDeviceID()
	if err != nil || !ValidDeviceID(id) {
		t.Fatalf("NewDeviceID = %q, %v", id, err)
	}
	if other, _ := NewDeviceID(); other == id {
		t.Fatal("device ids repeat")
	}
	for _, bad := range []string{"", "xyz", carDevice[:31], carDevice + "0", "0123456789ABCDEF0123456789ABCDEF", "0123456789abcdef0123456789abcdeg"} {
		if ValidDeviceID(bad) {
			t.Errorf("ValidDeviceID(%q) = true", bad)
		}
	}
}

// A family shares the car: several people sign in on it, the car can switch
// between them, and signing out hands the car to the next listener.
func TestSharedDeviceAccounts(t *testing.T) {
	dir := t.TempDir()
	clk := newClock()
	s := newTestService(t, dir, "", clk, "vlad:pw", "kid:pw2", "mom:pw3")

	dadTok, dad, err := s.Login("vlad", "pw", teslaUA, "10.0.0.12", carDevice)
	if err != nil {
		t.Fatal(err)
	}
	if dad.Device != carDevice || dad.Exp != clk.Now().AddDate(tokenYears, 0, 0).Unix() {
		t.Fatalf("session = %+v", dad)
	}
	clk.Advance(time.Minute)

	// The kid is added on the car through pairing; dad stays signed in.
	req, poll, _ := s.StartPairing(teslaUA, "10.0.0.12")
	if err := s.ApprovePairing(req.Code, "kid", "Car"); err != nil {
		t.Fatal(err)
	}
	_, kidTok, kid, err := s.PollPairing(poll, teslaUA, "10.0.0.12", carDevice)
	if err != nil || kid.Device != carDevice {
		t.Fatalf("pairing: %+v %v", kid, err)
	}
	if _, err := s.Authenticate(dadTok, teslaUA, ""); err != nil {
		t.Fatalf("adding a listener signed dad out: %v", err)
	}
	clk.Advance(time.Minute)
	if _, err := s.Authenticate(kidTok, teslaUA, ""); err != nil { // the kid listens now
		t.Fatal(err)
	}
	// Mom signs in elsewhere: not an account of the car.
	if _, _, err := s.Login("mom", "pw3", "", "", phoneDevice); err != nil {
		t.Fatal(err)
	}

	accounts := s.DeviceAccounts(carDevice)
	if len(accounts) != 2 || accounts[0].User != "kid" || accounts[1].User != "vlad" {
		t.Fatalf("car accounts = %+v", accounts)
	}
	if got := s.DeviceAccounts(""); len(got) != 0 {
		t.Fatalf("accounts without a device = %+v", got)
	}

	// Switching re-mints the very token the session was issued.
	tok, sess, err := s.SwitchAccount(carDevice, "vlad")
	if err != nil || tok != dadTok || sess.ID != dad.ID {
		t.Fatalf("switch to vlad = %q %+v %v (want %q)", tok, sess, err, dadTok)
	}
	if _, _, err := s.SwitchAccount(carDevice, "mom"); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("switch to an account of another device: %v", err)
	}
	if _, _, err := s.SwitchAccount(phoneDevice, "kid"); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("switch from another device: %v", err)
	}

	// Signing in again as the same user on the same device reuses the
	// session instead of piling up duplicates.
	clk.Advance(time.Minute)
	againTok, again, err := s.Login("kid", "pw2", teslaUA, "10.0.0.13", carDevice)
	if err != nil || again.ID != kid.ID || againTok != kidTok || again.Name != "Car" {
		t.Fatalf("repeated sign-in = %+v %v", again, err)
	}
	if n := len(s.Sessions().List("kid")); n != 1 {
		t.Fatalf("kid has %d sessions", n)
	}

	// Signing out the kid hands the car to dad.
	cur, _ := s.Authenticate(kidTok, teslaUA, "")
	next, nextTok, ok, err := s.SignOut(cur, carDevice)
	if err != nil || !ok || next.User != "vlad" || nextTok != dadTok {
		t.Fatalf("SignOut(kid) = %+v %q %v %v", next, nextTok, ok, err)
	}
	if _, err := s.Authenticate(kidTok, teslaUA, ""); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("signed-out session still valid")
	}
	cur, _ = s.Authenticate(dadTok, teslaUA, "")
	if _, _, ok, err := s.SignOut(cur, carDevice); ok || err != nil {
		t.Fatalf("last account signed out: ok=%v err=%v", ok, err)
	}
	if got := s.DeviceAccounts(carDevice); len(got) != 0 {
		t.Fatalf("accounts after everyone signed out = %+v", got)
	}

	// Device links and expiries survive a restart.
	_, carol, _ := s.Login("mom", "pw3", "", "", carDevice)
	s2 := newTestService(t, dir, "", clk, "vlad:pw", "kid:pw2", "mom:pw3")
	if tok, sess, err := s2.SwitchAccount(carDevice, "mom"); err != nil || sess.ID != carol.ID || tok == "" {
		t.Fatalf("after restart: %+v %v", sess, err)
	}
	// Removed users cannot be switched to.
	s3 := newTestService(t, dir, "", clk, "vlad:pw", "kid:pw2")
	if _, _, err := s3.SwitchAccount(carDevice, "mom"); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("switch to removed user: %v", err)
	}
}

// Sessions created before devices and expiries were recorded get them on
// their next visit and then become switchable.
func TestOldSessionsAreLinkedLater(t *testing.T) {
	dir := t.TempDir()
	clk := newClock()
	s := newTestService(t, dir, "", clk)
	tok, sess, err := s.Login("vlad", "pw", teslaUA, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	// Strip the new fields, as in a sessions.json written by 2.0.
	path := filepath.Join(dir, "sessions.json")
	var raw map[string]map[string]any
	b, _ := os.ReadFile(path)
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	for _, v := range raw {
		delete(v, "device")
		delete(v, "exp")
	}
	b, _ = json.Marshal(raw)
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}

	s = newTestService(t, dir, "", clk)
	if _, _, err := s.SwitchAccount(carDevice, "vlad"); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("unlinked session switchable: %v", err)
	}
	authed, err := s.Authenticate(tok, teslaUA, "")
	if err != nil || authed.Exp == 0 || authed.Device != "" {
		t.Fatalf("Authenticate = %+v %v", authed, err)
	}
	if err := s.LinkDevice(sess.ID, "not-a-device"); err == nil {
		t.Fatal("invalid device id accepted")
	}
	if err := s.LinkDevice(sess.ID, carDevice); err != nil {
		t.Fatal(err)
	}
	// A linked session keeps its device.
	if err := s.LinkDevice(sess.ID, phoneDevice); err != nil {
		t.Fatal(err)
	}
	if got, _, err := s.SwitchAccount(carDevice, "vlad"); err != nil || got != tok {
		t.Fatalf("switch after linking = %q %v", got, err)
	}
}
