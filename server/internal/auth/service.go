// Package auth implements BookBeam's logins, v1-compatible signed session
// tokens, the session registry, login rate limiting and device pairing.
package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/vburenin/bookbeam/server/internal/fsutil"
)

var (
	// ErrUnauthorized means the token is missing, malformed, forged,
	// expired, revoked, or belongs to a user that no longer exists.
	ErrUnauthorized = errors.New("unauthorized")
	// ErrInvalidCredentials means the username/password pair is wrong.
	ErrInvalidCredentials = errors.New("invalid username or password")
)

// RateLimitedError is returned by Login while the caller is locked out.
type RateLimitedError struct{ RetryAfter time.Duration }

func (e *RateLimitedError) Error() string {
	return fmt.Sprintf("too many failed attempts; retry in %s", e.RetryAfter.Round(time.Second))
}

// Config configures a Service.
type Config struct {
	// StateDir holds secret.key and sessions.json.
	StateDir string
	// LegacySecretPath is v1's <data>/session_secret, copied on first start.
	LegacySecretPath string
	Users            *Users
	Logger           *slog.Logger
	// Now overrides the clock (tests).
	Now func() time.Time
}

// Service ties together credentials, tokens, sessions, rate limiting and
// pairing. It is safe for concurrent use.
type Service struct {
	users    *Users
	signer   signer
	sessions *Registry
	limiter  *rateLimiter
	pairing  *pairing
	log      *slog.Logger
	now      func() time.Time
}

// NewService loads (or creates) the signing key and session registry.
func NewService(cfg Config) (*Service, error) {
	if cfg.Users == nil {
		return nil, errors.New("auth: no users configured")
	}
	log := cfg.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	if err := os.MkdirAll(cfg.StateDir, 0o755); err != nil {
		return nil, err
	}

	// The legacy v1 key is adopted only on the very first start, recognised
	// by the absence of sessions.json (and its backup). Afterwards, deleting
	// secret.key really does sign everyone out instead of resurrecting the
	// v1 key.
	sessionsPath := filepath.Join(cfg.StateDir, "sessions.json")
	firstStart := !fsutil.Exists(sessionsPath) && !fsutil.Exists(sessionsPath+".bak")
	secret, migrated, err := loadSecret(filepath.Join(cfg.StateDir, "secret.key"), cfg.LegacySecretPath, firstStart)
	if err != nil {
		return nil, fmt.Errorf("session key: %w", err)
	}
	if migrated {
		log.Info("adopted legacy v1 session key; existing sign-ins stay valid", "from", cfg.LegacySecretPath)
	}
	reg, err := openRegistry(sessionsPath, log, now())
	if err != nil {
		return nil, fmt.Errorf("sessions: %w", err)
	}
	return &Service{
		users:    cfg.Users,
		signer:   signer{secret: secret},
		sessions: reg,
		limiter:  newRateLimiter(),
		pairing:  newPairing(),
		log:      log,
		now:      now,
	}, nil
}

// Sessions exposes the session registry for listing/renaming/revoking.
func (s *Service) Sessions() *Registry { return s.sessions }

// Run performs periodic background work (batched session writes) until ctx
// is cancelled.
func (s *Service) Run(ctx context.Context) { s.sessions.run(ctx) }

// Close flushes pending session updates.
func (s *Service) Close() error { return s.sessions.Flush() }

// Authenticate validates a cookie token and records the activity. Tokens
// minted by v1 (unknown nonces) are adopted into the registry.
func (s *Service) Authenticate(token, ua, ip string) (Session, error) {
	now := s.now()
	user, nonce, exp, err := s.signer.verify(token, now)
	if err != nil || !s.users.Exists(user) {
		return Session{}, ErrUnauthorized
	}
	sess, ok := s.sessions.get(nonce)
	switch {
	case !ok:
		// A v1 cookie: its issue time is exactly ten years before expiry.
		sess = Session{
			ID:        nonce,
			User:      user,
			Name:      DeviceName(ua),
			UA:        ua,
			IP:        ip,
			CreatedAt: exp.AddDate(-tokenYears, 0, 0).UnixMilli(),
			LastSeen:  now.UnixMilli(),
			Exp:       exp.Unix(),
		}
		if err := s.sessions.add(sess); err != nil {
			s.log.Error("registering legacy session", "user", user, "err", err)
		} else {
			s.log.Info("registered legacy v1 session", "user", user, "device", sess.Name)
		}
		return sess, nil
	case sess.Revoked() || sess.User != user:
		return Session{}, ErrUnauthorized
	}
	s.sessions.touch(nonce, ip, ua, exp.Unix(), now)
	sess.LastSeen, sess.IP, sess.UA = now.UnixMilli(), ip, ua
	if sess.Exp == 0 {
		sess.Exp = exp.Unix()
	}
	return sess, nil
}

// Login checks credentials (subject to rate limiting) and, on success,
// signs the user in on device (the ab_device cookie; see IssueSession).
func (s *Service) Login(username, password, ua, ip, device string) (token string, sess Session, err error) {
	now := s.now()
	limitKey := ""
	if s.users.Exists(username) {
		limitKey = username
	}
	if wait := s.limiter.check(limitKey, ip, now); wait > 0 {
		return "", Session{}, &RateLimitedError{RetryAfter: wait}
	}
	if !s.users.Verify(username, password) {
		s.limiter.fail(limitKey, ip, now)
		s.log.Warn("failed login", "user", username, "ip", ip)
		return "", Session{}, ErrInvalidCredentials
	}
	s.limiter.succeed(username)
	return s.IssueSession(username, "", ua, ip, device)
}

// IssueSession signs user in on device and returns the session token.
// Other users' sessions on the device are left alone (they stay available
// for switching). If user already has a session there, it is reused and
// its token minted again, so repeated sign-ins do not pile up duplicates.
// name defaults to one derived from ua (new sessions) or the existing name.
func (s *Service) IssueSession(user, name, ua, ip, device string) (string, Session, error) {
	now := s.now()
	if prev, ok := s.deviceSession(device, user, now); ok {
		sess, err := s.sessions.reuse(prev.ID, name, ua, ip, now)
		switch {
		case err == nil:
			return s.signer.mint(sess.User, sess.Exp, sess.ID), sess, nil
		case !errors.Is(err, ErrSessionNotFound):
			return "", Session{}, err
		}
		// Revoked in the meantime: sign in afresh.
	}
	if name == "" {
		name = DeviceName(ua)
	}
	token, nonce, exp, err := s.signer.issue(user, now)
	if err != nil {
		return "", Session{}, err
	}
	sess := Session{
		ID:        nonce,
		User:      user,
		Name:      name,
		UA:        ua,
		IP:        ip,
		CreatedAt: now.UnixMilli(),
		LastSeen:  now.UnixMilli(),
		Device:    device,
		Exp:       exp.Unix(),
	}
	if err := s.sessions.add(sess); err != nil {
		return "", Session{}, err
	}
	return token, sess, nil
}

// switchable reports whether a session's token can be minted again and
// still be accepted.
func (s *Service) switchable(sess Session, now time.Time) bool {
	return !sess.Revoked() && sess.Exp > now.Unix() && s.users.Exists(sess.User)
}

// deviceSession finds user's most recently used switchable session on
// device.
func (s *Service) deviceSession(device, user string, now time.Time) (Session, bool) {
	for _, sess := range s.sessions.onDevice(device) {
		if sess.User == user && s.switchable(sess, now) {
			return sess, true
		}
	}
	return Session{}, false
}

// DeviceAccounts lists the accounts signed in on device: one session per
// user (the most recently used), most recently used first.
func (s *Service) DeviceAccounts(device string) []Session {
	now := s.now()
	seen := map[string]bool{}
	var out []Session
	for _, sess := range s.sessions.onDevice(device) {
		if !seen[sess.User] && s.switchable(sess, now) {
			seen[sess.User] = true
			out = append(out, sess)
		}
	}
	return out
}

// LinkDevice records that a session lives in device (sessions created
// before devices were tracked are linked on their next visit). A session
// already linked to a device keeps it.
func (s *Service) LinkDevice(sessionID, device string) error {
	if !ValidDeviceID(device) {
		return errors.New("invalid device id")
	}
	return s.sessions.linkDevice(sessionID, device)
}

// SwitchAccount returns the token of user's session on device, for making
// it the browser's current session. ErrSessionNotFound means user is not
// signed in there.
func (s *Service) SwitchAccount(device, user string) (string, Session, error) {
	sess, ok := s.deviceSession(device, user, s.now())
	if !ok {
		return "", Session{}, ErrSessionNotFound
	}
	return s.signer.mint(sess.User, sess.Exp, sess.ID), sess, nil
}

// SignOut revokes the current session and picks the account the device
// should continue with: the most recently used other user signed in on
// the same device. ok is false when there is none (the device is now
// signed out).
func (s *Service) SignOut(cur Session, device string) (next Session, token string, ok bool, err error) {
	now := s.now()
	if err := s.sessions.Revoke(cur.User, cur.ID, now); err != nil && !errors.Is(err, ErrSessionNotFound) {
		return Session{}, "", false, err
	}
	if device == "" || (cur.Device != "" && cur.Device != device) {
		return Session{}, "", false, nil
	}
	for _, sess := range s.sessions.onDevice(device) {
		if sess.User != cur.User && s.switchable(sess, now) {
			return sess, s.signer.mint(sess.User, sess.Exp, sess.ID), true, nil
		}
	}
	return Session{}, "", false, nil
}

// Revoke signs out one of user's sessions.
func (s *Service) Revoke(user, id string) error { return s.sessions.Revoke(user, id, s.now()) }

// RevokeOthers signs out all of user's sessions except keep.
func (s *Service) RevokeOthers(user, keep string) ([]string, error) {
	return s.sessions.RevokeOthers(user, keep, s.now())
}

// StartPairing creates a pairing code for an unauthenticated device. The
// name shown to the approver is derived from the device's User-Agent, never
// taken from the (unauthenticated) request, so a stranger cannot dress a
// pairing request up as "Dad's Tesla"; the approver can still pick a name.
func (s *Service) StartPairing(ua, ip string) (PairRequest, string, error) {
	return s.pairing.start(DeviceName(ua), ua, ip, s.now())
}

// LookupPairing returns a live pairing request by its (user-typed) code.
func (s *Service) LookupPairing(code string) (PairRequest, error) {
	return s.pairing.lookup(code, s.now())
}

// ApprovePairing lets user sign the device in under the chosen name (the
// device's own name when empty).
func (s *Service) ApprovePairing(code, user, name string) error {
	name = CleanName(name)
	if name == "" {
		req, err := s.pairing.lookup(code, s.now())
		if err != nil {
			return err
		}
		name = req.DeviceName
	}
	return s.pairing.decide(code, user, name, s.now())
}

// DenyPairing rejects a pending pairing request.
func (s *Service) DenyPairing(code string) error {
	return s.pairing.decide(code, "", "", s.now())
}

// PollPairing reports the status of a pairing request. When it is approved
// (once per poll token) the polling device is signed in (see IssueSession)
// and the session token returned.
func (s *Service) PollPairing(pollToken, ua, ip, device string) (status, token string, sess Session, err error) {
	status, approval := s.pairing.poll(pollToken, s.now())
	if status != PairApproved {
		return status, "", Session{}, nil
	}
	if !s.users.Exists(approval.User) {
		return PairDenied, "", Session{}, nil
	}
	token, sess, err = s.IssueSession(approval.User, approval.Name, ua, ip, device)
	if err != nil {
		return "", "", Session{}, err
	}
	s.log.Info("device paired", "user", approval.User, "device", approval.Name, "ip", ip)
	return PairApproved, token, sess, nil
}

// CleanName trims a user-supplied device name and bounds its length.
func CleanName(name string) string {
	name = strings.Join(strings.Fields(name), " ")
	if r := []rune(name); len(r) > MaxSessionNameLen {
		name = string(r[:MaxSessionNameLen])
	}
	return name
}
