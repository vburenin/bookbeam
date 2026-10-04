package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/vburenin/bookbeam/server/internal/fsutil"
)

// Session is one signed-in browser. Its ID is the token nonce.
type Session struct {
	ID        string `json:"-"`
	User      string `json:"user"`
	Name      string `json:"name"`
	UA        string `json:"ua"`
	IP        string `json:"ip"`
	CreatedAt int64  `json:"createdAt"` // ms since epoch
	LastSeen  int64  `json:"lastSeen"`  // ms since epoch
	RevokedAt int64  `json:"revokedAt"` // ms since epoch; 0 = active
	// Device is the ab_device cookie of the browser the session lives in;
	// sessions sharing it can be switched between ("Who's listening?").
	Device string `json:"device,omitempty"`
	// Exp is the token's expiry (unix seconds). Tokens are deterministic,
	// so with it the session's token can be minted again when switching
	// listeners. 0 for sessions not seen since before it was recorded.
	Exp int64 `json:"exp,omitempty"`
}

// Revoked reports whether the session was signed out.
func (s Session) Revoked() bool { return s.RevokedAt > 0 }

// ErrSessionNotFound is returned for unknown (or other users') sessions.
var ErrSessionNotFound = errors.New("session not found")

// lastSeenFlushInterval bounds how often lastSeen-only changes hit the disk.
const lastSeenFlushInterval = 2 * time.Minute

// MaxSessionNameLen bounds user-chosen device names.
const MaxSessionNameLen = 64

// Registry is the persistent set of sessions (sessions.json), keyed by nonce.
// Structural changes (create, rename, revoke, device link) are written
// immediately; lastSeen/ip updates are batched and flushed periodically and
// on Close.
//
// Before each write the previous version is kept as sessions.json.bak, so a
// sessions.json damaged by a crash on a file system that does not honour
// fsync (NAS shares) costs at most the last change instead of a server that
// refuses to start.
type Registry struct {
	path string
	bak  string
	log  *slog.Logger

	mu       sync.Mutex
	sessions map[string]*Session
	dirty    bool
	saved    []byte // content of the last successful write (or load)
}

// errCorrupt marks a registry file that exists but cannot be decoded.
var errCorrupt = errors.New("corrupt session registry")

// decodeRegistry parses a sessions.json image.
func decodeRegistry(raw []byte) (map[string]*Session, error) {
	var stored map[string]*Session
	if err := json.Unmarshal(raw, &stored); err != nil {
		return nil, errors.Join(errCorrupt, err)
	}
	out := make(map[string]*Session, len(stored))
	for id, s := range stored {
		if s == nil || id == "" {
			continue
		}
		s.ID = id
		out[id] = s
	}
	return out, nil
}

// readRegistry loads one registry file. It returns fs.ErrNotExist for a
// missing file and errCorrupt for one that cannot be decoded.
func readRegistry(path string) (map[string]*Session, []byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	m, err := decodeRegistry(raw)
	return m, raw, err
}

// openRegistry loads sessions.json, falling back to its backup when the
// file is missing or damaged. Only when neither is usable does it start
// empty: validly signed tokens are then re-registered on their next use, so
// devices stay signed in, but earlier sign-outs may be forgotten. I/O errors
// (as opposed to damaged content) are returned: refusing to start is safer
// than silently forgetting every sign-out.
func openRegistry(path string, log *slog.Logger, now time.Time) (*Registry, error) {
	r := &Registry{path: path, bak: path + ".bak", log: log, sessions: map[string]*Session{}}

	m, raw, err := readRegistry(path)
	switch {
	case err == nil:
		r.sessions, r.saved = m, raw
		return r, nil
	case errors.Is(err, errCorrupt):
		aside, merr := fsutil.MoveAside(path, now)
		if merr != nil {
			return nil, errors.Join(err, merr)
		}
		log.Error("sessions.json is damaged; moved it aside", "file", aside, "err", err)
	case !errors.Is(err, fs.ErrNotExist):
		return nil, err
	}
	primaryMissing := errors.Is(err, fs.ErrNotExist)

	bm, braw, berr := readRegistry(r.bak)
	switch {
	case berr == nil:
		r.sessions = bm
		r.saved = braw
		log.Warn("restored sessions from backup; changes made just before the damage may be lost",
			"from", r.bak, "sessions", len(bm))
	case errors.Is(berr, errCorrupt):
		aside, merr := fsutil.MoveAside(r.bak, now)
		if merr != nil {
			return nil, errors.Join(berr, merr)
		}
		log.Error("sessions backup is damaged too; moved it aside", "file", aside, "err", berr)
		r.logStartingEmpty()
	case errors.Is(berr, fs.ErrNotExist):
		if !primaryMissing {
			r.logStartingEmpty()
		}
		// Otherwise this is the first start: write the empty registry so its
		// presence marks the state directory as initialised (see NewService).
	default:
		return nil, berr
	}
	if err := r.saveLocked(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *Registry) logStartingEmpty() {
	r.log.Error("starting with an empty session list: signed-in devices stay signed in " +
		"(they are re-registered on their next visit), but devices signed out earlier may " +
		"be able to sign back in. To sign out every device, stop BookBeam, delete " +
		"secret.key in the state directory and start it again.")
}

// get returns a copy of the session with the given id.
func (r *Registry) get(id string) (Session, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.sessions[id]
	if !ok {
		return Session{}, false
	}
	return *s, true
}

// add registers a new session and persists the registry.
func (r *Registry) add(s Session) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := s
	r.sessions[s.ID] = &cp
	return r.saveLocked()
}

// touch records activity on a session (in memory; flushed later). It also
// backfills the token expiry of sessions created before it was recorded.
func (r *Registry) touch(id, ip, ua string, exp int64, now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.sessions[id]
	if !ok {
		return
	}
	s.LastSeen = now.UnixMilli()
	if ip != "" {
		s.IP = ip
	}
	if ua != "" {
		s.UA = ua
	}
	if s.Exp == 0 {
		s.Exp = exp
	}
	r.dirty = true
}

// linkDevice records the browser a session lives in, unless it is already
// linked (a session never moves between devices).
func (r *Registry) linkDevice(id, device string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.sessions[id]
	if !ok || s.Revoked() {
		return ErrSessionNotFound
	}
	if s.Device != "" {
		return nil
	}
	s.Device = device
	return r.saveLocked()
}

// List returns user's active sessions, most recently seen first.
func (r *Registry) List(user string) []Session {
	return r.collect(func(s *Session) bool { return s.User == user })
}

// onDevice returns the active sessions linked to device, most recently
// seen first.
func (r *Registry) onDevice(device string) []Session {
	if device == "" {
		return nil
	}
	return r.collect(func(s *Session) bool { return s.Device == device })
}

// collect returns the active sessions matching keep, most recent first.
func (r *Registry) collect(keep func(*Session) bool) []Session {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []Session
	for _, s := range r.sessions {
		if !s.Revoked() && keep(s) {
			out = append(out, *s)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].LastSeen != out[j].LastSeen {
			return out[i].LastSeen > out[j].LastSeen
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// Rename sets the display name of one of user's active sessions.
func (r *Registry) Rename(user, id, name string) (Session, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.sessions[id]
	if !ok || s.User != user || s.Revoked() {
		return Session{}, ErrSessionNotFound
	}
	s.Name = name
	return *s, r.saveLocked()
}

// reuse marks an existing session as freshly signed in again (a repeated
// sign-in on the same device), optionally renaming it.
func (r *Registry) reuse(id, name, ua, ip string, now time.Time) (Session, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.sessions[id]
	if !ok || s.Revoked() {
		return Session{}, ErrSessionNotFound
	}
	if name != "" {
		s.Name = name
	}
	s.LastSeen = now.UnixMilli()
	if ua != "" {
		s.UA = ua
	}
	if ip != "" {
		s.IP = ip
	}
	return *s, r.saveLocked()
}

// Revoke signs out one of user's sessions.
func (r *Registry) Revoke(user, id string, now time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.sessions[id]
	if !ok || s.User != user || s.Revoked() {
		return ErrSessionNotFound
	}
	s.RevokedAt = now.UnixMilli()
	return r.saveLocked()
}

// RevokeOthers signs out all of user's sessions except keep and returns the
// ids it revoked.
func (r *Registry) RevokeOthers(user, keep string, now time.Time) ([]string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var ids []string
	for id, s := range r.sessions {
		if s.User == user && id != keep && !s.Revoked() {
			s.RevokedAt = now.UnixMilli()
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return nil, nil
	}
	sort.Strings(ids)
	return ids, r.saveLocked()
}

// Flush writes pending lastSeen updates.
func (r *Registry) Flush() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.dirty {
		return nil
	}
	return r.saveLocked()
}

// run flushes batched updates every lastSeenFlushInterval until ctx ends.
func (r *Registry) run(ctx context.Context) {
	t := time.NewTicker(lastSeenFlushInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := r.Flush(); err != nil {
				r.log.Error("saving sessions", "err", err)
			}
		}
	}
}

// saveLocked writes the registry, first preserving the previous (known
// good) version as the backup.
func (r *Registry) saveLocked() error {
	data, err := fsutil.MarshalJSON(r.sessions)
	if err != nil {
		return err
	}
	if r.saved != nil && !bytes.Equal(r.saved, data) {
		if err := fsutil.WriteFileAtomic(r.bak, r.saved, 0o600); err != nil {
			// The backup is a safety net; failing to refresh it must not
			// block sign-ins.
			r.log.Warn("cannot update sessions backup", "file", r.bak, "err", err)
		}
	}
	if err := fsutil.WriteFileAtomic(r.path, data, 0o600); err != nil {
		return err
	}
	r.saved = data
	r.dirty = false
	return nil
}
