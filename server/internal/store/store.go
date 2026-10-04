// Package store keeps each user's progress, bookmarks, settings and
// listening stats in users/<name>.json (written atomically), and migrates
// BookBeam 1.x state on first use.
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/vburenin/bookbeam/server/internal/fsutil"
	"github.com/vburenin/bookbeam/server/internal/library"
)

// Options configure a Store.
type Options struct {
	// Dir holds users/<name>.json files.
	Dir string
	// LegacyDir is v1's <data>/state directory (read-only).
	LegacyDir string
	Logger    *slog.Logger
	// Now overrides the clock (tests).
	Now func() time.Time
}

// Store serialises access per user; different users never contend.
// Usernames must already be validated (they become file names).
type Store struct {
	opts Options
	log  *slog.Logger
	now  func() time.Time

	mu    sync.Mutex
	users map[string]*user

	subsMu sync.Mutex
	subs   []func(user string, changes []Change)
}

type user struct {
	mu     sync.Mutex
	name   string
	data   *UserData
	active activeClient
	// reconciled is the index version the data was last re-linked against
	// (and reconciledAt that index's scan time); see reconcileLocked.
	reconciled   string
	reconciledAt int64
}

// New creates a store rooted at opts.Dir.
func New(opts Options) (*Store, error) {
	if err := os.MkdirAll(opts.Dir, 0o700); err != nil {
		return nil, err
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Store{opts: opts, log: opts.Logger, now: opts.Now, users: map[string]*user{}}, nil
}

// StateView is a snapshot of a user's data for GET api/state.
type StateView struct {
	Settings   Settings              `json:"settings"`
	Progress   map[string]Progress   `json:"progress"`
	Bookmarks  map[string][]Bookmark `json:"bookmarks"`
	ServerTime int64                 `json:"serverTime"`
}

// State returns a copy of the user's settings, progress and bookmarks.
func (s *Store) State(name string, idx *library.Index) (StateView, error) {
	var v StateView
	err := s.withUser(name, idx, func(u *user) error {
		v.Settings = u.data.Settings
		v.Progress = copyProgress(u.data.Progress)
		v.Bookmarks = make(map[string][]Bookmark, len(u.data.Bookmarks))
		for id, bms := range u.data.Bookmarks {
			v.Bookmarks[id] = append([]Bookmark(nil), bms...)
		}
		v.ServerTime = s.now().UnixMilli()
		return nil
	})
	return v, err
}

// Subscribe registers fn to be told about changes the store makes on its
// own (see Change). fn runs while the user's data is locked, so that its
// events are ordered before those of the next request; it must not call
// back into the Store.
func (s *Store) Subscribe(fn func(user string, changes []Change)) {
	s.subsMu.Lock()
	defer s.subsMu.Unlock()
	s.subs = append(s.subs, fn)
}

func (s *Store) notify(user string, changes []Change) {
	if len(changes) == 0 {
		return
	}
	s.subsMu.Lock()
	subs := slices.Clone(s.subs)
	s.subsMu.Unlock()
	for _, fn := range subs {
		fn(user, changes)
	}
}

func (s *Store) userEntry(name string) *user {
	s.mu.Lock()
	defer s.mu.Unlock()
	u := s.users[name]
	if u == nil {
		u = &user{name: name}
		s.users[name] = u
	}
	return u
}

// withUser runs fn with the user's data loaded, brought up to date with
// idx (pending legacy migration, re-linking) and locked.
func (s *Store) withUser(name string, idx *library.Index, fn func(u *user) error) error {
	u := s.userEntry(name)
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.data == nil {
		d, err := s.load(name)
		if err != nil {
			return err
		}
		u.data = d
	}
	s.syncLocked(u, idx)
	return fn(u)
}

// syncLocked migrates pending v1 state and re-links saved places against
// idx, telling subscribers what changed. The caller holds u.mu.
func (s *Store) syncLocked(u *user, idx *library.Index) {
	var changes []Change
	if u.data.LegacyPending && idx.Len() > 0 {
		for _, p := range s.migrateLegacy(u, idx) {
			changes = append(changes, Change{Kind: ChangeProgress, BookID: p.BookID, Progress: &p})
		}
	}
	changes = append(changes, s.reconcileLocked(u, idx)...)
	s.notify(u.name, changes)
}

func (s *Store) path(name string) string {
	return filepath.Join(s.opts.Dir, name+".json")
}

func (s *Store) legacyPath(name string) string {
	if s.opts.LegacyDir == "" {
		return ""
	}
	return filepath.Join(s.opts.LegacyDir, name+".json")
}

// load reads a user's file. A missing file starts fresh (flagging a v1
// file for migration); a corrupt one is moved aside, never deleted.
func (s *Store) load(name string) (*UserData, error) {
	p := s.path(name)
	raw, err := os.ReadFile(p)
	if errors.Is(err, fs.ErrNotExist) {
		d := newUserData()
		if lp := s.legacyPath(name); lp != "" && fsutil.Exists(lp) {
			d.LegacyPending = true
		}
		return d, nil
	}
	if err != nil {
		return nil, err // I/O error: keep failing rather than risk overwriting
	}
	d := &UserData{}
	if err = json.Unmarshal(raw, d); err == nil {
		d.normalize()
		return d, nil
	}
	aside, rerr := fsutil.MoveAside(p, s.now())
	if rerr != nil {
		return nil, fmt.Errorf("%w (and could not move it aside: %v)", err, rerr)
	}
	s.log.Error("user data file was corrupt; moved aside and starting fresh", "user", name, "file", aside, "err", err)
	return newUserData(), nil
}

func (s *Store) save(u *user) error {
	if err := fsutil.WriteJSON(s.path(u.name), u.data, 0o600); err != nil {
		s.log.Error("saving user data", "user", u.name, "err", err)
		return err
	}
	return nil
}

// Reconcile brings every loaded user up to date with a new index (pending
// v1 migrations, re-linking places to moved files); subscribers are told
// about the changes. Users not loaded yet are handled lazily on their next
// request.
func (s *Store) Reconcile(idx *library.Index) {
	if idx.Len() == 0 {
		return
	}
	s.mu.Lock()
	users := make([]*user, 0, len(s.users))
	for _, u := range s.users {
		users = append(users, u)
	}
	s.mu.Unlock()

	for _, u := range users {
		u.mu.Lock()
		if u.data != nil {
			s.syncLocked(u, idx)
		}
		u.mu.Unlock()
	}
}

// copyProgress returns a detached copy of the user's progress map.
func copyProgress(m map[string]*Progress) map[string]Progress {
	out := make(map[string]Progress, len(m))
	for k, v := range m {
		out[k] = *v
	}
	return out
}
