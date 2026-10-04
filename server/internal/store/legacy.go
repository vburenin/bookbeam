package store

import (
	"encoding/json"
	"net/url"
	"os"
	"sort"
	"strings"

	"github.com/vburenin/bookbeam/server/internal/library"
)

// legacyState is the subset of BookBeam 1.x's state/<user>.json we migrate.
type legacyState struct {
	// CurrentURL is the library-relative path of the track being played.
	CurrentURL   string  `json:"currentUrl"`
	CurrentTime  float64 `json:"currentTime"`
	PlaybackRate float64 `json:"playbackRate"`
	// Listened holds percent-encoded media URLs such as
	// "/media/Expanse/Book%201/01.mp3" (possibly with a URL prefix).
	Listened []string `json:"listened"`
}

// legacyFinishedSkew dates other migrated books one minute before the
// current book so "Continue listening" keeps the v1 current book on top.
const legacyFinishedSkew = 60_000

// migrateLegacy converts the user's v1 state into progress entries (only
// for books without progress yet) and clears the pending flag. It is
// best-effort: unreadable or unmatched legacy data is logged and skipped.
// The caller holds u.mu. It returns the progress entries it created.
func (s *Store) migrateLegacy(u *user, idx *library.Index) []Progress {
	path := s.legacyPath(u.name)
	created := s.legacyProgress(u, path, idx)
	u.data.LegacyPending = false
	if err := s.save(u); err != nil {
		// Keep the flag so the migration is retried later.
		u.data.LegacyPending = true
		return nil
	}
	return created
}

func (s *Store) legacyProgress(u *user, path string, idx *library.Index) []Progress {
	raw, err := os.ReadFile(path)
	if err != nil {
		s.log.Warn("cannot read legacy v1 state", "user", u.name, "err", err)
		return nil
	}
	st, err := os.Stat(path)
	if err != nil {
		return nil
	}
	var ls legacyState
	if err := json.Unmarshal(raw, &ls); err != nil {
		s.log.Warn("ignoring malformed legacy v1 state", "user", u.name, "err", err)
		return nil
	}
	mtime := st.ModTime().UnixMilli()
	speed := u.data.Settings.DefaultSpeed
	if validSpeed(ls.PlaybackRate) {
		speed = ls.PlaybackRate
		if u.data.Settings.DefaultSpeed == DefaultSettings().DefaultSpeed {
			u.data.Settings.DefaultSpeed = ls.PlaybackRate
		}
	}

	migrated := map[string]*Progress{}
	if b, ti, ok := lookupLegacyTrack(idx, ls.CurrentURL); ok {
		migrated[b.ID] = legacyEntry(b, ti, max(0, ls.CurrentTime), speed, mtime)
	}

	listened := map[string]map[int]bool{}
	for _, entry := range ls.Listened {
		if b, ti, ok := lookupLegacyTrack(idx, entry); ok {
			if listened[b.ID] == nil {
				listened[b.ID] = map[int]bool{}
			}
			listened[b.ID][ti] = true
		}
	}
	for id, tracks := range listened {
		if migrated[id] != nil {
			continue
		}
		b := idx.Book(id)
		at := mtime - legacyFinishedSkew
		if len(tracks) == len(b.Tracks) {
			p := legacyEntry(b, 0, 0, speed, at)
			p.Finished, p.FinishedAt = true, at
			migrated[id] = p
			continue
		}
		highest := 0
		for ti := range tracks {
			highest = max(highest, ti)
		}
		migrated[id] = legacyEntry(b, highest, 0, speed, at)
	}

	var created []Progress
	for id, p := range migrated {
		if _, exists := u.data.Progress[id]; exists {
			continue // progress made in v2 wins
		}
		u.data.Progress[id] = p
		created = append(created, *p)
	}
	sort.Slice(created, func(i, j int) bool { return created[i].Path < created[j].Path })
	s.log.Info("migrated legacy v1 state", "user", u.name, "books", len(created), "defaultSpeed", u.data.Settings.DefaultSpeed)
	return created
}

func legacyEntry(b *library.Book, track int, pos, speed float64, at int64) *Progress {
	return &Progress{
		BookID:       b.ID,
		Path:         b.Path,
		TrackIndex:   track,
		TrackPath:    b.Tracks[track].Path,
		Position:     pos,
		BookPosition: b.Tracks[track].Start + pos,
		Duration:     b.Duration,
		Speed:        speed,
		StartedAt:    at,
		UpdatedAt:    at,
	}
}

// lookupLegacyTrack resolves a v1 reference to an indexed track. v1 stored
// the current track as a plain library-relative path ("Kids/media/Story/
// 02.mp3") and listened tracks as percent-encoded media URLs
// ("/media/Kids/media/Story/02.mp3", possibly behind a URL prefix, which
// may itself be "/media", or as absolute URLs). Every reading is tried:
// the reference as a path, and whatever follows each "/media/" in it, so
// a library folder named "media" cannot confuse the lookup. URL-shaped
// references try the media-URL readings first, plain paths themselves.
func lookupLegacyTrack(idx *library.Index, ref string) (*library.Book, int, bool) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return nil, 0, false
	}
	var urlReadings []string
	for i := 0; ; {
		j := strings.Index(ref[i:], "/media/")
		if j < 0 {
			break
		}
		urlReadings = append(urlReadings, ref[i+j+len("/media/"):])
		i += j + len("/media") // the next match may start at this one's last "/"
	}
	asPath := strings.TrimPrefix(ref, "/")
	candidates := append([]string{asPath}, urlReadings...)
	if strings.HasPrefix(ref, "/") || strings.Contains(ref, "://") {
		candidates = append(urlReadings, asPath)
	}
	for _, c := range candidates {
		if b, ti, ok := idx.TrackByPath(c); ok {
			return b, ti, true
		}
		if dec, err := url.PathUnescape(c); err == nil && dec != c {
			if b, ti, ok := idx.TrackByPath(strings.TrimPrefix(dec, "/")); ok {
				return b, ti, true
			}
		}
	}
	return nil, 0, false
}
