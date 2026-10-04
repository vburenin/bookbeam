package store

import (
	"fmt"
	"math"
	"time"

	"github.com/vburenin/bookbeam/server/internal/library"
)

// Progress events sent by clients.
const (
	EventTick     = "tick"
	EventPlay     = "play"
	EventPause    = "pause"
	EventSeek     = "seek"
	EventTrack    = "track"
	EventSpeed    = "speed"
	EventEnded    = "ended"
	EventFinished = "finished"
)

var validEvents = map[string]bool{
	EventTick: true, EventPlay: true, EventPause: true, EventSeek: true,
	EventTrack: true, EventSpeed: true, EventEnded: true, EventFinished: true,
}

const (
	// maxListenedPerReport caps the listening time one report may add
	// (clients report every 15 s; this tolerates delayed/queued reports).
	maxListenedPerReport = 120
	// nearEndWindow: positions this close to the end don't "unfinish".
	nearEndWindow = 60
	// activeStaleAfter: a playing client that stopped reporting for this
	// long no longer counts as the active player.
	activeStaleAfter = 90 * time.Second
	maxClientIDLen   = 64
	maxTZOffset      = 16 * 60
)

// ProgressUpdate is the body of PUT api/progress/{bookId}.
type ProgressUpdate struct {
	TrackIndex int `json:"trackIndex"`
	// TrackPath, when it names a track of the book, is authoritative over
	// TrackIndex (a client's index may predate a change to the book's files).
	TrackPath    string   `json:"trackPath"`
	Position     float64  `json:"position"`
	BookPosition *float64 `json:"bookPosition"`
	Speed        float64  `json:"speed"`
	Playing      bool     `json:"playing"`
	ClientID     string   `json:"clientId"`
	Listened     float64  `json:"listened"`
	TZOffset     int      `json:"tzOffset"` // minutes, JS getTimezoneOffset() semantics
	Event        string   `json:"event"`
	Unfinish     bool     `json:"unfinish"` // explicit "listen again"
}

// ProgressResult is the outcome of a progress update.
type ProgressResult struct {
	Progress Progress
	// ActiveClient is the client currently playing for this user ("" if none).
	ActiveClient string
	// ClaimedPlayback is set when this update was a "play" that made the
	// sender the active client (other devices should be told to pause).
	ClaimedPlayback bool
}

// activeClient tracks which of a user's clients is playing (in memory).
type activeClient struct {
	id   string
	seen time.Time
}

func (a activeClient) current(now time.Time) string {
	if a.id == "" || now.Sub(a.seen) > activeStaleAfter {
		return ""
	}
	return a.id
}

// UpdateProgress applies a playback report.
func (s *Store) UpdateProgress(name string, idx *library.Index, bookID string, upd ProgressUpdate) (ProgressResult, error) {
	b := idx.Book(bookID)
	if b == nil {
		return ProgressResult{}, ErrBookNotFound
	}
	if upd.Event == "" {
		upd.Event = EventTick
	}
	if !validEvents[upd.Event] {
		return ProgressResult{}, invalid(fmt.Sprintf("unknown event %q", upd.Event))
	}
	upd.TrackIndex = trackIndexOf(idx, b, upd.TrackPath, upd.TrackIndex)
	if upd.TrackIndex < 0 || upd.TrackIndex >= len(b.Tracks) {
		return ProgressResult{}, invalid("trackIndex out of range")
	}
	if len(upd.ClientID) > maxClientIDLen {
		upd.ClientID = upd.ClientID[:maxClientIDLen]
	}
	if upd.TZOffset < -maxTZOffset || upd.TZOffset > maxTZOffset {
		upd.TZOffset = 0
	}

	var res ProgressResult
	err := s.withUser(name, idx, func(u *user) error {
		now := s.now()
		ms := now.UnixMilli()
		p := u.data.Progress[bookID]
		if p == nil {
			p = &Progress{BookID: bookID, Speed: u.data.Settings.DefaultSpeed}
			u.data.Progress[bookID] = p
		}
		track := b.Tracks[upd.TrackIndex]
		pos := math.Max(0, upd.Position)
		p.Path = b.Path
		p.TrackIndex = upd.TrackIndex
		p.TrackPath = track.Path
		p.TrackSize = track.Size
		p.Position = pos
		p.BookPosition = bookPosition(b, upd.TrackIndex, pos, upd.BookPosition)
		p.Duration = b.Duration
		if upd.Speed > 0 {
			p.Speed = clampSpeed(upd.Speed)
		}
		if p.StartedAt == 0 {
			p.StartedAt = ms
		}
		p.UpdatedAt = ms
		p.ClientID = upd.ClientID

		switch {
		case upd.Event == EventFinished:
			p.Finished = true
			p.FinishedAt = ms
		case upd.Unfinish && p.Finished && !nearEnd(p.BookPosition, p.Duration):
			p.Finished = false
			p.FinishedAt = 0
		}

		if secs := math.Min(maxListenedPerReport, math.Max(0, upd.Listened)); secs > 0 {
			p.Listened += secs
			u.data.Stats.add(localDate(now, upd.TZOffset), secs)
		}

		res.ClaimedPlayback = u.trackActive(upd, now)
		res.ActiveClient = u.active.current(now)
		res.Progress = *p
		return s.save(u)
	})
	return res, err
}

// trackIndexOf resolves a client's track reference: the track at trackPath
// when that is a file of book b, else the given index.
func trackIndexOf(idx *library.Index, b *library.Book, trackPath string, index int) int {
	if trackPath != "" {
		if tb, ti, ok := idx.TrackByPath(trackPath); ok && tb.ID == b.ID {
			return ti
		}
	}
	return index
}

// trackActive updates the user's active (playing) client and reports
// whether this update explicitly claimed playback.
func (u *user) trackActive(upd ProgressUpdate, now time.Time) bool {
	id := upd.ClientID
	if id == "" {
		return false
	}
	switch {
	case upd.Event == EventPlay:
		u.active = activeClient{id: id, seen: now}
		return true
	case upd.Event == EventPause || upd.Event == EventEnded || upd.Event == EventFinished || !upd.Playing:
		if u.active.id == id {
			u.active = activeClient{}
		}
	case u.active.id == id:
		u.active.seen = now
	case u.active.current(now) == "":
		// Playing without having announced it (its "play" report was lost):
		// adopt it, since nobody else is playing.
		u.active = activeClient{id: id, seen: now}
	}
	return false
}

// ActiveClient returns the user's currently playing client id, or "".
func (s *Store) ActiveClient(name string) string {
	s.mu.Lock()
	u := s.users[name]
	s.mu.Unlock()
	if u == nil {
		return ""
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.active.current(s.now())
}

// bookPosition is the offset from the start of the book. The server's
// own track offsets are authoritative when every preceding track has a
// known duration; otherwise (unprobeable files) the client's figure, which
// is based on durations the player discovered, is used when given.
func bookPosition(b *library.Book, track int, pos float64, client *float64) float64 {
	for i := range track {
		if b.Tracks[i].Duration <= 0 {
			if client != nil && *client >= 0 {
				return *client
			}
			break
		}
	}
	return b.Tracks[track].Start + pos
}

func nearEnd(bookPos, duration float64) bool {
	return duration > 0 && bookPos >= duration-nearEndWindow
}

// SetFinished marks a book finished or not finished (keeping the
// position). Marking a never-played book finished creates its progress.
func (s *Store) SetFinished(name string, idx *library.Index, bookID string, finished bool) (Progress, error) {
	var out Progress
	err := s.withUser(name, idx, func(u *user) error {
		ms := s.now().UnixMilli()
		p := u.data.Progress[bookID]
		if p == nil {
			b := idx.Book(bookID)
			if b == nil {
				return ErrBookNotFound
			}
			if !finished {
				return ErrNoProgress
			}
			p = &Progress{
				BookID:    bookID,
				Path:      b.Path,
				TrackPath: b.Tracks[0].Path,
				TrackSize: b.Tracks[0].Size,
				Duration:  b.Duration,
				Speed:     u.data.Settings.DefaultSpeed,
				StartedAt: ms,
			}
			u.data.Progress[bookID] = p
		}
		p.Finished = finished
		p.FinishedAt = 0
		if finished {
			p.FinishedAt = ms
		}
		p.UpdatedAt = ms
		out = *p
		return s.save(u)
	})
	return out, err
}

// DeleteProgress forgets a book's progress (it becomes "not started").
func (s *Store) DeleteProgress(name string, idx *library.Index, bookID string) error {
	return s.withUser(name, idx, func(u *user) error {
		if _, ok := u.data.Progress[bookID]; !ok {
			return nil
		}
		delete(u.data.Progress, bookID)
		return s.save(u)
	})
}
