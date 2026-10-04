package store

import (
	"errors"
	"math"
	"slices"
)

// Settings are a user's playback and appearance preferences.
type Settings struct {
	SkipBack     int     `json:"skipBack"`     // seconds
	SkipForward  int     `json:"skipForward"`  // seconds
	DefaultSpeed float64 `json:"defaultSpeed"` // for books never played
	AutoRewind   bool    `json:"autoRewind"`   // smart rewind on resume
	Theme        string  `json:"theme"`        // "dark" | "light" | "auto"
}

// Allowed setting values.
var (
	skipChoices  = []int{5, 10, 15, 20, 30, 45, 60, 90}
	themeChoices = []string{"dark", "light", "auto"}
)

// Playback speed bounds.
const (
	MinSpeed = 0.5
	MaxSpeed = 3.5
)

// DefaultSettings returns the settings of a new user.
func DefaultSettings() Settings {
	return Settings{SkipBack: 15, SkipForward: 30, DefaultSpeed: 1.0, AutoRewind: true, Theme: "dark"}
}

// normalize replaces invalid values (e.g. from a hand-edited file) with
// defaults.
func (s *Settings) normalize() {
	d := DefaultSettings()
	if !slices.Contains(skipChoices, s.SkipBack) {
		s.SkipBack = d.SkipBack
	}
	if !slices.Contains(skipChoices, s.SkipForward) {
		s.SkipForward = d.SkipForward
	}
	if !validSpeed(s.DefaultSpeed) {
		s.DefaultSpeed = d.DefaultSpeed
	}
	if !slices.Contains(themeChoices, s.Theme) {
		s.Theme = d.Theme
	}
}

func validSpeed(v float64) bool { return v >= MinSpeed && v <= MaxSpeed }

func clampSpeed(v float64) float64 { return math.Min(MaxSpeed, math.Max(MinSpeed, v)) }

// Progress is a user's place in one book. The place is TrackPath +
// Position; TrackIndex and BookPosition are derived from the library index
// and re-derived when the book's files change (see reconcile).
type Progress struct {
	BookID       string  `json:"bookId"`
	Path         string  `json:"path"` // book path, for humans and re-linking
	TrackIndex   int     `json:"trackIndex"`
	TrackPath    string  `json:"trackPath"`
	TrackSize    int64   `json:"trackSize"`    // bytes; finds the file again after a folder rename
	Position     float64 `json:"position"`     // seconds within the track
	BookPosition float64 `json:"bookPosition"` // seconds from the start of the book
	Duration     float64 `json:"duration"`     // book duration snapshot
	Speed        float64 `json:"speed"`
	Finished     bool    `json:"finished"`
	FinishedAt   int64   `json:"finishedAt"` // ms, server clock
	StartedAt    int64   `json:"startedAt"`  // ms, server clock
	UpdatedAt    int64   `json:"updatedAt"`  // ms, server clock
	Listened     float64 `json:"listened"`   // wall-clock seconds listened
	ClientID     string  `json:"clientId"`   // last writer
}

// Bookmark is a saved position with an optional note. Like Progress, it is
// anchored to TrackPath (+ TrackSize for re-linking after renames).
type Bookmark struct {
	ID           string  `json:"id"`
	TrackIndex   int     `json:"trackIndex"`
	TrackPath    string  `json:"trackPath"`
	TrackSize    int64   `json:"trackSize"`
	Position     float64 `json:"position"`
	BookPosition float64 `json:"bookPosition"`
	Note         string  `json:"note"`
	CreatedAt    int64   `json:"createdAt"` // ms
}

// Stats aggregates listening time.
type Stats struct {
	// Days maps a local date ("2006-01-02") to seconds listened.
	Days map[string]float64 `json:"days"`
	// Total is all-time seconds listened (Days only keeps statsDays).
	Total float64 `json:"total"`
}

// dataVersion is the users/<name>.json schema version.
const dataVersion = 2

// UserData is the content of users/<name>.json.
type UserData struct {
	Version   int                   `json:"version"`
	Settings  Settings              `json:"settings"`
	Progress  map[string]*Progress  `json:"progress"`
	Bookmarks map[string][]Bookmark `json:"bookmarks"`
	Stats     Stats                 `json:"stats"`
	// LegacyPending marks a v1 state file that is waiting for the library
	// index before it can be migrated.
	LegacyPending bool `json:"legacyPending,omitempty"`
}

func newUserData() *UserData {
	d := &UserData{Version: dataVersion, Settings: DefaultSettings()}
	d.normalize()
	return d
}

func (d *UserData) normalize() {
	d.Version = dataVersion
	d.Settings.normalize()
	if d.Progress == nil {
		d.Progress = map[string]*Progress{}
	}
	for id, p := range d.Progress {
		if p == nil {
			delete(d.Progress, id)
		}
	}
	if d.Bookmarks == nil {
		d.Bookmarks = map[string][]Bookmark{}
	}
	if d.Stats.Days == nil {
		d.Stats.Days = map[string]float64{}
	}
}

// Errors returned for missing things; the HTTP layer maps them to 404.
var (
	ErrBookNotFound     = errors.New("book not found")
	ErrBookmarkNotFound = errors.New("bookmark not found")
	ErrNoProgress       = errors.New("no progress for this book")
)

// IsNotFound reports whether err means "no such resource".
func IsNotFound(err error) bool {
	return errors.Is(err, ErrBookNotFound) || errors.Is(err, ErrBookmarkNotFound) || errors.Is(err, ErrNoProgress)
}

// InputError reports an invalid request; the HTTP layer maps it to 400.
type InputError struct{ Msg string }

func (e *InputError) Error() string { return e.Msg }

func invalid(msg string) error { return &InputError{Msg: msg} }
