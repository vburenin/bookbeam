package store

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vburenin/bookbeam/server/internal/library"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func book(path string, durations ...float64) *library.Book {
	b := &library.Book{ID: library.BookID(path), Path: path, Title: filepath.Base(path)}
	var start float64
	for i, d := range durations {
		name := path + "/" + string(rune('a'+i)) + ".mp3"
		b.Tracks = append(b.Tracks, library.Track{Path: name, Duration: d, Start: start})
		start += d
	}
	b.Duration = start
	return b
}

func singleBook(path string, dur float64) *library.Book {
	return &library.Book{
		ID: library.BookID(path), Path: path, Duration: dur,
		Tracks: []library.Track{{Path: path, Duration: dur}},
	}
}

var (
	leviathan = func() *library.Book {
		b := book("Expanse/Leviathan Wakes", 100, 200, 300)
		for i, n := range []string{"01 - Chapter 1.mp3", "02 - Chapter 2.mp3", "03 - Chapter 3.mp3"} {
			b.Tracks[i].Path = b.Path + "/" + n
		}
		return b
	}()
	martian = singleBook("Single Books/The Martian.m4b", 900)
	pooh    = func() *library.Book {
		d := make([]float64, 12)
		for i := range d {
			d[i] = 75
		}
		b := book("Kids/Winnie-the-Pooh", d...)
		for i := range b.Tracks {
			b.Tracks[i].Path = b.Path + "/Chapter " + strconv.Itoa(i+1) + ".opus"
		}
		return b
	}()
	weird  = singleBook("Weird #Name? 100%/part 1 – intro.wav", 45)
	broken = book("Broken", 0, 50)
)

func testIndex() *library.Index {
	return library.NewIndex([]*library.Book{leviathan, martian, pooh, weird, broken}, 1)
}

type fixture struct {
	*Store
	clk   *clock
	dir   string
	idx   *library.Index
	state string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	root := t.TempDir()
	f := &fixture{
		clk:   &clock{t: time.Date(2026, 10, 3, 3, 0, 0, 0, time.UTC)},
		dir:   filepath.Join(root, "users"),
		state: filepath.Join(root, "legacy"),
		idx:   testIndex(),
	}
	f.reopen(t)
	return f
}

func (f *fixture) reopen(t *testing.T) {
	t.Helper()
	s, err := New(Options{Dir: f.dir, LegacyDir: f.state, Now: f.clk.Now})
	if err != nil {
		t.Fatal(err)
	}
	f.Store = s
}

func (f *fixture) put(t *testing.T, bookID string, u ProgressUpdate) ProgressResult {
	t.Helper()
	res, err := f.UpdateProgress("vlad", f.idx, bookID, u)
	if err != nil {
		t.Fatalf("UpdateProgress(%+v): %v", u, err)
	}
	return res
}

func ptr(v float64) *float64 { return &v }

func TestProgressValidation(t *testing.T) {
	f := newFixture(t)
	if _, err := f.UpdateProgress("vlad", f.idx, "b_missing", ProgressUpdate{}); !errors.Is(err, ErrBookNotFound) {
		t.Errorf("unknown book: %v", err)
	}
	var in *InputError
	if _, err := f.UpdateProgress("vlad", f.idx, leviathan.ID, ProgressUpdate{Event: "rewind"}); !errors.As(err, &in) {
		t.Errorf("bad event: %v", err)
	}
	for _, ti := range []int{-1, 3} {
		if _, err := f.UpdateProgress("vlad", f.idx, leviathan.ID, ProgressUpdate{TrackIndex: ti}); !errors.As(err, &in) {
			t.Errorf("trackIndex %d: %v", ti, err)
		}
	}
}

func TestProgressPutSemantics(t *testing.T) {
	f := newFixture(t)
	t0 := f.clk.Now().UnixMilli()

	res := f.put(t, leviathan.ID, ProgressUpdate{
		TrackIndex: 1, Position: 50, BookPosition: ptr(9999), ClientID: "phone",
		Listened: 12.5, TZOffset: 420, Event: "tick", Playing: true,
	})
	p := res.Progress
	if p.BookID != leviathan.ID || p.Path != leviathan.Path || p.TrackPath != leviathan.Tracks[1].Path || p.Duration != 600 {
		t.Errorf("index fields not filled: %+v", p)
	}
	if p.BookPosition != 150 {
		t.Errorf("bookPosition = %v, want server-computed 150", p.BookPosition)
	}
	if p.Speed != 1.0 || p.StartedAt != t0 || p.UpdatedAt != t0 || p.Listened != 12.5 || p.ClientID != "phone" {
		t.Errorf("progress = %+v", p)
	}

	// Listened is clamped to 0..120 per report; startedAt sticks.
	f.clk.Advance(time.Minute)
	p = f.put(t, leviathan.ID, ProgressUpdate{TrackIndex: 1, Position: 60, Listened: 500, TZOffset: -420, Speed: 10}).Progress
	if p.Listened != 132.5 || p.StartedAt != t0 || p.UpdatedAt != t0+60_000 || p.Speed != 3.5 {
		t.Errorf("after clamp: %+v", p)
	}
	p = f.put(t, leviathan.ID, ProgressUpdate{TrackIndex: 1, Position: -5, Listened: -30, Speed: 0.1}).Progress
	if p.Listened != 132.5 || p.Position != 0 || p.Speed != 0.5 {
		t.Errorf("negative inputs: %+v", p)
	}
	p = f.put(t, leviathan.ID, ProgressUpdate{TrackIndex: 1, Position: 1}).Progress
	if p.Speed != 0.5 {
		t.Errorf("speed 0 must keep the previous speed, got %v", p.Speed)
	}

	// Stats day bucketing by the client's timezone: 03:00Z is still
	// Oct 2 at UTC-7 (offset 420) but already Oct 3 at UTC+7 (-420).
	f.Store.mu.Lock()
	days := f.users["vlad"].data.Stats.Days
	f.Store.mu.Unlock()
	if days["2026-10-02"] != 12.5 || days["2026-10-03"] != 120 || len(days) != 2 {
		t.Errorf("stats days = %v", days)
	}

	// A track whose predecessors have unknown durations trusts the client.
	p = f.put(t, broken.ID, ProgressUpdate{TrackIndex: 1, Position: 10, BookPosition: ptr(70)}).Progress
	if p.BookPosition != 70 {
		t.Errorf("unknown-duration bookPosition = %v, want client's 70", p.BookPosition)
	}
	p = f.put(t, broken.ID, ProgressUpdate{TrackIndex: 1, Position: 10}).Progress
	if p.BookPosition != 10 {
		t.Errorf("fallback bookPosition = %v", p.BookPosition)
	}
}

func TestFinishedRules(t *testing.T) {
	f := newFixture(t)
	p := f.put(t, leviathan.ID, ProgressUpdate{TrackIndex: 2, Position: 299, Event: "finished"}).Progress
	if !p.Finished || p.FinishedAt != f.clk.Now().UnixMilli() {
		t.Fatalf("finished event: %+v", p)
	}
	f.clk.Advance(time.Second)
	// Ordinary reports leave the flag alone, even from the start.
	p = f.put(t, leviathan.ID, ProgressUpdate{TrackIndex: 0, Position: 5, Event: "seek"}).Progress
	if !p.Finished {
		t.Fatal("seek without unfinish cleared finished")
	}
	// "unfinish" inside the last 60 s of the book is ignored.
	p = f.put(t, leviathan.ID, ProgressUpdate{TrackIndex: 2, Position: 250, Event: "play", Unfinish: true}).Progress
	if !p.Finished {
		t.Fatal("unfinish near the end cleared finished")
	}
	p = f.put(t, leviathan.ID, ProgressUpdate{TrackIndex: 0, Position: 0, Event: "play", Unfinish: true}).Progress
	if p.Finished || p.FinishedAt != 0 {
		t.Fatalf("explicit listen-again: %+v", p)
	}
}

func TestActiveClient(t *testing.T) {
	f := newFixture(t)
	play := func(client, event string, playing bool) ProgressResult {
		return f.put(t, leviathan.ID, ProgressUpdate{ClientID: client, Event: event, Playing: playing})
	}
	if r := play("A", "play", true); !r.ClaimedPlayback || r.ActiveClient != "A" {
		t.Fatalf("A play: %+v", r)
	}
	if r := play("B", "tick", true); r.ClaimedPlayback || r.ActiveClient != "A" {
		t.Fatalf("B tick while A active: %+v", r)
	}
	if r := play("B", "play", true); !r.ClaimedPlayback || r.ActiveClient != "B" {
		t.Fatalf("B play: %+v", r)
	}
	if r := play("A", "tick", true); r.ActiveClient != "B" {
		t.Fatalf("A must learn B is active: %+v", r)
	}
	if r := play("A", "pause", false); r.ActiveClient != "B" {
		t.Fatalf("A pausing must not clear B: %+v", r)
	}
	if got := f.ActiveClient("vlad"); got != "B" {
		t.Fatalf("ActiveClient = %q", got)
	}
	if r := play("B", "pause", false); r.ActiveClient != "" {
		t.Fatalf("B pause: %+v", r)
	}
	// A client that stopped reporting goes stale and can be replaced
	// silently by one that is playing.
	play("C", "play", true)
	f.clk.Advance(activeStaleAfter + time.Second)
	if got := f.ActiveClient("vlad"); got != "" {
		t.Fatalf("stale active client still reported: %q", got)
	}
	if r := play("D", "tick", true); r.ClaimedPlayback || r.ActiveClient != "D" {
		t.Fatalf("adopting a playing client: %+v", r)
	}
	if got := f.ActiveClient("kid"); got != "" {
		t.Fatalf("other user sees active client %q", got)
	}
}

func TestSetFinishedAndDelete(t *testing.T) {
	f := newFixture(t)
	if _, err := f.SetFinished("vlad", f.idx, "b_missing", true); !errors.Is(err, ErrBookNotFound) {
		t.Errorf("unknown book: %v", err)
	}
	if _, err := f.SetFinished("vlad", f.idx, martian.ID, false); !errors.Is(err, ErrNoProgress) {
		t.Errorf("unfinish never-played: %v", err)
	}
	p, err := f.SetFinished("vlad", f.idx, martian.ID, true)
	if err != nil || !p.Finished || p.FinishedAt == 0 || p.TrackPath != martian.Path || p.Duration != 900 {
		t.Fatalf("mark finished: %+v %v", p, err)
	}

	f.put(t, leviathan.ID, ProgressUpdate{TrackIndex: 1, Position: 42})
	f.SetFinished("vlad", f.idx, leviathan.ID, true)
	p, _ = f.SetFinished("vlad", f.idx, leviathan.ID, false)
	if p.Finished || p.FinishedAt != 0 || p.TrackIndex != 1 || p.Position != 42 {
		t.Fatalf("mark unfinished must keep position: %+v", p)
	}

	if err := f.DeleteProgress("vlad", f.idx, leviathan.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.DeleteProgress("vlad", f.idx, leviathan.ID); err != nil {
		t.Fatalf("delete is idempotent: %v", err)
	}
	f.reopen(t)
	st, _ := f.State("vlad", f.idx)
	if _, ok := st.Progress[leviathan.ID]; ok || !st.Progress[martian.ID].Finished {
		t.Fatalf("persisted state = %+v", st.Progress)
	}
}

func TestBookmarksCRUD(t *testing.T) {
	f := newFixture(t)
	bm1, all, err := f.AddBookmark("vlad", f.idx, leviathan.ID, NewBookmark{TrackIndex: 2, Position: 10, Note: "  later  "})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(bm1.ID, "k") || len(bm1.ID) != 11 || bm1.BookPosition != 310 || bm1.Note != "later" || bm1.CreatedAt == 0 {
		t.Fatalf("bookmark = %+v", bm1)
	}
	bm2, all, _ := f.AddBookmark("vlad", f.idx, leviathan.ID, NewBookmark{Position: 5})
	if len(all) != 2 || all[0].ID != bm2.ID || all[1].ID != bm1.ID {
		t.Fatalf("bookmarks not ordered by position: %+v", all)
	}

	var in *InputError
	if _, _, err := f.AddBookmark("vlad", f.idx, leviathan.ID, NewBookmark{TrackIndex: 5}); !errors.As(err, &in) {
		t.Errorf("bad track: %v", err)
	}
	if _, _, err := f.AddBookmark("vlad", f.idx, leviathan.ID, NewBookmark{Note: strings.Repeat("x", maxNoteLen+1)}); !errors.As(err, &in) {
		t.Errorf("long note: %v", err)
	}
	if _, _, err := f.AddBookmark("vlad", f.idx, "b_missing", NewBookmark{}); !errors.Is(err, ErrBookNotFound) {
		t.Errorf("unknown book: %v", err)
	}

	upd, all, err := f.UpdateBookmark("vlad", f.idx, leviathan.ID, bm1.ID, "the storm")
	if err != nil || upd.Note != "the storm" || all[1].Note != "the storm" {
		t.Fatalf("update: %+v %v", upd, err)
	}
	if _, _, err := f.UpdateBookmark("vlad", f.idx, leviathan.ID, "knope", ""); !errors.Is(err, ErrBookmarkNotFound) {
		t.Errorf("update unknown: %v", err)
	}
	if _, _, err := f.UpdateBookmark("kid", f.idx, leviathan.ID, bm1.ID, ""); !errors.Is(err, ErrBookmarkNotFound) {
		t.Errorf("other user's bookmark: %v", err)
	}

	all, err = f.DeleteBookmark("vlad", f.idx, leviathan.ID, bm2.ID)
	if err != nil || len(all) != 1 || all[0].ID != bm1.ID {
		t.Fatalf("delete: %+v %v", all, err)
	}
	if _, err := f.DeleteBookmark("vlad", f.idx, leviathan.ID, bm2.ID); !errors.Is(err, ErrBookmarkNotFound) {
		t.Errorf("double delete: %v", err)
	}

	f.reopen(t)
	st, _ := f.State("vlad", f.idx)
	if got := st.Bookmarks[leviathan.ID]; len(got) != 1 || got[0].Note != "the storm" {
		t.Fatalf("persisted bookmarks: %+v", got)
	}
	all, _ = f.DeleteBookmark("vlad", f.idx, leviathan.ID, bm1.ID)
	if all == nil || len(all) != 0 {
		t.Fatalf("empty list must be non-nil: %#v", all)
	}
}

func TestSettingsValidation(t *testing.T) {
	f := newFixture(t)
	patch := func(js string) (Settings, error) {
		var m map[string]json.RawMessage
		if err := json.Unmarshal([]byte(js), &m); err != nil {
			t.Fatal(err)
		}
		return f.PatchSettings("vlad", f.idx, m)
	}
	st, err := patch(`{"skipBack":10,"theme":"light","autoRewind":false,"defaultSpeed":1.25}`)
	want := Settings{SkipBack: 10, SkipForward: 30, DefaultSpeed: 1.25, AutoRewind: false, Theme: "light"}
	if err != nil || st != want {
		t.Fatalf("patch = %+v %v", st, err)
	}
	for _, bad := range []string{
		`{"skipBack":7}`, `{"skipForward":"30"}`, `{"theme":"neon"}`, `{"defaultSpeed":4}`,
		`{"defaultSpeed":0.25}`, `{"autoRewind":"yes"}`, `{"volume":1}`,
		`{"skipBack":5,"theme":"neon"}`, // all-or-nothing
	} {
		var in *InputError
		if _, err := patch(bad); !errors.As(err, &in) {
			t.Errorf("%s accepted (%v)", bad, err)
		}
	}
	f.reopen(t)
	if got, _ := f.State("vlad", f.idx); got.Settings != want {
		t.Fatalf("settings after invalid patches = %+v", got.Settings)
	}
}

func TestStats(t *testing.T) {
	f := newFixture(t)
	// The clock is 2026-10-03 03:00Z; at UTC (tzOffset 0) "today" is Oct 3.
	f.Store.withUser("vlad", f.idx, func(u *user) error {
		u.data.Stats.Days = map[string]float64{
			"2025-01-01": 999, // pruned on the next write (> 400 days old)
			"2026-09-27": 60,
			"2026-09-30": 100,
			"2026-10-01": 200,
			"2026-10-02": 300,
		}
		u.data.Stats.Total = 1659
		return nil
	})
	v, err := f.Stats("vlad", f.idx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if v.Today != 0 || v.Streak != 3 || v.Total != 1659 {
		t.Errorf("before listening today: %+v", v)
	}
	f.put(t, leviathan.ID, ProgressUpdate{Listened: 30})
	f.SetFinished("vlad", f.idx, martian.ID, true)
	f.put(t, pooh.ID, ProgressUpdate{Listened: 0})

	v, _ = f.Stats("vlad", f.idx, 0)
	if v.Today != 30 || v.Streak != 4 || v.Total != 1689 || v.BooksFinished != 1 || v.BooksInProgress != 2 {
		t.Errorf("stats = %+v", v)
	}
	wantWeek := []DayStat{
		{"2026-09-27", 60}, {"2026-09-28", 0}, {"2026-09-29", 0}, {"2026-09-30", 100},
		{"2026-10-01", 200}, {"2026-10-02", 300}, {"2026-10-03", 30},
	}
	if len(v.Week) != 7 {
		t.Fatalf("week = %+v", v.Week)
	}
	for i, d := range wantWeek {
		if v.Week[i] != d {
			t.Errorf("week[%d] = %+v, want %+v", i, v.Week[i], d)
		}
	}
	f.Store.withUser("vlad", f.idx, func(u *user) error {
		if _, ok := u.data.Stats.Days["2025-01-01"]; ok {
			t.Error("old day not pruned")
		}
		return nil
	})
	// At UTC-12 (tzOffset 720) it is still Oct 2.
	if v, _ := f.Stats("vlad", f.idx, 720); v.Today != 300 {
		t.Errorf("tz -12h today = %v", v.Today)
	}
}

const legacyV1 = `{
  "currentUrl": "Expanse/Leviathan Wakes/03 - Chapter 3.mp3",
  "currentSrc": "http://localhost:8080/media/Expanse/Leviathan%20Wakes/03%20-%20Chapter%203.mp3",
  "currentTime": 123.5,
  "playbackRate": 1.5,
  "currentTrackIndex": 2,
  "expandedStates": {"Audiobooks/Expanse": true},
  "listened": [
    "/media/Expanse/Leviathan%20Wakes/01%20-%20Chapter%201.mp3",
    "/media/Expanse/Leviathan%20Wakes/02%20-%20Chapter%202.mp3",
    "/books/media/Single%20Books/The%20Martian.m4b",
    "/media/Kids/Winnie-the-Pooh/Chapter%201.opus",
    "/media/Kids/Winnie-the-Pooh/Chapter%202.opus",
    "/media/Weird%20%23Name%3F%20100%25/part%201%20%E2%80%93%20intro.wav",
    "/media/Gone/Missing.mp3"
  ]
}`

func writeLegacy(t *testing.T, f *fixture, user, content string) time.Time {
	t.Helper()
	if err := os.MkdirAll(f.state, 0o755); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(f.state, user+".json")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	mtime := time.Date(2026, 9, 1, 8, 0, 0, 0, time.UTC)
	if err := os.Chtimes(p, mtime, mtime); err != nil {
		t.Fatal(err)
	}
	return mtime
}

func TestLegacyMigration(t *testing.T) {
	f := newFixture(t)
	mtime := writeLegacy(t, f, "vlad", legacyV1).UnixMilli()

	st, err := f.State("vlad", f.idx)
	if err != nil {
		t.Fatal(err)
	}
	if st.Settings.DefaultSpeed != 1.5 {
		t.Errorf("defaultSpeed = %v", st.Settings.DefaultSpeed)
	}
	cur := st.Progress[leviathan.ID]
	if cur.TrackIndex != 2 || cur.Position != 123.5 || cur.BookPosition != 423.5 || cur.Speed != 1.5 ||
		cur.UpdatedAt != mtime || cur.Finished || cur.TrackPath != leviathan.Tracks[2].Path {
		t.Errorf("current book: %+v", cur)
	}
	if m := st.Progress[martian.ID]; !m.Finished || m.UpdatedAt != mtime-60_000 || m.FinishedAt != mtime-60_000 {
		t.Errorf("fully listened book: %+v", m)
	}
	if w := st.Progress[weird.ID]; !w.Finished {
		t.Errorf("percent-encoded special characters: %+v", w)
	}
	if p := st.Progress[pooh.ID]; p.Finished || p.TrackIndex != 1 || p.Position != 0 || p.UpdatedAt != mtime-60_000 {
		t.Errorf("partly listened book: %+v", p)
	}
	if len(st.Progress) != 4 {
		t.Errorf("progress entries = %d: %+v", len(st.Progress), st.Progress)
	}

	// Migration happens once: forgetting progress must stick.
	f.DeleteProgress("vlad", f.idx, pooh.ID)
	f.reopen(t)
	st, _ = f.State("vlad", f.idx)
	if _, ok := st.Progress[pooh.ID]; ok || len(st.Progress) != 3 {
		t.Errorf("migration repeated: %+v", st.Progress)
	}
	if b, _ := os.ReadFile(filepath.Join(f.state, "vlad.json")); string(b) != legacyV1 {
		t.Error("legacy file modified")
	}
	// Users without a legacy file start empty.
	if st, _ := f.State("kid", f.idx); len(st.Progress) != 0 || st.Settings != DefaultSettings() {
		t.Errorf("kid state = %+v", st)
	}
}

func TestLegacyMigrationWaitsForIndex(t *testing.T) {
	f := newFixture(t)
	writeLegacy(t, f, "vlad", legacyV1)
	empty := library.NewIndex(nil, 0)

	st, _ := f.State("vlad", empty)
	if len(st.Progress) != 0 {
		t.Fatalf("migrated against an empty index: %+v", st.Progress)
	}
	// A write before the index exists persists the pending flag.
	if _, err := f.PatchSettings("vlad", empty, map[string]json.RawMessage{"theme": json.RawMessage(`"auto"`)}); err != nil {
		t.Fatal(err)
	}
	f.reopen(t)
	rec := f.record()
	f.State("vlad", empty)
	f.Reconcile(f.idx)
	if got := rec.take("vlad"); len(got) != 4 || got[0].Kind != ChangeProgress || got[0].Progress == nil {
		t.Fatalf("Reconcile changes = %+v", got)
	}
	st, _ = f.State("vlad", f.idx)
	if len(st.Progress) != 4 || st.Settings.Theme != "auto" || st.Settings.DefaultSpeed != 1.5 {
		t.Fatalf("after deferred migration: %+v", st)
	}
	f.Reconcile(f.idx)
	if again := rec.take("vlad"); len(again) != 0 {
		t.Fatalf("migrated twice: %+v", again)
	}
}

func TestLegacyMigrationKeepsV2Progress(t *testing.T) {
	f := newFixture(t)
	writeLegacy(t, f, "vlad", legacyV1)
	data := newUserData()
	data.LegacyPending = true
	data.Settings.DefaultSpeed = 1.1
	data.Progress[leviathan.ID] = &Progress{BookID: leviathan.ID, TrackIndex: 0, Position: 7, UpdatedAt: 42}
	b, _ := json.Marshal(data)
	if err := os.MkdirAll(f.dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.dir, "vlad.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	st, _ := f.State("vlad", f.idx)
	if p := st.Progress[leviathan.ID]; p.Position != 7 || p.UpdatedAt != 42 {
		t.Errorf("v2 progress overwritten: %+v", p)
	}
	if st.Settings.DefaultSpeed != 1.1 {
		t.Errorf("user-chosen default speed overwritten: %v", st.Settings.DefaultSpeed)
	}
	if !st.Progress[martian.ID].Finished {
		t.Error("other legacy books not merged")
	}
}

func TestCorruptUserFileIsMovedAside(t *testing.T) {
	f := newFixture(t)
	if err := os.MkdirAll(f.dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.dir, "vlad.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := f.State("vlad", f.idx)
	if err != nil || st.Settings != DefaultSettings() {
		t.Fatalf("state = %+v %v", st, err)
	}
	matches, _ := filepath.Glob(filepath.Join(f.dir, "vlad.json.corrupt-*"))
	if len(matches) != 1 {
		t.Fatalf("corrupt file not preserved: %v", matches)
	}
}

func TestWritesAreAtomicAndClean(t *testing.T) {
	f := newFixture(t)
	var wg sync.WaitGroup
	for i := range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			f.UpdateProgress("vlad", f.idx, leviathan.ID, ProgressUpdate{Position: float64(i), Listened: 1})
		}()
	}
	wg.Wait()
	entries, _ := os.ReadDir(f.dir)
	if len(entries) != 1 || entries[0].Name() != "vlad.json" {
		t.Fatalf("users dir = %v", entries)
	}
	var d UserData
	b, _ := os.ReadFile(filepath.Join(f.dir, "vlad.json"))
	if err := json.Unmarshal(b, &d); err != nil || d.Version != 2 || d.Progress[leviathan.ID].Listened != 20 {
		t.Fatalf("file = %s (%v)", b, err)
	}
}

// v1 paths are found even when the library has a folder named "media" or
// v1 itself ran under a "/media" URL prefix.
func TestLegacyMigrationMediaFolder(t *testing.T) {
	f := newFixture(t)
	story := book("Kids/media/Story", 60, 90)
	other := book("Other", 30, 30)
	f.idx = library.NewIndex([]*library.Book{story, other}, 1)
	writeLegacy(t, f, "vlad", `{
		"currentUrl": "Kids/media/Story/b.mp3", "currentTime": 77, "playbackRate": 1.25,
		"listened": ["/media/Kids/media/Story/a.mp3", "/media/Kids/media/Story/b.mp3",
		             "/media/media/Other/a.mp3", "http://car.local/media/media/Other/b.mp3"]
	}`)
	st, err := f.State("vlad", f.idx)
	if err != nil {
		t.Fatal(err)
	}
	if p := st.Progress[story.ID]; p.TrackIndex != 1 || p.Position != 77 || p.Finished {
		t.Errorf("current book = %+v, want track 1 at 77 s", p)
	}
	if p := st.Progress[other.ID]; !p.Finished {
		t.Errorf("book listened under a /media URL prefix = %+v, want finished", p)
	}
}
