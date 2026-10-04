package store

import (
	"encoding/json"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/vburenin/bookbeam/server/internal/library"
)

// recorder collects the changes the store reports to subscribers.
type recorder struct {
	mu      sync.Mutex
	changes map[string][]Change
}

func (f *fixture) record() *recorder {
	r := &recorder{changes: map[string][]Change{}}
	f.Subscribe(func(user string, ch []Change) {
		r.mu.Lock()
		defer r.mu.Unlock()
		r.changes[user] = append(r.changes[user], ch...)
	})
	return r
}

// take returns and forgets the changes reported for user.
func (r *recorder) take(user string) []Change {
	r.mu.Lock()
	defer r.mu.Unlock()
	ch := r.changes[user]
	delete(r.changes, user)
	return ch
}

// track describes one file of a test book.
type track struct {
	name string
	dur  float64
	size int64
}

// fileBook builds a book from named files (sizes matter for re-linking).
func fileBook(dir string, tracks ...track) *library.Book {
	b := &library.Book{ID: library.BookID(dir), Path: dir, Title: path.Base(dir)}
	var start float64
	for _, t := range tracks {
		b.Tracks = append(b.Tracks, library.Track{Path: dir + "/" + t.name, Duration: t.dur, Start: start, Size: t.size})
		start += t.dur
		b.Size += t.size
	}
	b.Duration = start
	return b
}

// singleFileBook is a book that is one file.
func singleFileBook(rel string, dur float64, size int64) *library.Book {
	return &library.Book{ID: library.BookID(rel), Path: rel, Duration: dur, Size: size,
		Tracks: []library.Track{{Path: rel, Duration: dur, Size: size}}}
}

var (
	ch01 = track{"01.mp3", 100, 1001}
	ch02 = track{"02.mp3", 110, 1002}
	ch03 = track{"03.mp3", 120, 1003}
	ch04 = track{"04.mp3", 130, 1004}
	ch05 = track{"05.mp3", 140, 1005}
)

// indexSeq hands out increasing scan times, as successive scans have.
var indexSeq int64 = 100

func newIndex(books ...*library.Book) *library.Index {
	indexSeq++
	return library.NewIndex(books, indexSeq)
}

func (f *fixture) view(t *testing.T, idx *library.Index) StateView {
	t.Helper()
	st, err := f.State("vlad", idx)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func changeKeys(changes []Change) []string {
	var out []string
	for _, c := range changes {
		k := c.Kind + ":" + c.BookID
		switch {
		case c.Kind == ChangeProgress && c.Progress == nil:
			k += ":gone"
		case c.Kind == ChangeBookmarks && len(c.Bookmarks) == 0:
			k += ":none"
		}
		out = append(out, k)
	}
	return out
}

// sameKeys compares change keys as sets (bookmark changes are reported in
// book-id order, which is a hash order).
func sameKeys(got, want []string) bool {
	return slices.Equal(slices.Sorted(slices.Values(got)), slices.Sorted(slices.Values(want)))
}

func writeUserData(t *testing.T, f *fixture, user string, d *UserData) {
	t.Helper()
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(f.dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.dir, user+".json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// A missing chapter restored to a book shifts every later track index; the
// saved place (and bookmarks) must stay on the same file.
func TestRelinkAfterTracksShift(t *testing.T) {
	f := newFixture(t)
	rec := f.record()
	before := fileBook("Seq", ch01, ch02, ch04, ch05)
	f.idx = newIndex(before)
	put := f.put(t, before.ID, ProgressUpdate{TrackIndex: 2, Position: 45, Event: EventPause})
	bm, _, err := f.AddBookmark("vlad", f.idx, before.ID, NewBookmark{TrackIndex: 3, Position: 20, Note: "good bit"})
	if err != nil {
		t.Fatal(err)
	}
	if put.Progress.TrackSize != ch04.size || bm.TrackPath != "Seq/05.mp3" || bm.TrackSize != ch05.size {
		t.Fatalf("progress %+v / bookmark %+v not anchored to their files", put.Progress, bm)
	}
	rec.take("vlad")

	after := fileBook("Seq", ch01, ch02, ch03, ch04, ch05)
	f.clk.Advance(time.Minute)
	st := f.view(t, newIndex(after))
	p := st.Progress[after.ID]
	if p.TrackIndex != 3 || p.TrackPath != "Seq/04.mp3" || p.Position != 45 || p.BookPosition != 330+45 {
		t.Fatalf("progress not re-linked: %+v", p)
	}
	if p.UpdatedAt != put.Progress.UpdatedAt {
		t.Errorf("re-linking changed updatedAt %d -> %d (a device's newer local place would lose)", put.Progress.UpdatedAt, p.UpdatedAt)
	}
	if got := st.Bookmarks[after.ID]; len(got) != 1 || got[0].TrackIndex != 4 || got[0].BookPosition != 460+20 {
		t.Fatalf("bookmark not re-linked: %+v", got)
	}
	if got := changeKeys(rec.take("vlad")); !sameKeys(got, []string{"progress:" + after.ID, "bookmarks:" + after.ID}) {
		t.Fatalf("changes = %v", got)
	}

	// Persisted, and not reported again.
	f.reopen(t)
	rec = f.record()
	st = f.view(t, newIndex(after))
	if p := st.Progress[after.ID]; p.TrackIndex != 3 {
		t.Fatalf("after reopen: %+v", p)
	}
	if got := rec.take("vlad"); len(got) != 0 {
		t.Fatalf("unchanged data reported: %v", changeKeys(got))
	}

	// A file renamed inside the book keeps its size and is found again.
	renamed := fileBook("Seq", ch01, ch02, ch03, track{"04 - Chapter Four.mp3", 130, 1004}, ch05)
	st = f.view(t, newIndex(renamed))
	if p := st.Progress[after.ID]; p.TrackIndex != 3 || p.TrackPath != "Seq/04 - Chapter Four.mp3" {
		t.Fatalf("renamed file: %+v", p)
	}
}

// Renaming or moving a book folder must carry everyone's place along.
func TestRelinkFolderRename(t *testing.T) {
	f := newFixture(t)
	rec := f.record()
	old := fileBook("Expanse/Leviathan Wakes", ch01, ch02, ch03)
	other := fileBook("Other", track{"01.mp3", 50, 999})
	f.idx = newIndex(old, other)
	f.put(t, old.ID, ProgressUpdate{TrackIndex: 1, Position: 30, Listened: 10})
	if _, _, err := f.AddBookmark("vlad", f.idx, old.ID, NewBookmark{TrackIndex: 2, Position: 7}); err != nil {
		t.Fatal(err)
	}
	rec.take("vlad")

	moved := fileBook("James S. A. Corey/Expanse 1 - Leviathan Wakes", ch01, ch02, ch03)
	idx := newIndex(moved, other)
	f.Reconcile(idx) // vlad is loaded: re-linked eagerly after the scan
	changes := rec.take("vlad")
	got := changeKeys(changes)
	want := []string{"progress:" + old.ID + ":gone", "progress:" + moved.ID, "bookmarks:" + moved.ID, "bookmarks:" + old.ID + ":none"}
	if !sameKeys(got, want) || got[0] != want[0] {
		// The old id is retired before the new one is announced.
		t.Fatalf("changes = %v\nwant %v", got, want)
	}
	if changes[0].MovedTo != moved.ID {
		// Devices with the old book loaded follow it to the new id.
		t.Fatalf("retired entry MovedTo = %q, want %q", changes[0].MovedTo, moved.ID)
	}
	st := f.view(t, idx)
	if _, ok := st.Progress[old.ID]; ok {
		t.Fatal("old entry kept")
	}
	p := st.Progress[moved.ID]
	if p.BookID != moved.ID || p.Path != moved.Path || p.TrackPath != moved.Path+"/02.mp3" || p.Position != 30 || p.Listened != 10 {
		t.Fatalf("moved progress = %+v", p)
	}
	if bms := st.Bookmarks[moved.ID]; len(bms) != 1 || bms[0].TrackPath != moved.Path+"/03.mp3" {
		t.Fatalf("moved bookmarks = %+v", st.Bookmarks)
	}
}

// Adding a second .m4b to a folder turns the folder book into single-file
// books: the place follows its file to the new book id.
func TestRelinkRegrouped(t *testing.T) {
	f := newFixture(t)
	folder := fileBook("Downloads", track{"The Martian.m4b", 900, 5000})
	f.idx = newIndex(folder)
	f.put(t, folder.ID, ProgressUpdate{Position: 90})

	martian := singleFileBook("Downloads/The Martian.m4b", 900, 5000)
	artemis := singleFileBook("Downloads/Artemis.m4b", 800, 4000)
	st := f.view(t, newIndex(artemis, martian))
	if p, ok := st.Progress[martian.ID]; !ok || p.Position != 90 || p.TrackIndex != 0 {
		t.Fatalf("progress = %+v", st.Progress)
	}
	if _, ok := st.Progress[artemis.ID]; ok || len(st.Progress) != 1 {
		t.Fatalf("progress = %+v", st.Progress)
	}
}

// Two books merging into one (disc folders recognised as one book): the
// more recently updated place wins and listening time adds up.
func TestRelinkMergeKeepsNewer(t *testing.T) {
	f := newFixture(t)
	cd1 := fileBook("It/CD 1", ch01, ch02)
	cd2 := fileBook("It/CD 2", ch03, ch04)
	f.idx = newIndex(cd1, cd2)
	f.put(t, cd1.ID, ProgressUpdate{TrackIndex: 1, Position: 5, Listened: 60})
	f.clk.Advance(time.Minute)
	newer := f.put(t, cd2.ID, ProgressUpdate{TrackIndex: 0, Position: 9, Listened: 30}).Progress

	whole := &library.Book{ID: library.BookID("It"), Path: "It"}
	for _, b := range []*library.Book{cd1, cd2} {
		for _, tr := range b.Tracks {
			tr.Start = whole.Duration
			whole.Tracks = append(whole.Tracks, tr)
			whole.Duration += tr.Duration
		}
	}
	st := f.view(t, newIndex(whole))
	p := st.Progress[whole.ID]
	if len(st.Progress) != 1 || p.TrackPath != "It/CD 2/03.mp3" || p.TrackIndex != 2 || p.Position != 9 ||
		p.UpdatedAt != newer.UpdatedAt || p.Listened != 90 || p.StartedAt >= newer.StartedAt {
		t.Fatalf("merged = %+v", st.Progress)
	}
}

// When nothing (or more than one thing) matches, the entry stays untouched
// and is never deleted; it is re-linked once its files come back.
func TestRelinkLeavesUnmatchedAlone(t *testing.T) {
	f := newFixture(t)
	rec := f.record()
	b := fileBook("Kids/Pooh", ch01, ch02)
	f.idx = newIndex(b)
	want := f.put(t, b.ID, ProgressUpdate{TrackIndex: 1, Position: 12}).Progress
	rec.take("vlad")

	for _, c := range []struct {
		name  string
		books []*library.Book
	}{
		{"empty library (share not mounted)", nil},
		{"files gone", []*library.Book{fileBook("Other", ch03)}},
		{"two copies elsewhere", []*library.Book{fileBook("A/Pooh", ch01, ch02), fileBook("B/Pooh", ch01, ch02)}},
	} {
		st := f.view(t, newIndex(c.books...))
		if got := st.Progress[b.ID]; got != want || len(st.Progress) != 1 {
			t.Errorf("%s: progress = %+v", c.name, st.Progress)
		}
		if got := rec.take("vlad"); len(got) != 0 {
			t.Errorf("%s: changes %v", c.name, changeKeys(got))
		}
	}
	st := f.view(t, newIndex(fileBook("Kids/Pooh", ch01, ch02)))
	if got := st.Progress[b.ID]; got.Position != 12 {
		t.Fatalf("back: %+v", st.Progress)
	}
}

// Same-named, same-sized files in several books are told apart by the book
// duration the progress entry remembers.
func TestRelinkTieBreakByDuration(t *testing.T) {
	f := newFixture(t)
	intro := track{"00 - Intro.mp3", 30, 777}
	b1 := fileBook("Series/Book 1", intro, ch01)
	f.idx = newIndex(b1)
	f.put(t, b1.ID, ProgressUpdate{Position: 10})

	renamed := fileBook("Series/1 - Book 1", intro, ch01)
	b2 := fileBook("Series/Book 2", intro, ch02)
	st := f.view(t, newIndex(renamed, b2))
	if _, ok := st.Progress[renamed.ID]; !ok {
		t.Fatalf("progress = %+v", st.Progress)
	}
}

// A request that captured an index before a scan finished must not undo the
// newer re-linking.
func TestRelinkIgnoresOlderIndex(t *testing.T) {
	f := newFixture(t)
	old := fileBook("Old Name", ch01)
	oldIdx := newIndex(old)
	f.idx = oldIdx
	f.put(t, old.ID, ProgressUpdate{Position: 3})

	renamed := fileBook("New Name", ch01)
	f.view(t, newIndex(renamed))
	st := f.view(t, oldIdx)
	if _, ok := st.Progress[renamed.ID]; !ok || len(st.Progress) != 1 {
		t.Fatalf("older index undid re-linking: %+v", st.Progress)
	}
}

// Bookmarks saved before they carried a file path are anchored to the file
// at their index, unless their book position shows the files have shifted
// since.
func TestRelinkBackfillsOldBookmarks(t *testing.T) {
	f := newFixture(t)
	b := fileBook("Seq", ch01, ch02, ch03)
	data := newUserData()
	data.Bookmarks[b.ID] = []Bookmark{
		{ID: "kgood", TrackIndex: 1, Position: 5, BookPosition: 105},
		{ID: "kshifted", TrackIndex: 2, Position: 5, BookPosition: 105}, // saved when track 2 started at 100
	}
	writeUserData(t, f, "vlad", data)
	rec := f.record()
	st := f.view(t, newIndex(b))
	got := st.Bookmarks[b.ID]
	if len(got) != 2 || got[0].ID != "kgood" || got[0].TrackPath != "Seq/02.mp3" || got[0].TrackSize != ch02.size {
		t.Fatalf("bookmarks = %+v", got)
	}
	if got[1].ID != "kshifted" || got[1].TrackPath != "" {
		t.Fatalf("shifted bookmark anchored to the wrong file: %+v", got[1])
	}
	if ch := changeKeys(rec.take("vlad")); !sameKeys(ch, []string{"bookmarks:" + b.ID}) {
		t.Fatalf("changes = %v", ch)
	}
}

// A client that sends trackPath is believed over its (possibly stale) index.
func TestProgressPutTrackPathWins(t *testing.T) {
	f := newFixture(t)
	b := fileBook("Seq", ch01, ch02, ch03, ch04)
	f.idx = newIndex(b)
	res := f.put(t, b.ID, ProgressUpdate{TrackIndex: 2, TrackPath: "Seq/04.mp3", Position: 8})
	if p := res.Progress; p.TrackIndex != 3 || p.TrackPath != "Seq/04.mp3" || p.BookPosition != 330+8 {
		t.Fatalf("progress = %+v", p)
	}
	// A path of another book (or none) falls back to the index.
	other := fileBook("Other", ch05)
	f.idx = newIndex(b, other)
	res = f.put(t, b.ID, ProgressUpdate{TrackIndex: 1, TrackPath: "Other/05.mp3", Position: 1})
	if p := res.Progress; p.TrackIndex != 1 || p.TrackPath != "Seq/02.mp3" {
		t.Fatalf("progress = %+v", p)
	}
	bm, _, err := f.AddBookmark("vlad", f.idx, b.ID, NewBookmark{TrackIndex: 0, TrackPath: "Seq/03.mp3", Position: 2})
	if err != nil || bm.TrackIndex != 2 || bm.TrackPath != "Seq/03.mp3" {
		t.Fatalf("bookmark = %+v %v", bm, err)
	}
}
