package library

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
	"time"
)

// mustRename moves a library entry, failing the test on error.
func mustRename(t *testing.T, from, to string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(to), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(from, to); err != nil {
		t.Fatal(err)
	}
}

func countCovers(t *testing.T, state string) int {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(state, "covers"))
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return len(entries)
}

// TestEmptyLibraryKeepsIndex covers an unmounted library: an empty mount
// point must not wipe the index, the probe cache or the covers.
func TestEmptyLibraryKeepsIndex(t *testing.T) {
	base := t.TempDir()
	lib, stash, state := filepath.Join(base, "lib"), filepath.Join(base, "stash"), filepath.Join(base, "state")
	writeAudio(t, lib, "A/1.mp3", withArt(tags(10, "", "A", ""), "image/png", pngData("art")))
	writeAudio(t, lib, "B/1.mp3", tags(10, "", "B", ""))
	tl := openTestLib(t, lib, state)
	tl.scan(t)
	x1 := tl.Index()
	probes := tl.prober.calls.Load()
	if countCovers(t, state) != 1 {
		t.Fatal("cover not extracted")
	}
	unmount := func() {
		mustRename(t, filepath.Join(lib, "A"), filepath.Join(stash, "A"))
		mustRename(t, filepath.Join(lib, "B"), filepath.Join(stash, "B"))
	}
	remount := func() {
		mustRename(t, filepath.Join(stash, "A"), filepath.Join(lib, "A"))
		mustRename(t, filepath.Join(stash, "B"), filepath.Join(lib, "B"))
	}

	unmount()
	for _, opts := range []ScanOptions{{}, {RetryFailed: true, Manual: true}} {
		changed, err := tl.ScanWith(context.Background(), opts)
		if !errors.Is(err, ErrLibraryEmpty) || changed {
			t.Fatalf("%+v: scan of an empty root = %v, %v; want ErrLibraryEmpty", opts, changed, err)
		}
	}
	if tl.Index() != x1 || len(tl.files) != 2 || countCovers(t, state) != 1 {
		t.Fatalf("refused scan touched the index (%d books), cache (%d files) or covers", tl.Index().Len(), len(tl.files))
	}
	if again := openTestLib(t, lib, state); again.Index().Len() != 2 {
		t.Fatalf("saved index lost: %d books", again.Index().Len())
	}
	// An outage longer than the grace period costs nothing either.
	*tl.clock = tl.clock.Add(missingGrace + time.Hour)
	if _, err := tl.Scan(context.Background(), false); !errors.Is(err, ErrLibraryEmpty) || len(tl.files) != 2 {
		t.Fatalf("long outage: err %v, %d cached files", err, len(tl.files))
	}

	// The share comes back: nothing to probe, nothing changed.
	remount()
	if tl.scan(t) || tl.prober.calls.Load() != probes {
		t.Fatalf("after remount: changed or re-probed (%d probes)", tl.prober.calls.Load()-probes)
	}

	// A forced rescan accepts an empty library, but the probe results and
	// covers stay for the grace period.
	unmount()
	if _, err := tl.ScanWith(context.Background(), ScanOptions{Manual: true, Force: true}); err != nil {
		t.Fatal(err)
	}
	if tl.Index().Len() != 0 || len(tl.files) != 2 || countCovers(t, state) != 1 {
		t.Fatalf("forced empty scan: %d books, %d cached files, %d covers", tl.Index().Len(), len(tl.files), countCovers(t, state))
	}
	remount()
	tl.scan(t)
	if tl.Index().Version != x1.Version || tl.prober.calls.Load() != probes || tl.prober.picCalls.Load() != 1 {
		t.Errorf("after the share returned: version %s (want %s), %d re-probes, %d extractions",
			tl.Index().Version, x1.Version, tl.prober.calls.Load()-probes, tl.prober.picCalls.Load())
	}
}

func TestShrinkNeedsConfirmation(t *testing.T) {
	base := t.TempDir()
	lib, stash := filepath.Join(base, "lib"), filepath.Join(base, "stash")
	for _, b := range []string{"A", "B", "C", "D"} {
		writeAudio(t, lib, b+"/1.mp3", tags(10, "", b, ""))
	}
	tl := openTestLib(t, lib, filepath.Join(base, "state"))
	tl.scan(t)
	x1 := tl.Index()
	drop := func() {
		for _, b := range []string{"A", "B", "C"} {
			mustRename(t, filepath.Join(lib, b), filepath.Join(stash, b))
		}
	}
	restore := func() {
		for _, b := range []string{"A", "B", "C"} {
			mustRename(t, filepath.Join(stash, b), filepath.Join(lib, b))
		}
	}

	// An automatic scan losing most files is refused once...
	drop()
	if _, err := tl.Scan(context.Background(), false); !errors.Is(err, ErrLibraryShrank) || tl.Index() != x1 {
		t.Fatalf("first shrinking scan: err %v, books %d", err, tl.Index().Len())
	}
	// ...and a glitch that heals by the re-check leaves no trace.
	restore()
	if tl.scan(t) || tl.Index().Version != x1.Version {
		t.Fatal("healed library changed")
	}
	drop()
	if _, err := tl.Scan(context.Background(), false); !errors.Is(err, ErrLibraryShrank) {
		t.Fatalf("shrink not detected again: %v", err)
	}
	// A loss that persists is accepted by the re-check.
	if !tl.scan(t) || !reflect.DeepEqual(bookPaths(tl.Index()), []string{"D"}) {
		t.Fatalf("confirmed shrink: %q", bookPaths(tl.Index()))
	}

	// A manual rescan accepts a shrink at once.
	restore()
	tl.scan(t)
	drop()
	if _, err := tl.ScanWith(context.Background(), ScanOptions{Manual: true}); err != nil || tl.Index().Len() != 1 {
		t.Fatalf("manual shrinking scan: %v, %d books", err, tl.Index().Len())
	}
}

// TestMovedFilesAreNotLost: reorganising the library is not a shrink, and
// moved files keep their probe results and covers.
func TestMovedFilesAreNotLost(t *testing.T) {
	base := t.TempDir()
	lib, state := filepath.Join(base, "lib"), filepath.Join(base, "state")
	for _, b := range []string{"A", "B", "C"} {
		writeAudio(t, lib, "Author/"+b+"/1.mp3", withArt(tags(10, "", b, ""), "image/jpeg", jpegData(b)))
	}
	tl := openTestLib(t, lib, state)
	tl.scan(t)
	probes, pics := tl.prober.calls.Load(), tl.prober.picCalls.Load()

	mustRename(t, filepath.Join(lib, "Author"), filepath.Join(lib, "Shelf", "Renamed Author"))
	if _, err := tl.Scan(context.Background(), false); err != nil {
		t.Fatalf("a moved folder was refused: %v", err)
	}
	if got := bookPaths(tl.Index()); !reflect.DeepEqual(got, []string{"Shelf/Renamed Author/A", "Shelf/Renamed Author/B", "Shelf/Renamed Author/C"}) {
		t.Fatalf("books after the move: %q", got)
	}
	if tl.prober.calls.Load() != probes || tl.prober.picCalls.Load() != pics {
		t.Errorf("moved files re-probed (%d) or covers re-extracted (%d)", tl.prober.calls.Load()-probes, tl.prober.picCalls.Load()-pics)
	}
	for _, b := range tl.Index().Books {
		if b.Cover == nil {
			t.Errorf("%s lost its cover", b.Path)
		} else if _, err := os.Stat(tl.CoverPath(b.Cover)); err != nil {
			t.Errorf("%s: cover file: %v", b.Path, err)
		}
	}
}

func TestUnreadableFolderKeepsBooks(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permissions do not apply to root")
	}
	base := t.TempDir()
	lib := filepath.Join(base, "lib")
	writeAudio(t, lib, "Book/1.mp3", tags(10, "", "Book", ""))
	writeAudio(t, lib, "Discs/Box/CD 1/a.mp3", tags(10, "", "Box", ""))
	writeAudio(t, lib, "Discs/Box/CD 2/a.mp3", tags(10, "", "Box", ""))
	writeAudio(t, lib, "Other/1.mp3", tags(10, "", "Other", ""))
	tl := openTestLib(t, lib, filepath.Join(base, "state"))
	tl.scan(t)
	x1 := tl.Index()
	probes := tl.prober.calls.Load()

	locked := []string{filepath.Join(lib, "Book"), filepath.Join(lib, "Discs", "Box", "CD 2")}
	for _, d := range locked {
		if err := os.Chmod(d, 0); err != nil {
			t.Fatal(err)
		}
	}
	unlock := func() {
		for _, d := range locked {
			_ = os.Chmod(d, 0o755)
		}
	}
	t.Cleanup(unlock)

	if _, err := tl.Scan(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	x2 := tl.Index()
	if got := bookPaths(x2); !reflect.DeepEqual(got, bookPaths(x1)) {
		t.Fatalf("books with unreadable folders: %q, want %q", got, bookPaths(x1))
	}
	for _, p := range []string{"Book", "Discs/Box"} {
		if bookByPath(t, x2, p) != bookByPath(t, x1, p) {
			t.Errorf("%s: not carried over from the previous index", p)
		}
	}
	if x2.Version != x1.Version {
		t.Error("an unreadable folder changed the library version")
	}

	unlock()
	tl.scan(t)
	if tl.prober.calls.Load() != probes || tl.Index().Version != x1.Version {
		t.Errorf("after recovery: %d re-probes, version changed %v", tl.prober.calls.Load()-probes, tl.Index().Version != x1.Version)
	}
}

func TestTransientProbeFailuresAreRetried(t *testing.T) {
	root := t.TempDir()
	writeAudio(t, root, "Chap/A.mp3", chaptered(30, "a1", "a2", "a3"))
	writeAudio(t, root, "Chap/B.mp3", chaptered(30, "b1", "b2", "b3"))
	writeAudio(t, root, "Slow/1.webm", tags(20, "", "Slow", ""))
	writeFile(t, root, "Bad/1.mp3", []byte("damaged beyond repair"))
	tl := openTestLib(t, root, filepath.Join(root, ".bookbeam"))
	tl.prober.failWith("B.mp3", &fs.PathError{Op: "read", Path: "/nas/Chap/B.mp3", Err: syscall.EIO})
	tl.prober.failWith("1.webm", errors.Join(errors.New("media: unsupported format"), fmt.Errorf("media: ffprobe: %w", context.DeadlineExceeded)))

	tl.scan(t)
	if e := tl.files["Chap/B.mp3"]; e == nil || !e.Retry || e.Err == "" {
		t.Fatalf("I/O failure entry = %+v, want a retryable error", e)
	}
	if e := tl.files["Slow/1.webm"]; e == nil || !e.Retry {
		t.Fatalf("ffprobe timeout entry = %+v, want retryable", e)
	}
	if e := tl.files["Bad/1.mp3"]; e == nil || e.Retry {
		t.Fatalf("damaged file entry = %+v, want a definitive error", e)
	}
	// While B cannot be read the folder is one book (not every file is
	// chaptered).
	if got := bookPaths(tl.Index()); !reflect.DeepEqual(got, []string{"Bad", "Chap", "Slow"}) {
		t.Fatalf("books while failing: %q", got)
	}

	// Periodic scans retry transient failures, not definitive ones.
	tl.scan(t)
	if tl.prober.probes("B.mp3") != 2 || tl.prober.probes("1.webm") != 2 || tl.prober.probes("1.mp3") != 1 {
		t.Errorf("probes: B %d, webm %d, bad %d", tl.prober.probes("B.mp3"), tl.prober.probes("1.webm"), tl.prober.probes("1.mp3"))
	}

	// Once the NAS recovers, the next periodic scan heals the library.
	tl.prober.failWith("B.mp3", nil)
	tl.prober.failWith("1.webm", nil)
	if !tl.scan(t) {
		t.Fatal("recovery not published")
	}
	if got := bookPaths(tl.Index()); !reflect.DeepEqual(got, []string{"Bad", "Chap/A.mp3", "Chap/B.mp3", "Slow"}) {
		t.Errorf("books after recovery: %q", got)
	}
	if d := bookByPath(t, tl.Index(), "Slow").Duration; d != 20 {
		t.Errorf("recovered duration %v", d)
	}
	if e := tl.files["Chap/B.mp3"]; e.Retry || e.Err != "" {
		t.Errorf("recovered entry %+v", e)
	}
}

func TestNotAudioAndEmptyFiles(t *testing.T) {
	root := t.TempDir()
	writeAudio(t, root, "Zero/01.mp3", tags(10, "", "", ""))
	writeFile(t, root, "Zero/02.mp3", nil)
	writeAudio(t, root, "Zero/03.mp3", tags(10, "", "", ""))
	writeFile(t, root, "zero-root.mp3", nil)
	writeFile(t, root, "Notes/readme.mp3", []byte(notAudioPrefix+": a text file"))
	writeAudio(t, root, "Mixed/1.mp3", tags(10, "", "", ""))
	writeFile(t, root, "Mixed/2.m4b", []byte(notAudioPrefix+" <html>"))
	writeFile(t, root, "Mixed/cover.jpg", nil) // empty images are ignored too

	tl := openTestLib(t, root, filepath.Join(root, ".bookbeam"))
	tl.scan(t)
	x := tl.Index()
	if got := bookPaths(x); !reflect.DeepEqual(got, []string{"Mixed", "Zero"}) {
		t.Fatalf("books: %q", got)
	}
	if got := trackNames(bookByPath(t, x, "Zero")); !reflect.DeepEqual(got, []string{"01.mp3", "03.mp3"}) {
		t.Errorf("Zero tracks: %q", got)
	}
	if got := trackNames(bookByPath(t, x, "Mixed")); !reflect.DeepEqual(got, []string{"1.mp3"}) {
		t.Errorf("Mixed tracks: %q", got)
	}
	if bookByPath(t, x, "Mixed").Cover != nil {
		t.Error("empty image used as cover")
	}
	if e := tl.files["Notes/readme.mp3"]; e == nil || !e.NotAudio {
		t.Errorf("not-audio entry %+v", e)
	}
	// The verdict is cached: the file is not looked at again until it
	// changes.
	tl.scan(t)
	if n := tl.prober.probes("readme.mp3"); n != 1 {
		t.Errorf("not-audio file probed %d times", n)
	}
}

// mp3Frames is a valid MPEG-1 layer III stream (128 kbit/s, 44.1 kHz, mono).
func mp3Frames(n int) []byte {
	frame := make([]byte, 417)
	copy(frame, []byte{0xFF, 0xFB, 0x90, 0xC0})
	return bytes.Repeat(frame, n)
}

// TestRealProberSkipsNonAudio runs the production prober: files that are
// not audio stay out of the index whatever their extension.
func TestRealProberSkipsNonAudio(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "Real/01.mp3", mp3Frames(100))
	writeFile(t, root, "Real/02.mp3", []byte("username:password and other things that are not audio"))
	writeFile(t, root, "Real/03.mp3", mp3Frames(50))
	writeFile(t, root, "Real/04.m4b", []byte(`{"secret": true}`))
	l, err := Open(Options{Root: root, StateDir: filepath.Join(root, ".bookbeam")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Scan(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	b := bookByPath(t, l.Index(), "Real")
	if got := trackNames(b); !reflect.DeepEqual(got, []string{"01.mp3", "03.mp3"}) {
		t.Fatalf("tracks: %q", got)
	}
	if b.Tracks[0].Duration < 2.5 || b.Tracks[0].Duration > 2.7 {
		t.Errorf("duration %v", b.Tracks[0].Duration)
	}
}

func TestRunRechecksUnavailableLibrary(t *testing.T) {
	base := t.TempDir()
	lib, stash := filepath.Join(base, "lib"), filepath.Join(base, "stash")
	writeAudio(t, lib, "A/1.mp3", tags(10, "", "A", ""))
	tl := openTestLib(t, lib, filepath.Join(base, "state"))
	tl.recheckDelay = 10 * time.Millisecond
	events := make(chan ScanEvent, 64)
	tl.Subscribe(func(ev ScanEvent) { events <- ev })
	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	go func() { tl.Run(ctx, 0); close(stopped) }()
	defer func() { cancel(); <-stopped }()

	next := func() ScanEvent {
		t.Helper()
		select {
		case ev := <-events:
			return ev
		case <-time.After(5 * time.Second):
			t.Fatal("no scan event")
			return ScanEvent{}
		}
	}
	if ev := next(); ev.Err != nil || tl.Index().Len() != 1 {
		t.Fatalf("initial scan %+v", ev)
	}
	version := tl.Index().Version

	mustRename(t, filepath.Join(lib, "A"), filepath.Join(stash, "A"))
	tl.RequestRescan()
	if ev := next(); !ev.Manual || !errors.Is(ev.Err, ErrLibraryEmpty) {
		t.Fatalf("manual scan of an empty root: %+v", ev)
	}
	// Re-checks follow without waiting for the (disabled) interval.
	if ev := next(); ev.Manual || !errors.Is(ev.Err, ErrLibraryEmpty) {
		t.Fatalf("re-check: %+v", ev)
	}
	mustRename(t, filepath.Join(stash, "A"), filepath.Join(lib, "A"))
	for ev := next(); ev.Err != nil; ev = next() {
	}
	if tl.Index().Version != version {
		t.Error("library changed across the outage")
	}

	// A forced rescan publishes an emptied library.
	mustRename(t, filepath.Join(lib, "A"), filepath.Join(stash, "A"))
	tl.RequestRescan(RescanOptions{Force: true})
	if ev := next(); !ev.Manual || ev.Err != nil || !ev.Changed || tl.Index().Len() != 0 {
		t.Fatalf("forced rescan: %+v, %d books", ev, tl.Index().Len())
	}
}

// TestSchemaChangeServesSavedIndex: after an upgrade that changes the cache
// format, the saved index is served while every file is probed again.
func TestSchemaChangeServesSavedIndex(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, ".bookbeam")
	writeAudio(t, root, "A/1.mp3", tags(10, "", "A", ""))
	writeAudio(t, root, "A/2.mp3", tags(10, "", "A", ""))
	tl := openTestLib(t, root, state)
	tl.scan(t)

	// Rewrite library.json as an older version would have: other schema,
	// no fingerprints.
	path := filepath.Join(state, "library.json")
	var raw map[string]any
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber() // nanosecond mtimes do not fit a float64
	if err := dec.Decode(&raw); err != nil {
		t.Fatal(err)
	}
	raw["schema"] = 1
	for _, b := range raw["books"].([]any) {
		for _, tr := range b.(map[string]any)["tracks"].([]any) {
			delete(tr.(map[string]any), "fingerprint")
		}
	}
	if data, err = json.Marshal(raw); err != nil {
		t.Fatal(err)
	}
	writeFile(t, state, "library.json", data)

	tl2 := openTestLib(t, root, state)
	if !tl2.Ready() || tl2.Index().Len() != 1 || tl2.Index().Version != tl.Index().Version {
		t.Fatalf("saved index not served: ready %v, %d books", tl2.Ready(), tl2.Index().Len())
	}
	if tr := tl2.Index().Books[0].Tracks[0]; tr.Fingerprint != TrackFingerprint(tr.Path, tr.Size, tr.ModTime) {
		t.Errorf("fingerprint not filled: %+v", tr)
	}
	tl2.scan(t)
	if got := tl2.prober.calls.Load(); got != 2 {
		t.Errorf("re-probed %d files, want 2", got)
	}
}
