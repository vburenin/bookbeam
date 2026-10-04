package library

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vburenin/bookbeam/server/internal/media"
)

// fakeFile is what test "audio" files contain: the Info the fake prober
// returns, plus optional embedded art.
type fakeFile struct {
	media.Info
	PicMIME string `json:"picMime,omitempty"`
	PicData []byte `json:"picData,omitempty"`
}

// notAudioPrefix starts test files whose content the fake prober reports
// as not audio (as media.ProbeFile does after sniffing).
const notAudioPrefix = "NOT AUDIO"

// fakeProber decodes fakeFile JSON; files starting with notAudioPrefix are
// not audio, and anything else fails to probe. fail injects errors by file
// name.
type fakeProber struct {
	calls    atomic.Int64
	picCalls atomic.Int64

	mu   sync.Mutex
	fail map[string]error
	seen map[string]int // probes per file name
}

func (p *fakeProber) failWith(name string, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.fail == nil {
		p.fail = map[string]error{}
	}
	if err == nil {
		delete(p.fail, name)
	} else {
		p.fail[name] = err
	}
}

func (p *fakeProber) probes(name string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.seen[name]
}

func (p *fakeProber) probe(path string, o media.Options) (*media.Info, error) {
	p.calls.Add(1)
	p.mu.Lock()
	if p.seen == nil {
		p.seen = map[string]int{}
	}
	p.seen[filepath.Base(path)]++
	err := p.fail[filepath.Base(path)]
	p.mu.Unlock()
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if strings.HasPrefix(string(b), notAudioPrefix) {
		return nil, media.ErrNotAudio
	}
	var ff fakeFile
	if err := json.Unmarshal(b, &ff); err != nil {
		return nil, errors.New("not a fake audio file")
	}
	info := ff.Info
	if len(ff.PicData) > 0 {
		info.HasPicture = true
		if o.WantPicture {
			p.picCalls.Add(1)
			info.Picture = &media.Picture{MIME: ff.PicMIME, Data: ff.PicData}
		}
	}
	return &info, nil
}

func writeFile(t *testing.T, root, rel string, data []byte) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeAudio(t *testing.T, root, rel string, f fakeFile) {
	t.Helper()
	if f.Duration == 0 {
		f.Duration = 60
	}
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, root, rel, b)
}

// Image file contents: real magic bytes (covers are recognised by content)
// followed by a marker.
func jpegData(s string) []byte { return append([]byte{0xFF, 0xD8, 0xFF, 0xE0}, s...) }
func pngData(s string) []byte  { return append([]byte("\x89PNG\r\n\x1a\n"), s...) }
func gifData(s string) []byte  { return append([]byte("GIF89a"), s...) }
func webpData(s string) []byte { return append([]byte("RIFF\x00\x00\x00\x00WEBP"), s...) }
func bmpData(s string) []byte {
	h := []byte("BM\x00\x00\x00\x00\x00\x00\x00\x00\x36\x00\x00\x00\x28\x00\x00\x00")
	return append(h, s...)
}

// withArt gives a fake file embedded art.
func withArt(f fakeFile, mime string, data []byte) fakeFile {
	f.PicMIME, f.PicData = mime, data
	return f
}

func tags(dur float64, title, album, artist string) fakeFile {
	return fakeFile{Info: media.Info{Duration: dur, Title: title, Album: album, Artist: artist}}
}

func chaptered(dur float64, titles ...string) fakeFile {
	f := fakeFile{Info: media.Info{Duration: dur, Format: "mp4"}}
	step := dur / float64(len(titles))
	for i, t := range titles {
		f.Chapters = append(f.Chapters, media.Chapter{Title: t, Start: float64(i) * step, End: float64(i+1) * step})
	}
	return f
}

type testLib struct {
	*Library
	prober *fakeProber
	clock  *time.Time
}

func openTestLib(t *testing.T, root, state string) *testLib {
	t.Helper()
	p := &fakeProber{}
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	tl := &testLib{prober: p, clock: &now}
	l, err := Open(Options{Root: root, StateDir: state, Probe: p.probe, Workers: 3, Now: func() time.Time { return *tl.clock }})
	if err != nil {
		t.Fatal(err)
	}
	tl.Library = l
	return tl
}

func (tl *testLib) scan(t *testing.T) bool {
	t.Helper()
	changed, err := tl.Scan(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	return changed
}

func bookPaths(x *Index) []string {
	var out []string
	for _, b := range x.Books {
		out = append(out, b.Path)
	}
	return out
}

func trackPaths(b *Book) []string {
	var out []string
	for _, t := range b.Tracks {
		out = append(out, t.Path)
	}
	return out
}

func bookByPath(t *testing.T, x *Index, p string) *Book {
	t.Helper()
	for _, b := range x.Books {
		if b.Path == p {
			return b
		}
	}
	t.Fatalf("no book %q in %v", p, bookPaths(x))
	return nil
}

func TestGroupingRules(t *testing.T) {
	root := t.TempDir()
	a := tags(60, "", "", "")
	for _, rel := range []string{
		"Author/Multi/10.mp3", "Author/Multi/2.mp3", "Author/Multi/1.mp3",
		"Mixed/a.m4b", "Mixed/b.mp3",
		"Discs/Book/CD 10/a.mp3", "Discs/Book/CD 2/a.mp3", "Discs/Book/CD 1/b.mp3", "Discs/Book/CD 1/a.mp3",
		"Discs/Book/Artwork/readme.txt",
		"NotDiscs/Book/CD 1/a.mp3", "NotDiscs/Book/Bonus/b.mp3",
		"Parent/own.mp3", "Parent/Child/c.mp3",
		"@eaDir/junk/x.mp3", ".hidden/y.mp3", "#recycle/z.mp3", "#snapshot/z.mp3",
		"lost+found/z.mp3", "$RECYCLE.BIN/z.mp3", "System Volume Information/z.mp3",
		"state/legacy.mp3", "Kids/state/kid.mp3", "Kids/._resource.mp3",
		"Loose.mp3",
		"Cycle/a.mp3",
	} {
		writeAudio(t, root, rel, a)
	}
	writeAudio(t, root, "Singles/A.m4b", chaptered(100, "x"))
	writeAudio(t, root, "Singles/B.m4b", tags(50, "B", "", ""))
	writeAudio(t, root, "Chaptered/x.mp3", chaptered(100, "one", "two"))
	writeAudio(t, root, "Chaptered/y.mp3", chaptered(100, "three", "four"))
	writeAudio(t, root, "HalfChaptered/x.mp3", chaptered(100, "one", "two"))
	writeAudio(t, root, "HalfChaptered/y.mp3", tags(10, "", "", ""))
	writeFile(t, root, "Docs Only/readme.txt", []byte("hi"))
	if err := os.MkdirAll(filepath.Join(root, "Empty"), 0o755); err != nil {
		t.Fatal(err)
	}
	// A symlink cycle and a symlink to a book outside the library.
	if err := os.Symlink("..", filepath.Join(root, "Cycle", "loop")); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	writeAudio(t, outside, "x.mp3", a)
	if err := os.Symlink(outside, filepath.Join(root, "Linked")); err != nil {
		t.Fatal(err)
	}
	// A state dir inside the library under a non-dot name is skipped.
	state := filepath.Join(root, "bbstate")
	writeAudio(t, root, "bbstate/covers/not-a-book.mp3", a)

	tl := openTestLib(t, root, state)
	done := make(chan struct{})
	go func() {
		defer close(done)
		tl.scan(t)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("scan did not finish (symlink cycle?)")
	}
	x := tl.Index()

	want := []string{
		"Author/Multi",
		"Chaptered/x.mp3",
		"Chaptered/y.mp3",
		"Cycle",
		"Discs/Book",
		"HalfChaptered",
		"Kids/state",
		"Linked",
		"Loose.mp3",
		"Mixed",
		"NotDiscs/Book/Bonus",
		"NotDiscs/Book/CD 1",
		"Parent",
		"Parent/Child",
		"Singles/A.m4b",
		"Singles/B.m4b",
	}
	if got := bookPaths(x); !reflect.DeepEqual(got, want) {
		t.Fatalf("books:\n got %q\nwant %q", got, want)
	}
	if got := trackPaths(bookByPath(t, x, "Author/Multi")); !reflect.DeepEqual(got, []string{"Author/Multi/1.mp3", "Author/Multi/2.mp3", "Author/Multi/10.mp3"}) {
		t.Errorf("natural track order: %q", got)
	}
	discs := bookByPath(t, x, "Discs/Book")
	if got := trackPaths(discs); !reflect.DeepEqual(got, []string{
		"Discs/Book/CD 1/a.mp3", "Discs/Book/CD 1/b.mp3", "Discs/Book/CD 2/a.mp3", "Discs/Book/CD 10/a.mp3",
	}) {
		t.Errorf("disc track order: %q", got)
	}
	if discs.Folder != "Discs" || discs.Title != "Book" {
		t.Errorf("disc book folder/title = %q/%q", discs.Folder, discs.Title)
	}
	if got := len(bookByPath(t, x, "Mixed").Tracks); got != 2 {
		t.Errorf("Mixed tracks = %d, want 2 (only one .m4b)", got)
	}
	loose := bookByPath(t, x, "Loose.mp3")
	if loose.Folder != "" || loose.Title != "Loose" || loose.ID != BookID("Loose.mp3") {
		t.Errorf("loose root file book = %+v", loose)
	}
	if single := bookByPath(t, x, "Singles/B.m4b"); single.Folder != "Singles" || single.Title != "B" {
		t.Errorf("single-file book = %+v", single)
	}
	if b, i, ok := x.TrackByPath("Discs/Book/CD 2/a.mp3"); !ok || b != discs || i != 2 {
		t.Errorf("TrackByPath = %v %d %v", b, i, ok)
	}
	if x.Book(discs.ID) != discs || x.Book("b_nope") != nil {
		t.Error("Book lookup")
	}
}

func TestDiscPattern(t *testing.T) {
	for name, want := range map[string]bool{
		"CD 1": true, "cd1": true, "Disc 02": true, "disk_3": true, "Part 1": true,
		"Book - CD 2": true, "Disc 1 of 2": true, "CD.3": true,
		"It (Disc 1)": true, "Dune [CD2]": true, "CD 01 - Chapters 1-4": true, "Disc 3: The End": true,
		"(cd 4)": true, "Book [Disc 1 of 3]": true,
		"Диск 1": true, "диск_02": true, "Часть 2 из 3": true, "Мастер и Маргарита (Диск 1)": true, "Частина 1": true,
		"Дискотека 1": false, "Участь 1": false,
		"CDs": false, "Bonus": false, "Partial 1": false, "Chapter 1": false, "1": false,
		"CD 1 bonus": false, "Discovery 1": false, "Book (Disc 1) extra": false,
	} {
		if got := discDirRE.MatchString(name); got != want {
			t.Errorf("disc %q = %v, want %v", name, got, want)
		}
	}
}

func TestNaturalSort(t *testing.T) {
	in := []string{"Chapter 10", "chapter 2", "Chapter 1", "Chapter 01", "b", "A", "a", "x2y10", "x2y9", "x10", "Ünïcødé", "track", ""}
	sort.Slice(in, func(i, j int) bool { return NaturalLess(in[i], in[j]) })
	want := []string{"", "A", "a", "b", "Chapter 01", "Chapter 1", "chapter 2", "Chapter 10", "track", "x2y9", "x2y10", "x10", "Ünïcødé"}
	if !reflect.DeepEqual(in, want) {
		t.Fatalf("got %q\nwant %q", in, want)
	}
	if NaturalCompare("a", "a") != 0 || NaturalCompare("a01", "a1") >= 0 {
		t.Error("tie-breaks")
	}
}

func TestTrackTitles(t *testing.T) {
	for name, want := range map[string]string{
		"01 - Chapter 1.mp3":       "Chapter 1",
		"01. Opening.mp3":          "Opening",
		"01_Intro.ogg":             "Intro",
		"07 Chapter Seven.mp3":     "Chapter Seven",
		"01.mp3":                   "01",
		"01 - .mp3":                "01 -",
		"2001 A Space Odyssey.mp3": "2001 A Space Odyssey",
		"pride_and_prejudice_01":   "pride_and_prejudice_01",
		"part 1 – intro.wav":       "part 1 – intro",
	} {
		if got := fileTitle(name); got != want {
			t.Errorf("fileTitle(%q) = %q, want %q", name, got, want)
		}
	}

	files := []fileEntry{{Name: "01 - One.mp3"}, {Name: "02 - Two.mp3"}}
	info := func(title string) *media.Info { return &media.Info{Title: title} }
	cases := []struct {
		name  string
		infos []*media.Info
		want  []string
	}{
		{"distinct tags win", []*media.Info{info("Prologue"), info("The Storm")}, []string{"Prologue", "The Storm"}},
		{"generic tags ignored", []*media.Info{info("Track 01"), info("track 2")}, []string{"One", "Two"}},
		{"identical tags ignored", []*media.Info{info("Leviathan"), info("leviathan")}, []string{"One", "Two"}},
		{"missing info", []*media.Info{nil, info("Real Title")}, []string{"One", "Real Title"}},
		{"numeric tags ignored", []*media.Info{info("1"), info("02")}, []string{"One", "Two"}},
	}
	for _, c := range cases {
		if got := trackTitles(files, c.infos); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: got %q want %q", c.name, got, c.want)
		}
	}
	if got := trackTitles(files[:1], []*media.Info{info("Same")}); got[0] != "Same" {
		t.Errorf("single track keeps its tag: %q", got)
	}
}

func TestBookMetadata(t *testing.T) {
	root := t.TempDir()
	// Tags: album title, artist (the author; the album artist is someone
	// else, e.g. a publisher), narrator tag, series.
	f := tags(100, "Ch 1", "Leviathan Wakes", "James S. A. Corey")
	f.AlbumArtist, f.Narrator, f.Composer = "Orbit Audio", "Jefferson Mays", "Composer"
	f.Series, f.SeriesPart, f.Year, f.Genre = "The Expanse", "1", "2011-06-15", "Science Fiction"
	f.Description = "Desc from tags"
	writeAudio(t, root, "Expanse/01 Leviathan/01.mp3", f)

	// Junk album -> cleaned folder name and year; artist equal to title is
	// not an author; composer becomes narrator; text files apply.
	g := tags(100, "", "Unknown Album", "Pride & Prejudice")
	g.Composer = "Composer Narrator"
	g.Comment = "short"
	writeAudio(t, root, "Classics/01 - Pride & Prejudice (1813)/a.mp3", g)
	writeFile(t, root, "Classics/01 - Pride & Prejudice (1813)/desc.txt", []byte("\xef\xbb\xbf  A classic.\r\nSecond line.  \n"))
	writeFile(t, root, "Classics/01 - Pride & Prejudice (1813)/reader.txt", []byte("Real Reader\nignored\n"))

	// Single-file: title-or-album, long comment as description.
	h := tags(100, "Project Hail Mary", "", "Andy Weir")
	h.Comment = "A lone astronaut must save the earth from disaster in this thriller."
	writeAudio(t, root, "Singles/phm.m4b", h)
	writeAudio(t, root, "Singles/other.m4b", tags(10, "", "Other Album", ""))
	writeFile(t, root, "Singles/desc.txt", []byte("shared folder text must not apply"))

	// No tags at all (probe fails): everything from names.
	writeFile(t, root, "Untagged/Book Name (1999)/03.mp3", []byte("garbage"))

	tl := openTestLib(t, root, filepath.Join(root, ".bookbeam"))
	tl.scan(t)
	x := tl.Index()

	lev := bookByPath(t, x, "Expanse/01 Leviathan")
	type meta struct{ Title, Author, Narrator, Series, SeriesPart, Year, Genre, Description string }
	want := meta{"Leviathan Wakes", "James S. A. Corey", "Jefferson Mays", "The Expanse", "1", "2011", "Science Fiction", "Desc from tags"}
	got := meta{lev.Title, lev.Author, lev.Narrator, lev.Series, lev.SeriesPart, lev.Year, lev.Genre, lev.Description}
	if got != want {
		t.Errorf("tagged book:\n got %+v\nwant %+v", got, want)
	}

	pp := bookByPath(t, x, "Classics/01 - Pride & Prejudice (1813)")
	if pp.Title != "Pride & Prejudice" || pp.Year != "1813" || pp.Author != "" ||
		pp.Narrator != "Real Reader" || pp.Description != "A classic.\nSecond line." {
		t.Errorf("name-derived book: %+v", pp)
	}

	phm := bookByPath(t, x, "Singles/phm.m4b")
	if phm.Title != "Project Hail Mary" || phm.Author != "Andy Weir" || phm.Description != h.Comment {
		t.Errorf("single-file book: %+v", phm)
	}
	if other := bookByPath(t, x, "Singles/other.m4b"); other.Title != "Other Album" || other.Description != "" {
		t.Errorf("single-file album fallback: %+v", other)
	}

	un := bookByPath(t, x, "Untagged/Book Name (1999)")
	if un.Title != "Book Name" || un.Year != "1999" || un.Duration != 0 || len(un.Tracks) != 1 || un.Tracks[0].Format != "mp3" {
		t.Errorf("unprobeable book: %+v", un)
	}
	if un.Tracks[0].Title != "03" || len(un.Chapters) != 1 || un.Chapters[0].Title != "03" {
		t.Errorf("unprobeable track/chapter: %+v %+v", un.Tracks, un.Chapters)
	}
}

func TestChaptersAndDurations(t *testing.T) {
	root := t.TempDir()
	writeAudio(t, root, "Book/1.mp3", tags(100.0004, "Intro", "", ""))
	ch := chaptered(300, "A", "", "C")
	ch.Chapters[2].End = 0 // prober left the last end unset
	writeAudio(t, root, "Book/2.mp3", ch)
	single := chaptered(50, "Only")
	writeAudio(t, root, "Book/3.mp3", single)

	tl := openTestLib(t, root, filepath.Join(root, ".bookbeam"))
	tl.scan(t)
	b := bookByPath(t, tl.Index(), "Book")
	if b.Duration != 450 || b.Tracks[1].Start != 100 || b.Tracks[2].Start != 400 {
		t.Fatalf("durations/starts: %v %+v", b.Duration, b.Tracks)
	}
	want := []Chapter{
		{Title: "Intro", Track: 0, Start: 0, End: 100, BookStart: 0},
		{Title: "A", Track: 1, Start: 0, End: 100, BookStart: 100},
		{Title: "Chapter 2", Track: 1, Start: 100, End: 200, BookStart: 200},
		{Title: "C", Track: 1, Start: 200, End: 300, BookStart: 300},
		{Title: "3", Track: 2, Start: 0, End: 50, BookStart: 400},
	}
	if !reflect.DeepEqual(b.Chapters, want) {
		t.Errorf("chapters:\n got %+v\nwant %+v", b.Chapters, want)
	}
}

func TestCoverSelection(t *testing.T) {
	root := t.TempDir()
	art := withArt(fakeFile{Info: media.Info{Duration: 10}}, "image/png", pngData("embedded png"))
	plain := tags(10, "", "", "")

	// Named cover beats folder.jpg, embedded art and bigger images.
	writeAudio(t, root, "Named/1.mp3", art)
	writeFile(t, root, "Named/Folder.JPG", jpegData("folder"))
	writeFile(t, root, "Named/COVER.png", pngData("cover"))
	writeFile(t, root, "Named/huge.jpg", jpegData(strings.Repeat("x", 5000)))

	// Embedded art (of the first track that has any) beats loose images.
	writeAudio(t, root, "Embedded/1.mp3", plain)
	writeAudio(t, root, "Embedded/2.mp3", art)
	writeFile(t, root, "Embedded/scan.jpg", jpegData("loose"))

	// Otherwise the largest image.
	writeAudio(t, root, "Largest/1.mp3", plain)
	writeFile(t, root, "Largest/small.jpg", jpegData("s"))
	writeFile(t, root, "Largest/big.webp", webpData("bigger image"))

	// Disc folders: a cover inside a disc folder counts, but the book
	// folder's own comes first.
	writeAudio(t, root, "Discs/CD 1/1.mp3", plain)
	writeAudio(t, root, "Discs/CD 2/1.mp3", plain)
	writeFile(t, root, "Discs/CD 2/front.jpeg", jpegData("front"))
	writeAudio(t, root, "Prio/CD 1/1.mp3", plain)
	writeAudio(t, root, "Prio/CD 2/1.mp3", plain)
	writeFile(t, root, "Prio/CD 1/cover.jpg", jpegData("disc cover"))
	writeFile(t, root, "Prio/folder.jpg", jpegData("book folder art"))

	// Single-file books: same-named image, else embedded; never folder art.
	writeAudio(t, root, "Singles/One.m4b", art)
	writeAudio(t, root, "Singles/Two.m4b", plain)
	writeFile(t, root, "Singles/two.jpg", jpegData("two"))
	writeFile(t, root, "Singles/cover.jpg", jpegData("folder cover"))
	writeAudio(t, root, "Singles/Three.m4b", plain)

	writeAudio(t, root, "None/1.mp3", plain)

	// Content decides: a "cover.jpg" that is not an image is passed over.
	writeAudio(t, root, "Fake/1.mp3", plain)
	writeFile(t, root, "Fake/cover.jpg", []byte("jpeg-bytes"))
	writeFile(t, root, "Fake/scan.png", pngData("real"))
	writeAudio(t, root, "Svg/1.mp3", plain)
	writeFile(t, root, "Svg/cover.png", []byte(`<svg xmlns="http://www.w3.org/2000/svg"/>`))

	// Embedded GIF and BMP art (BMP declared as JPEG: the bytes decide), and
	// art that is not an image at all.
	writeAudio(t, root, "Gif/1.mp3", withArt(plain, "image/gif", gifData("gif art")))
	writeAudio(t, root, "Bmp/1.mp3", withArt(plain, "image/jpeg", bmpData("bmp art")))
	writeAudio(t, root, "BadArt/1.mp3", withArt(plain, "image/jpeg", []byte("<html>not an image</html>")))

	state := filepath.Join(root, ".bookbeam")
	tl := openTestLib(t, root, state)
	tl.scan(t)
	x := tl.Index()

	check := func(book, kind, source, mime string) {
		t.Helper()
		c := bookByPath(t, x, book).Cover
		if c == nil {
			t.Errorf("%s: no cover", book)
			return
		}
		if c.Kind != kind || (source != "" && c.Source != source) || c.MIME != mime || c.Version == "" {
			t.Errorf("%s: cover %+v, want %s %s %s", book, c, kind, source, mime)
		}
	}
	check("Named", CoverFile, "Named/COVER.png", "image/png")
	check("Embedded", CoverEmbedded, "", "image/png")
	check("Largest", CoverFile, "Largest/big.webp", "image/webp")
	check("Discs", CoverFile, "Discs/CD 2/front.jpeg", "image/jpeg")
	check("Prio", CoverFile, "Prio/folder.jpg", "image/jpeg")
	check("Singles/One.m4b", CoverEmbedded, "", "image/png")
	check("Singles/Two.m4b", CoverFile, "Singles/two.jpg", "image/jpeg")
	check("Fake", CoverFile, "Fake/scan.png", "image/png")
	check("Gif", CoverEmbedded, "", "image/gif")
	check("Bmp", CoverEmbedded, "", "image/bmp")
	for _, book := range []string{"Singles/Three.m4b", "None", "Svg", "BadArt"} {
		if c := bookByPath(t, x, book).Cover; c != nil {
			t.Errorf("%s: unexpected cover %+v", book, c)
		}
	}

	emb := bookByPath(t, x, "Embedded").Cover
	data, err := os.ReadFile(tl.CoverPath(emb))
	if err != nil || string(data) != string(art.PicData) {
		t.Fatalf("extracted cover = %q, %v", data, err)
	}
	if filepath.Dir(tl.CoverPath(emb)) != filepath.Join(state, "covers") || len(emb.Source) != 44 {
		t.Errorf("cover cache location %q", tl.CoverPath(emb))
	}
	if gif := bookByPath(t, x, "Gif").Cover; !strings.HasSuffix(gif.Source, ".gif") {
		t.Errorf("gif cached as %q", gif.Source)
	}
	// Embedded, Singles/One, Gif, Bmp and BadArt.
	if got := tl.prober.picCalls.Load(); got != 5 {
		t.Errorf("picture extractions = %d, want 5", got)
	}

	// Rescans reuse extracted covers and remember failed extractions.
	tl.scan(t)
	if got := tl.prober.picCalls.Load(); got != 5 {
		t.Errorf("covers re-extracted on rescan: %d", got)
	}
	// So does a restart.
	tl2 := openTestLib(t, root, state)
	tl2.scan(t)
	if got := tl2.prober.picCalls.Load(); got != 0 {
		t.Errorf("covers re-extracted after restart: %d", got)
	}

	// A removed book keeps its cached cover for a grace period (the share
	// may come back), then it is pruned.
	if err := os.RemoveAll(filepath.Join(root, "Embedded")); err != nil {
		t.Fatal(err)
	}
	stale := tl2.CoverPath(emb)
	tl2.scan(t)
	if _, err := os.Stat(stale); err != nil {
		t.Errorf("cover of a just-vanished book was pruned: %v", err)
	}
	*tl2.clock = tl2.clock.Add(missingGrace + time.Hour)
	tl2.scan(t)
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Errorf("stale cover not pruned after the grace period: %v", err)
	}
}

func TestScanCacheVersionsAndAddedAt(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(t.TempDir(), "state")
	writeAudio(t, root, "Old/1.mp3", tags(10, "", "Old", ""))
	writeAudio(t, root, "Old/2.mp3", tags(10, "", "Old", ""))
	writeFile(t, root, "Broken/1.mp3", []byte("not probeable"))
	mtime := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
	for _, rel := range []string{"Old/1.mp3", "Old/2.mp3"} {
		if err := os.Chtimes(filepath.Join(root, rel), mtime, mtime.Add(-time.Duration(len(rel))*time.Hour)); err != nil {
			t.Fatal(err)
		}
	}

	tl := openTestLib(t, root, state)
	if tl.Ready() || tl.Index().Len() != 0 {
		t.Fatal("fresh library should not be ready")
	}
	if !tl.scan(t) {
		t.Fatal("first scan must report a change")
	}
	x1 := tl.Index()
	if got := tl.prober.calls.Load(); got != 3 {
		t.Fatalf("probe calls = %d, want 3", got)
	}
	old := bookByPath(t, x1, "Old")
	if want := mtime.Add(-9 * time.Hour).UnixMilli(); old.AddedAt != want {
		t.Errorf("first-scan addedAt = %d, want newest mtime %d", old.AddedAt, want)
	}
	broken := bookByPath(t, x1, "Broken")
	if broken.Tracks[0].Duration != 0 {
		t.Error("failed probe must yield duration 0")
	}

	// Unchanged rescan: nothing probed (failed files are not retried by a
	// periodic scan), same version, newer scannedAt.
	*tl.clock = tl.clock.Add(time.Hour)
	if tl.scan(t) {
		t.Error("unchanged rescan reported a change")
	}
	if got := tl.prober.calls.Load(); got != 3 {
		t.Errorf("unchanged rescan probed %d files", got-3)
	}
	x2 := tl.Index()
	if x2.Version != x1.Version || x2.ScannedAt <= x1.ScannedAt {
		t.Errorf("versions %s/%s scannedAt %d/%d", x1.Version, x2.Version, x1.ScannedAt, x2.ScannedAt)
	}

	// A full rescan retries failures.
	if _, err := tl.Scan(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if got := tl.prober.calls.Load(); got != 4 {
		t.Errorf("retry probed %d files, want 1", got-3)
	}

	// Restart: the persisted index is served immediately.
	tl2 := openTestLib(t, root, state)
	if !tl2.Ready() || tl2.Index().Version != x1.Version || tl2.Index().Len() != 2 {
		t.Fatalf("reloaded index: ready=%v version=%s", tl2.Ready(), tl2.Index().Version)
	}
	*tl2.clock = tl.clock.Add(time.Hour)

	// New book: addedAt = now. Changed file: re-probed, version changes.
	writeAudio(t, root, "New/1.mp3", tags(5, "", "New", ""))
	writeAudio(t, root, "Old/2.mp3", tags(20, "", "Old", ""))
	if !tl2.scan(t) {
		t.Fatal("changes not detected")
	}
	if got := tl2.prober.calls.Load(); got != 2 {
		t.Errorf("probed %d files after change, want 2", got)
	}
	x3 := tl2.Index()
	if nb := bookByPath(t, x3, "New"); nb.AddedAt != tl2.clock.UnixMilli() {
		t.Errorf("new book addedAt = %d, want now", nb.AddedAt)
	}
	if ob := bookByPath(t, x3, "Old"); ob.AddedAt != old.AddedAt || ob.Duration != 30 {
		t.Errorf("old book after change: addedAt %d duration %v", ob.AddedAt, ob.Duration)
	}

	// Removed files leave the index at once, but their probe results stay
	// cached for a grace period.
	if err := os.RemoveAll(filepath.Join(root, "Old")); err != nil {
		t.Fatal(err)
	}
	tl2.scan(t)
	if e := tl2.files["Old/1.mp3"]; e == nil || e.Missing != tl2.clock.UnixMilli() {
		t.Errorf("vanished file's cache entry = %+v, want it kept and marked missing", e)
	}
	if got := bookPaths(tl2.Index()); !reflect.DeepEqual(got, []string{"Broken", "New"}) {
		t.Errorf("books after removal: %q", got)
	}
	*tl2.clock = tl2.clock.Add(missingGrace + time.Minute)
	tl2.scan(t)
	if _, ok := tl2.files["Old/1.mp3"]; ok {
		t.Error("vanished file still cached after the grace period")
	}
}

func TestRunNotifiesAndRescans(t *testing.T) {
	root := t.TempDir()
	writeAudio(t, root, "A/1.mp3", tags(10, "", "", ""))
	tl := openTestLib(t, root, filepath.Join(root, ".bookbeam"))
	events := make(chan ScanEvent, 4)
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
	if ev := next(); !ev.Changed || ev.Manual || ev.Err != nil || ev.Version != tl.Index().Version {
		t.Fatalf("initial scan event %+v", ev)
	}
	tl.RequestRescan()
	if !tl.Scanning() {
		t.Error("Scanning() false right after RequestRescan")
	}
	if ev := next(); ev.Changed || !ev.Manual {
		t.Fatalf("manual rescan event %+v", ev)
	}
}

func TestOpenRejectsMissingRoot(t *testing.T) {
	if _, err := Open(Options{Root: filepath.Join(t.TempDir(), "nope"), StateDir: t.TempDir()}); err == nil {
		t.Fatal("expected error")
	}
}

func TestProbePanicIsContained(t *testing.T) {
	root := t.TempDir()
	writeAudio(t, root, "A/1.mp3", tags(10, "", "", ""))
	l, err := Open(Options{Root: root, StateDir: t.TempDir(), Probe: func(string, media.Options) (*media.Info, error) {
		panic("boom")
	}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Scan(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if l.Index().Len() != 1 {
		t.Fatal("book with panicking probe must still be listed")
	}
}

func TestCyrillicNames(t *testing.T) {
	for name, want := range map[string]string{
		"Мастер и Маргарита (Диск 2)": "Диск 2", "ДИСК 03": "Диск 3", "Часть 1": "Часть 1", "CD 4": "CD 4",
	} {
		if got := discLabel(name); got != want {
			t.Errorf("discLabel(%q) = %q, want %q", name, got, want)
		}
	}
	for _, s := range []string{"Неизвестный альбом", "неизвестно", "Без названия", "Трек 05", "Аудиокнига"} {
		if !junkTitleRE.MatchString(s) {
			t.Errorf("%q should be a junk title", s)
		}
	}
	for _, s := range []string{"Неизвестный исполнитель", "Разные исполнители", "Сборник"} {
		if !junkPersonRE.MatchString(s) {
			t.Errorf("%q should be a junk person", s)
		}
	}
	if got := usableTitle("Мастер и Маргарита"); got != "Мастер и Маргарита" {
		t.Errorf("usableTitle dropped a real Cyrillic title: %q", got)
	}
	if got := stripDiscMarker("Мастер и Маргарита (Диск 1)"); got != "Мастер и Маргарита" {
		t.Errorf("stripDiscMarker = %q", got)
	}
	// A name copied from an old Windows archive: raw Windows-1251 bytes.
	cp := "01 - \xc3\xeb\xe0\xe2\xe0 \xef\xe5\xf0\xe2\xe0\xff.mp3" // "01 - Глава первая.mp3"
	if got := fileTitle(cp); got != "Глава первая" {
		t.Errorf("fileTitle(cp1251) = %q", got)
	}
	if got, _ := cleanName("\xcf\xe8\xea\xed\xe8\xea (1972)"); got != "Пикник" {
		t.Errorf("cleanName = %q", got)
	}
}

func TestAnthologies(t *testing.T) {
	root := t.TempDir()
	story := func(author, title, album string) fakeFile {
		f := tags(1800, title, album, author)
		f.AlbumArtist = "Модель Для Сборки"
		return f
	}
	// A radio show's year: stories by different authors, one in two parts.
	writeAudio(t, root, "MDS/1998/203 Pelevin Viktor - Problemy vervolka.mp3", story("Пелевин Виктор", "Проблемы верволка в ср полосе", "MDS_1998.01.15"))
	writeAudio(t, root, "MDS/1998/204 Pelevin Viktor - Zhjoltaja Strela.mp3", story("Пелевин Виктор", "Жёлтая Стрела", "MDS_1998.01.15"))
	writeAudio(t, root, "MDS/1998/205 Pelevin Viktor - Princ Gosplana 1.mp3", story("Пелевин Виктор", "Принц Госплана (часть 1)", "MDS_1998.01.29"))
	writeAudio(t, root, "MDS/1998/205 Pelevin Viktor - Princ Gosplana 2.mp3", story("Пелевин Виктор", "Принц Госплана (часть 2)", "MDS_1998.01.29"))
	writeAudio(t, root, "MDS/1998/206 Bachilo - Pravilnaya skazka.mp3", story("Александр Бачило", "Правильная сказка", "MDS_1998.02.05"))
	writeAudio(t, root, "MDS/1998/207 Zorich - Noch.mp3", story("Александр Зорич", "Ночь в Палеонтологическом музее", "MDS_1998.02.12"))
	writeAudio(t, root, "MDS/1998/208 Asimov - Robot.mp3", story("Азимов Айзек", "Робот Эл-76", "MDS_1998.02.19"))
	writeAudio(t, root, "MDS/1998/209 Sheckley - Zapah.mp3", story("Шекли Роберт", "Запах мысли", "MDS_1998.02.26"))
	writeAudio(t, root, "MDS/1998/210 Bradbury - Vino.mp3", story("Брэдбери Рэй", "Вино из одуванчиков", "MDS_1998.03.05"))
	// Untagged anthology: authors from "Author - Title" names; two parts.
	for _, n := range []string{"Аверин Никита - Часть 1. Цена победы.mp3", "Аверин Никита - Часть 2. Цена победы.mp3", "Александр Бачило - Правильная сказка.mp3", "Майкл Маршалл Смит - Запах.mp3", "Андрей Дашков - Латая дыру.mp3"} {
		writeAudio(t, root, "MDS/Season 2/"+n, tags(1800, "", "", ""))
	}
	// A real book: one author, the album artist is the narrator.
	for i, n := range []string{"01 - Глава 1.mp3", "02 - Глава 2.mp3", "03 - Глава 3.mp3"} {
		f := tags(1800, fmt.Sprintf("Глава %d", i+1), "Восстание Персеполя", "Джеймс Кори")
		f.AlbumArtist = "Кирилл Головин"
		writeAudio(t, root, "Expanse/Пространство 07/"+n, f)
	}

	tl := openTestLib(t, root, filepath.Join(root, ".bookbeam"))
	tl.scan(t)
	x := tl.Index()

	got := map[string][]string{}
	for _, b := range x.Books {
		got[b.Folder] = append(got[b.Folder], fmt.Sprintf("%s / %s / %d", b.Title, b.Author, len(b.Tracks)))
	}
	want := map[string][]string{
		"MDS/1998": {
			"Проблемы верволка в ср полосе / Пелевин Виктор / 1",
			"Жёлтая Стрела / Пелевин Виктор / 1",
			"Принц Госплана / Пелевин Виктор / 2",
			"Правильная сказка / Александр Бачило / 1",
			"Ночь в Палеонтологическом музее / Александр Зорич / 1",
			"Робот Эл-76 / Азимов Айзек / 1",
			"Запах мысли / Шекли Роберт / 1",
			"Вино из одуванчиков / Брэдбери Рэй / 1",
		},
		"MDS/Season 2": {
			"Цена победы / Аверин Никита / 2",
			"Запах / Майкл Маршалл Смит / 1",
			"Латая дыру / Андрей Дашков / 1",
			"Правильная сказка / Александр Бачило / 1",
		},
		"Expanse": {"Восстание Персеполя / Джеймс Кори / 3"},
	}
	for folder, w := range want {
		g := got[folder]
		sort.Strings(g)
		sort.Strings(w)
		if !reflect.DeepEqual(g, w) {
			t.Errorf("%s:\n got %q\nwant %q", folder, g, w)
		}
	}
	if b := bookByPath(t, x, "Expanse/Пространство 07"); b.Narrator != "Кирилл Головин" {
		t.Errorf("album artist should be the narrator of a book: %q", b.Narrator)
	}
	for _, b := range x.Books {
		if b.Folder == "MDS/1998" && b.Narrator != "" {
			t.Errorf("anthology show name used as narrator: %q", b.Narrator)
		}
	}
}

func TestSplitAuthorTitle(t *testing.T) {
	for in, want := range map[string][2]string{
		"273  Каттнер Генри - День не в счет":                 {"Каттнер Генри", "День не в счет"},
		"565  Kim_Njuman_-_Egipetskaya_Alleya":                {"Kim Njuman", "Egipetskaya Alleya"},
		"01 Oleg Ovchinnikov - Operatory odnostronney svyazy": {"Oleg Ovchinnikov", "Operatory odnostronney svyazy"},
		"19 Paul Gossen, Sergey Chekmayev - Gotick blues":     {"Paul Gossen, Sergey Chekmayev", "Gotick blues"},
		"31 июня":             {"", "31 июня"},
		"3-D Action в натуре": {"", "3-D Action в натуре"},
		"Жёлтая Стрела":       {"", "Жёлтая Стрела"},
		"01 - Глава 1":        {"", "01 - Глава 1"},
	} {
		a, ti := splitAuthorTitle(in)
		if a != want[0] || (a != "" && ti != want[1]) {
			t.Errorf("splitAuthorTitle(%q) = %q, %q; want %q", in, a, ti, want)
		}
	}
}
