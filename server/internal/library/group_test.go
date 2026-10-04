package library

import (
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/vburenin/bookbeam/server/internal/media"
)

// scanFiles builds a library of fake audio files and scans it.
func scanFiles(t *testing.T, files map[string]fakeFile) *Index {
	t.Helper()
	root := t.TempDir()
	for rel, f := range files {
		writeAudio(t, root, rel, f)
	}
	tl := openTestLib(t, root, filepath.Join(root, ".bookbeam"))
	tl.scan(t)
	return tl.Index()
}

// fake builds a fake file from tag values.
type fake struct {
	title, album, artist string
	track, disc          int
}

func (f fake) file() fakeFile {
	ff := tags(60, f.title, f.album, f.artist)
	ff.Track, ff.Disc = f.track, f.disc
	return ff
}

func trackNames(b *Book) []string {
	var out []string
	for _, t := range b.Tracks {
		out = append(out, strings.TrimPrefix(t.Path, b.Path+"/"))
	}
	return out
}

func TestTrackOrder(t *testing.T) {
	words := []string{"One", "Two", "Three", "Four", "Five", "Six", "Seven", "Eight", "Nine", "Ten", "Eleven", "Twelve"}
	wordFiles := map[string]fakeFile{}
	var wordOrder []string
	for i, w := range words {
		name := "Chapter " + w + ".mp3"
		wordFiles["Words/"+name] = fake{track: i + 1}.file()
		wordOrder = append(wordOrder, name)
	}
	chapters := []string{"Prologue", "The Boy Who Lived", "The Vanishing Glass", "Letters", "Epilogue"}
	chapterFiles := map[string]fakeFile{}
	var chapterOrder []string
	for i, c := range chapters {
		chapterFiles["Titles/"+c+".mp3"] = fake{title: c, track: i + 1}.file()
		chapterOrder = append(chapterOrder, c+".mp3")
	}

	tests := []struct {
		name  string
		files map[string]fakeFile
		book  string
		want  []string
	}{
		{"word-numbered files follow their track tags", wordFiles, "Words", wordOrder},
		{"chapter-titled files follow their track tags", chapterFiles, "Titles", chapterOrder},
		{"numbered names win over contradicting tags", map[string]fakeFile{
			"Num/01 Intro.mp3":   fake{track: 2}.file(),
			"Num/02 Chapter.mp3": fake{track: 1}.file(),
		}, "Num", []string{"01 Intro.mp3", "02 Chapter.mp3"}},
		{"incomplete tags keep the name order", map[string]fakeFile{
			"Partial/B.mp3": fake{track: 1}.file(),
			"Partial/A.mp3": fake{}.file(),
			"Partial/C.mp3": fake{track: 2}.file(),
		}, "Partial", []string{"A.mp3", "B.mp3", "C.mp3"}},
		{"duplicate tags keep the name order", map[string]fakeFile{
			"Dup/B.mp3": fake{track: 1}.file(),
			"Dup/A.mp3": fake{track: 1}.file(),
		}, "Dup", []string{"A.mp3", "B.mp3"}},
		{"the extension never decides", map[string]fakeFile{
			"Sort/Chapter 2-2.mp3":             fake{}.file(),
			"Sort/Chapter 1 (continued).mp3":   fake{}.file(),
			"Sort/Chapter 2.mp3":               fake{}.file(),
			"Sort/Chapter 1.mp3":               fake{}.file(),
			"Sort/Chapter 1 - second half.mp3": fake{}.file(),
		}, "Sort", []string{"Chapter 1.mp3", "Chapter 1 (continued).mp3", "Chapter 1 - second half.mp3", "Chapter 2.mp3", "Chapter 2-2.mp3"}},
		{"names repeating one number defer to tags", map[string]fakeFile{
			"Same/Book (2011) - Prologue.mp3":    fake{track: 1}.file(),
			"Same/Book (2011) - Chapter One.mp3": fake{track: 2}.file(),
			"Same/Book (2011) - Epilogue.mp3":    fake{track: 3}.file(),
		}, "Same", []string{"Book (2011) - Prologue.mp3", "Book (2011) - Chapter One.mp3", "Book (2011) - Epilogue.mp3"}},
		{"disc tags order a flat folder", map[string]fakeFile{
			"Flat/Alpha.mp3": fake{disc: 2, track: 1}.file(),
			"Flat/Beta.mp3":  fake{disc: 1, track: 2}.file(),
			"Flat/Gamma.mp3": fake{disc: 1, track: 1}.file(),
			"Flat/Delta.mp3": fake{disc: 2, track: 2}.file(),
		}, "Flat", []string{"Gamma.mp3", "Beta.mp3", "Alpha.mp3", "Delta.mp3"}},
		{"tags order each disc of a disc book", map[string]fakeFile{
			"DiscBook/CD 1/Zed.mp3": fake{track: 2}.file(),
			"DiscBook/CD 1/Ann.mp3": fake{track: 1}.file(),
			"DiscBook/CD 2/Bob.mp3": fake{track: 1}.file(),
			"DiscBook/CD 2/Cat.mp3": fake{track: 2}.file(),
		}, "DiscBook", []string{"CD 1/Ann.mp3", "CD 1/Zed.mp3", "CD 2/Bob.mp3", "CD 2/Cat.mp3"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			x := scanFiles(t, tt.files)
			if got := trackNames(bookByPath(t, x, tt.book)); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("order:\n got %q\nwant %q", got, tt.want)
			}
		})
	}
}

func TestAlbumGrouping(t *testing.T) {
	dahl := map[string]fakeFile{}
	for _, b := range []string{"Matilda", "The BFG", "The Witches", "Danny the Champion of the World"} {
		dahl["Roald Dahl/"+b+".mp3"] = fake{title: b, album: b, artist: "Roald Dahl"}.file()
	}
	tests := []struct {
		name  string
		files map[string]fakeFile
		want  []string
	}{
		{"each file its own album: separate books", dahl, []string{
			"Roald Dahl/Danny the Champion of the World.mp3", "Roald Dahl/Matilda.mp3",
			"Roald Dahl/The BFG.mp3", "Roald Dahl/The Witches.mp3",
		}},
		{"album named in the file name only", map[string]fakeFile{
			"Kids/Roald Dahl - Matilda (Unabridged).mp3": fake{album: "Matilda"}.file(),
			"Kids/Roald Dahl - The BFG.mp3":              fake{album: "The BFG"}.file(),
		}, []string{"Kids/Roald Dahl - Matilda (Unabridged).mp3", "Kids/Roald Dahl - The BFG.mp3"}},
		{"shared album: one book", map[string]fakeFile{
			"Shared/01 Opening.mp3": fake{title: "Opening", album: "Shared Book"}.file(),
			"Shared/02 Middle.mp3":  fake{title: "Middle", album: "Shared Book"}.file(),
		}, []string{"Shared"}},
		{"albums differing only by disc: one book", map[string]fakeFile{
			"Parts/Book CD1.mp3": fake{title: "Book CD1", album: "Book CD1"}.file(),
			"Parts/Book CD2.mp3": fake{title: "Book CD2", album: "Book CD2"}.file(),
		}, []string{"Parts"}},
		{"albums unrelated to the files: one book", map[string]fakeFile{
			"Odd/a.mp3": fake{album: "Xylophone"}.file(),
			"Odd/b.mp3": fake{album: "Yesterday"}.file(),
		}, []string{"Odd"}},
		{"one file without an album: one book", map[string]fakeFile{
			"Mix/Matilda.mp3": fake{title: "Matilda", album: "Matilda"}.file(),
			"Mix/notes.mp3":   fake{}.file(),
		}, []string{"Mix"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := bookPaths(scanFiles(t, tt.files)); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("books:\n got %q\nwant %q", got, tt.want)
			}
		})
	}
}

func TestDiscFolders(t *testing.T) {
	files := map[string]fakeFile{
		"Paren/It/It (Disc 1)/01.mp3":            fake{}.file(),
		"Paren/It/It (Disc 2)/01.mp3":            fake{}.file(),
		"Bracket/Dune/Dune [CD1]/a.mp3":          fake{}.file(),
		"Bracket/Dune/Dune [CD2]/a.mp3":          fake{}.file(),
		"Suffix/Emma/CD 01 - Chapters 1-4/a.mp3": fake{}.file(),
		"Suffix/Emma/CD 02 - Chapters 5-9/a.mp3": fake{}.file(),
		"Bare/Numbered/1/a.mp3":                  fake{album: "Numbered (Disc 1)", disc: 1}.file(),
		"Bare/Numbered/1/b.mp3":                  fake{album: "Numbered (Disc 1)", disc: 1}.file(),
		"Bare/Numbered/2/a.mp3":                  fake{album: "Numbered (Disc 2)", disc: 2}.file(),
		"Series/Saga/1/a.mp3":                    fake{album: "Saga One"}.file(),
		"Series/Saga/2/a.mp3":                    fake{album: "Saga Two"}.file(),
		"Untagged/Vols/1/a.mp3":                  fake{}.file(),
		"Untagged/Vols/2/a.mp3":                  fake{}.file(),
		"SameDisc/Box/1/a.mp3":                   fake{album: "Box", disc: 1}.file(),
		"SameDisc/Box/2/a.mp3":                   fake{album: "Box", disc: 1}.file(),
		"Nested/Long/Part 2/CD 1/a.mp3":          fake{}.file(),
		"Nested/Long/Part 1/CD 2/a.mp3":          fake{}.file(),
		"Nested/Long/Part 1/CD 1/a.mp3":          fake{}.file(),
		"Nested/Long/Part 2/CD 2/a.mp3":          fake{}.file(),
		"TooDeep/X/Part 1/CD 1/Side A/a.mp3":     fake{}.file(),
		"Mixed/Book/CD 1/a.mp3":                  fake{}.file(),
		"Mixed/Book/Bonus/b.mp3":                 fake{}.file(),
		"PartMixed/Book/Part 1/a.mp3":            fake{}.file(),
		"PartMixed/Book/Part 2/CD 1/a.mp3":       fake{}.file(),
		"PartMixed/Book/Part 2/CD 2/a.mp3":       fake{}.file(),
		"NotNested/Book/Part 1/CD 1/a.mp3":       fake{}.file(),
		"NotNested/Book/Part 1/Extras/a.mp3":     fake{}.file(),
	}
	x := scanFiles(t, files)
	want := []string{
		"Bare/Numbered",
		"Bracket/Dune",
		"Mixed/Book/Bonus",
		"Mixed/Book/CD 1",
		"Nested/Long",
		"NotNested/Book/Part 1/CD 1",
		"NotNested/Book/Part 1/Extras",
		"Paren/It",
		"PartMixed/Book",
		"SameDisc/Box/1",
		"SameDisc/Box/2",
		"Series/Saga/1",
		"Series/Saga/2",
		"Suffix/Emma",
		"TooDeep/X/Part 1/CD 1/Side A",
		"Untagged/Vols/1",
		"Untagged/Vols/2",
	}
	if got := bookPaths(x); !reflect.DeepEqual(got, want) {
		t.Fatalf("books:\n got %q\nwant %q", got, want)
	}
	if got := trackNames(bookByPath(t, x, "Nested/Long")); !reflect.DeepEqual(got, []string{
		"Part 1/CD 1/a.mp3", "Part 1/CD 2/a.mp3", "Part 2/CD 1/a.mp3", "Part 2/CD 2/a.mp3",
	}) {
		t.Errorf("nested disc order: %q", got)
	}
	if got := trackNames(bookByPath(t, x, "PartMixed/Book")); !reflect.DeepEqual(got, []string{
		"Part 1/a.mp3", "Part 2/CD 1/a.mp3", "Part 2/CD 2/a.mp3",
	}) {
		t.Errorf("part with discs: %q", got)
	}
	if got := trackNames(bookByPath(t, x, "Bare/Numbered")); !reflect.DeepEqual(got, []string{"1/a.mp3", "1/b.mp3", "2/a.mp3"}) {
		t.Errorf("bare-number discs: %q", got)
	}
}

func TestDiscBookTitles(t *testing.T) {
	x := scanFiles(t, map[string]fakeFile{
		"Stephen King/It (1986)/Disc 1/01 Track.mp3": fake{title: "Track 1", album: "It (Disc 1)"}.file(),
		"Stephen King/It (1986)/Disc 1/02 Track.mp3": fake{title: "Track 2", album: "It (Disc 1)"}.file(),
		"Stephen King/It (1986)/Disc 2/01 Track.mp3": fake{title: "Track 1", album: "It (Disc 2)"}.file(),
		"Stephen King/It (1986)/Disc 2/02 Track.mp3": fake{title: "Track 2", album: "It (Disc 2)"}.file(),
		"Stephen King/Misery/CD1/1.mp3":              fake{title: "Chapter 1", album: "Misery CD1"}.file(),
		"Stephen King/Misery/CD2/1.mp3":              fake{title: "Chapter 2", album: "Misery CD2"}.file(),
		"Stephen King/Carrie/Carrie [CD1]/Track.mp3": fake{album: "Carrie"}.file(),
		"Stephen King/Carrie/Carrie [CD2]/Track.mp3": fake{album: "Carrie"}.file(),
		// Folder names that say nothing: the title must come from the albums.
		"Rips/king_it_rip/Disc 1/1.mp3": fake{album: "It (Disc 1)"}.file(),
		"Rips/king_it_rip/Disc 2/1.mp3": fake{album: "It (Disc 2)"}.file(),
		"Rips/misery_rip/CD1/1.mp3":     fake{album: "Misery CD1"}.file(),
		"Rips/misery_rip/CD2/1.mp3":     fake{album: "Misery CD2"}.file(),
		"Rips/carrie_rip/Disc 1/1.mp3":  fake{album: "Carrie, Disc 1 of 2"}.file(),
		"Rips/carrie_rip/Disc 2/1.mp3":  fake{album: "Carrie, Disc 1 of 2"}.file(),
		"Mixed Albums/1.mp3":            fake{album: "Alpha"}.file(),
		"Mixed Albums/2.mp3":            fake{album: "Beta"}.file(),
		"Mixed Albums/3.mp3":            fake{album: "Gamma"}.file(),
	})
	it := bookByPath(t, x, "Stephen King/It (1986)")
	if it.Title != "It" || it.Year != "1986" {
		t.Errorf("It: title %q year %q", it.Title, it.Year)
	}
	if got := titlesOf(it); !reflect.DeepEqual(got, []string{
		"Disc 1 · 01 Track", "Disc 1 · 02 Track", "Disc 2 · 01 Track", "Disc 2 · 02 Track",
	}) {
		t.Errorf("It track titles: %q", got)
	}
	misery := bookByPath(t, x, "Stephen King/Misery")
	if misery.Title != "Misery" || !reflect.DeepEqual(titlesOf(misery), []string{"Chapter 1", "Chapter 2"}) {
		t.Errorf("Misery: %q %q", misery.Title, titlesOf(misery))
	}
	if got := titlesOf(bookByPath(t, x, "Stephen King/Carrie")); !reflect.DeepEqual(got, []string{"CD 1 · Track", "CD 2 · Track"}) {
		t.Errorf("Carrie track titles: %q", got)
	}
	for path, want := range map[string]string{
		"Rips/king_it_rip": "It", "Rips/misery_rip": "Misery", "Rips/carrie_rip": "Carrie",
	} {
		if got := bookByPath(t, x, path).Title; got != want {
			t.Errorf("%s: title %q, want %q", path, got, want)
		}
	}
	if got := bookByPath(t, x, "Mixed Albums").Title; got != "Mixed Albums" {
		t.Errorf("albums without a majority: title %q, want the folder name", got)
	}
}

func titlesOf(b *Book) []string {
	var out []string
	for _, t := range b.Tracks {
		out = append(out, t.Title)
	}
	return out
}

func TestMetadataFromTracks(t *testing.T) {
	series := fake{album: "Right", artist: "Writer"}.file()
	series.Series, series.SeriesPart, series.Narrator = "The Saga", "2", "Reader"
	x := scanFiles(t, map[string]fakeFile{
		// An untagged publisher intro must not decide.
		"Intro/Tagged Book Folder/00 - Intro.mp3": fake{}.file(),
		"Intro/Tagged Book Folder/01 - Ch.mp3":    fake{album: "Proper Album", artist: "Proper Author"}.file(),
		"Intro/Tagged Book Folder/02 - Ch.mp3":    fake{album: "Proper Album", artist: "Proper Author"}.file(),
		// One self-contained file in a folder: its title tag.
		"TitleOnly/Some Folder Name/book.m4b": fake{title: "Real Book Title"}.file(),
		// One plain mp3 in a folder: the album first (the title may be a chapter's).
		"LoneMp3/Folder Title/chapter.mp3":   fake{title: "Chapter 1", album: "Album Title"}.file(),
		"LoneMp3/Untagged Album/chapter.mp3": fake{title: "Only Title"}.file(),
		// The majority wins; values present on some tracks only are used.
		"Majority/Book/1.mp3": fake{album: "Right", artist: "Writer"}.file(),
		"Majority/Book/2.mp3": series,
		"Majority/Book/3.mp3": fake{album: "Right", artist: "Writer"}.file(),
		"Majority/Book/4.mp3": fake{album: "Wrong", artist: "Other"}.file(),
	})
	type meta struct{ Title, Author, Narrator, Series, SeriesPart string }
	for path, want := range map[string]meta{
		"Intro/Tagged Book Folder":   {Title: "Proper Album", Author: "Proper Author"},
		"TitleOnly/Some Folder Name": {Title: "Real Book Title"},
		"LoneMp3/Folder Title":       {Title: "Album Title"},
		"LoneMp3/Untagged Album":     {Title: "Only Title"},
		"Majority/Book":              {Title: "Right", Author: "Writer", Narrator: "Reader", Series: "The Saga", SeriesPart: "2"},
	} {
		b := bookByPath(t, x, path)
		if got := (meta{b.Title, b.Author, b.Narrator, b.Series, b.SeriesPart}); got != want {
			t.Errorf("%s:\n got %+v\nwant %+v", path, got, want)
		}
	}
}

func TestTitleCleanup(t *testing.T) {
	for _, tt := range []struct{ name, title, year string }{
		{"1984 - George Orwell", "1984 - George Orwell", ""},
		{"2001 - A Space Odyssey", "2001 - A Space Odyssey", ""},
		{"03 - Caliban's War", "Caliban's War", ""},
		{"1. The Hobbit", "The Hobbit", ""},
		{"Hatchet [Unabridged]", "Hatchet", ""},
		{"Matilda (Unabridged Edition) (1988)", "Matilda", "1988"},
		{"Book (2001) [Abridged]", "Book", "2001"},
		{"Foo - Unabridged", "Foo", ""},
		{"Foo: Abridged Version", "Foo", ""},
		{"Non-abridged", "Non-abridged", ""},
		{"[Unabridged]", "[Unabridged]", ""},
	} {
		if title, year := cleanName(tt.name); title != tt.title || year != tt.year {
			t.Errorf("cleanName(%q) = %q, %q; want %q, %q", tt.name, title, year, tt.title, tt.year)
		}
	}
	for _, tt := range []struct{ title, author, want string }{
		{"George Orwell - 1984", "George Orwell", "1984"},
		{"1984 - george orwell", "George Orwell", "1984"},
		{"1984 – George Orwell", "George Orwell", "1984"},
		{"George Orwell", "George Orwell", "George Orwell"},
		{"Animal Farm", "George Orwell", "Animal Farm"},
		{"1984 - George Orwell", "", "1984 - George Orwell"},
	} {
		if got := stripAuthor(tt.title, tt.author); got != tt.want {
			t.Errorf("stripAuthor(%q, %q) = %q, want %q", tt.title, tt.author, got, tt.want)
		}
	}
	for _, junk := range []string{"Unknown Album (3/4/2009 9:23:15 PM)", "<Unknown>", "Audiobooks", "Track 7", "untitled"} {
		if usableTitle(junk) != "" {
			t.Errorf("title %q should be junk", junk)
		}
	}
	for _, junk := range []string{"Various Artists", "various", "VA", "<unknown>", "Unknown Artist"} {
		if usablePerson(junk) != "" {
			t.Errorf("person %q should be junk", junk)
		}
	}
	if usablePerson("Vanessa") != "Vanessa" || usableTitle("Unknown Soldier") != "Unknown Soldier" {
		t.Error("real names must survive")
	}

	stand := func() fakeFile {
		f := fake{title: "The Stand", album: "The Stand"}.file()
		f.Chapters = []media.Chapter{{Title: "a", Start: 0, End: 30}, {Title: "b", Start: 30, End: 60}}
		return f
	}
	x := scanFiles(t, map[string]fakeFile{
		"Orwell/1984 - George Orwell/a.mp3":   func() fakeFile { f := fake{}.file(); f.AlbumArtist = "George Orwell"; return f }(),
		"Orwell/2001 - A Space Odyssey/a.mp3": fake{artist: "Arthur C. Clarke"}.file(),
		"Junk/Wmp/a.mp3":                      fake{album: "Unknown Album (3/4/2009 9:23:15 PM)", artist: "Various Artists"}.file(),
		"Junk/Hatchet/a.mp3":                  fake{album: "Hatchet [Unabridged]"}.file(),
		"HP/Harry Potter 1/a.mp3":             fake{album: "Harry Potter"}.file(),
		"HP/Harry Potter 2/a.mp3":             fake{album: "Harry Potter"}.file(),
		"Stand/The Stand Part 1.m4b":          stand(),
		"Stand/The Stand Part 2.m4b":          stand(),
		"Same/Dune/a.mp3":                     fake{album: "Dune"}.file(),
		"Same/Dune Copy/a.mp3":                fake{album: "Dune"}.file(),
		"Untouched/Book One/a.mp3":            fake{album: "Shared"}.file(),
		"Untouched/Book Two/a.mp3":            fake{}.file(),
	})
	type meta struct{ Title, Author string }
	for path, want := range map[string]meta{
		"Orwell/1984 - George Orwell":   {"1984", "George Orwell"},
		"Orwell/2001 - A Space Odyssey": {"2001 - A Space Odyssey", "Arthur C. Clarke"},
		"Junk/Wmp":                      {"Wmp", ""},
		"Junk/Hatchet":                  {"Hatchet", ""},
		"HP/Harry Potter 1":             {"Harry Potter 1", ""},
		"HP/Harry Potter 2":             {"Harry Potter 2", ""},
		"Stand/The Stand Part 1.m4b":    {"The Stand Part 1", ""},
		"Stand/The Stand Part 2.m4b":    {"The Stand Part 2", ""},
		"Same/Dune":                     {"Dune", ""},
		"Same/Dune Copy":                {"Dune Copy", ""},
		"Untouched/Book One":            {"Shared", ""},
		"Untouched/Book Two":            {"Book Two", ""},
	} {
		b := bookByPath(t, x, path)
		if got := (meta{b.Title, b.Author}); got != want {
			t.Errorf("%s: got %+v, want %+v", path, got, want)
		}
	}
}

func TestModelLookups(t *testing.T) {
	x := scanFiles(t, map[string]fakeFile{
		"A/01.mp3": fake{}.file(),
		"A/02.mp3": fake{title: "longer tags make a bigger file"}.file(),
		"B/01.mp3": fake{}.file(),
	})
	hex12 := regexp.MustCompile(`^[0-9a-f]{12}$`)
	for _, b := range x.Books {
		for _, tr := range b.Tracks {
			if !hex12.MatchString(tr.Fingerprint) || tr.Fingerprint != TrackFingerprint(tr.Path, tr.Size, tr.ModTime) {
				t.Errorf("%s: fingerprint %q", tr.Path, tr.Fingerprint)
			}
		}
	}
	if TrackFingerprint("a.mp3", 1, 2) == TrackFingerprint("a.mp3", 1, 3) {
		t.Error("fingerprint ignores mtime")
	}

	a1, _, _ := x.TrackByPath("A/01.mp3")
	size := a1.Tracks[0].Size
	refs := x.TracksByBaseAndSize("01.mp3", size)
	if len(refs) != 2 || refs[0].Book.Path != "A" || refs[1].Book.Path != "B" || refs[0].Track != 0 {
		t.Errorf("TracksByBaseAndSize(01.mp3) = %+v", refs)
	}
	if got := x.TracksByBaseAndSize("02.mp3", size); len(got) != 0 {
		t.Errorf("size must match: %+v", got)
	}
	if refs := x.TracksByBaseAndSize("02.mp3", bookByPath(t, x, "A").Tracks[1].Size); len(refs) != 1 || refs[0].Track != 1 {
		t.Errorf("TracksByBaseAndSize(02.mp3) = %+v", refs)
	}
	var nilIndex *Index
	if nilIndex.TracksByBaseAndSize("x", 1) != nil {
		t.Error("nil index")
	}

	// Indexes saved by older versions lack fingerprints: NewIndex adds them.
	old := NewIndex([]*Book{{ID: "b_1", Path: "P", Tracks: []Track{{Path: "P/1.mp3", Size: 5, ModTime: 7}}}}, 1)
	if got := old.Books[0].Tracks[0].Fingerprint; got != TrackFingerprint("P/1.mp3", 5, 7) {
		t.Errorf("filled fingerprint %q", got)
	}
}
