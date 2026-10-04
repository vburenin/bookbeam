package media

import (
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The committed fixtures in testdata/ are produced by testdata/generate.sh;
// these tests pin down what that script writes and need no ffmpeg.

func TestFixtureMP3(t *testing.T) {
	info, err := ProbeFile("testdata/chapters.mp3", Options{WantPicture: true})
	if err != nil {
		t.Fatal(err)
	}
	expectDuration(t, info.Duration, 6, 0.001)
	expectFields(t, info, Info{
		Format: "mp3", SampleRate: 8000, Channels: 1, Bitrate: 8544,
		Title: "Fixture Title", Album: "Fixture Album", Artist: "Fixture Author",
		AlbumArtist: "Fixture Author", Composer: "Fixture Reader", Narrator: "Fixture Narrator",
		Genre: "Audiobook", Year: "2020", Comment: "Fixture comment",
		Series: "Fixture Series", SeriesPart: "2", Track: 2, TrackTotal: 5, Disc: 1, DiscTotal: 1,
	})
	expectChapters(t, info.Chapters,
		Chapter{Title: "Opening", Start: 0, End: 2},
		Chapter{Title: "Middle – ünïcødé", Start: 2, End: 4.25},
		Chapter{Title: "Closing", Start: 4.25, End: 6})
	if !info.HasPicture || info.Picture == nil || info.Picture.MIME != "image/png" || len(info.Picture.Data) < 50 {
		t.Errorf("picture = %v %+v, want a PNG", info.HasPicture, info.Picture)
	}
}

func TestFixtureM4B(t *testing.T) {
	info, err := ProbeFile("testdata/book.m4b", Options{WantPicture: true})
	if err != nil {
		t.Fatal(err)
	}
	expectDuration(t, info.Duration, 6, 0.001)
	expectFields(t, info, Info{
		Format: "mp4", SampleRate: 8000, Channels: 1,
		Title: "Fixture Book", Album: "Fixture Book", Artist: "Fixture Author",
		Composer: "Fixture Reader", Genre: "Audiobook", Year: "2021",
		Description: "A much longer synopsis of the fixture book.", Track: 1, TrackTotal: 1,
	})
	expectChapters(t, info.Chapters,
		Chapter{Title: "Opening", Start: 0, End: 2},
		Chapter{Title: "Middle – ünïcødé", Start: 2, End: 4.25},
		Chapter{Title: "Closing", Start: 4.25, End: 6})
	if info.Picture == nil || info.Picture.MIME != "image/png" {
		t.Errorf("picture = %+v, want PNG", info.Picture)
	}
}

func TestFixtureOpus(t *testing.T) {
	info, err := ProbeFile("testdata/tagged.opus", Options{})
	if err != nil {
		t.Fatal(err)
	}
	// 6 s exactly: the Opus pre-skip is excluded (ffprobe reports 6.0065).
	expectDuration(t, info.Duration, 6, 0.0001)
	expectFields(t, info, Info{
		Format: "opus", SampleRate: 48000, Channels: 1,
		Title: "Chapter Five", Album: "Fixture Opus", Artist: "Fixture Author",
		Narrator: "Opus Reader", Series: "Opus Series", SeriesPart: "3",
		Description: "Opus description", Comment: "Opus description", Track: 5, TrackTotal: 12,
	})
	expectChapters(t, info.Chapters,
		Chapter{Title: "Opening", Start: 0, End: 2},
		Chapter{Title: "Middle – ünïcødé", Start: 2, End: 4.25},
		Chapter{Title: "Closing", Start: 4.25, End: 6})
	if info.HasPicture {
		t.Error("HasPicture = true for a file without art")
	}
}

func TestPictureOnlyLoadedWhenWanted(t *testing.T) {
	for _, name := range []string{"chapters.mp3", "book.m4b"} {
		info, err := ProbeFile(filepath.Join("testdata", name), Options{})
		if err != nil {
			t.Fatal(err)
		}
		if !info.HasPicture || info.Picture != nil {
			t.Errorf("%s: HasPicture=%v Picture=%v, want true and nil", name, info.HasPicture, info.Picture)
		}
	}
}

func TestProbeFileErrors(t *testing.T) {
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty.mp3")
	writeFile(t, empty, nil)
	text := filepath.Join(dir, "notes.txt")
	writeFile(t, text, []byte("not audio at all"))
	junkMP3 := filepath.Join(dir, "junk.mp3")
	writeFile(t, junkMP3, []byte(strings.Repeat("junk", 1000)))

	if _, err := ProbeFile(empty, Options{}); !errors.Is(err, ErrUnsupported) {
		t.Errorf("empty file: err = %v, want ErrUnsupported", err)
	}
	if _, err := ProbeFile(text, Options{}); !errors.Is(err, ErrUnsupported) {
		t.Errorf("text file: err = %v, want ErrUnsupported", err)
	}
	if info, err := ProbeFile(junkMP3, Options{}); err == nil {
		t.Errorf("junk .mp3: got %+v, want an error", info)
	}
	if _, err := ProbeFile(dir, Options{}); err == nil {
		t.Error("directory: want an error")
	}
	if _, err := ProbeFile(filepath.Join(dir, "missing.mp3"), Options{}); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing file: err = %v, want ErrNotExist", err)
	}
}

func TestDetect(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		ext  string
		want string
	}{
		{"mp3 by sync", mpegStream(4, 128), "", "mp3"},
		{"mp3 behind id3", cat(id3TagBytes(3, 0, id3Frame23("TIT2", 0, id3Text("x"))), mpegStream(4, 128)), "", "mp3"},
		{"mp3 with junk prefix by extension", cat([]byte("junkjunk"), mpegStream(4, 128)), ".MP3", "mp3"},
		{"aac behind id3", cat(id3TagBytes(4, 0), adtsFrame(4, 2, 100), adtsFrame(4, 2, 100)), ".mp3", "aac"},
		{"flac behind id3", cat(id3TagBytes(3, 0), []byte("fLaC"), flacBlock(0, true, flacStreamInfoBlock(44100, 2, 44100))), ".mp3", "flac"},
		{"wav", wavFile(wavFmt(1, 1, 8000, 16), riffChunk("data", make([]byte, 16000))), ".mp3", "wav"},
		{"adts", cat(adtsFrame(4, 2, 100), adtsFrame(4, 2, 100)), "", "aac"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := mustProbe(t, tt.data, tt.ext, Options{})
			if info.Format != tt.want {
				t.Errorf("Format = %q, want %q", info.Format, tt.want)
			}
		})
	}

	if _, err := probeBytes([]byte{0x1A, 0x45, 0xDF, 0xA3, 0, 0, 0, 0}, ".webm", Options{}); !errors.Is(err, ErrUnsupported) {
		t.Errorf("webm: err = %v, want ErrUnsupported", err)
	}
}

func TestNormalizeChapters(t *testing.T) {
	got := normalizeChapters([]Chapter{
		{Title: " Third ", Start: 20},
		{Title: "", Start: 0},
		{Title: "First", Start: 0}, // same start: its title fills the untitled one
		{Title: "", Start: 10},
		{Title: "Beyond the end", Start: 40},
		{Title: "NaN", Start: math.NaN()},
		{Title: "Negative", Start: -0.0001},
	}, 30)
	expectChapters(t, got,
		Chapter{Title: "First", Start: 0, End: 10},
		Chapter{Title: "Chapter 2", Start: 10, End: 20},
		Chapter{Title: "Third", Start: 20, End: 30})

	// Unknown duration keeps a native end for the last chapter.
	got = normalizeChapters([]Chapter{{Title: "A", Start: 0}, {Title: "B", Start: 5, End: 9}}, 0)
	expectChapters(t, got, Chapter{Title: "A", Start: 0, End: 5}, Chapter{Title: "B", Start: 5, End: 9})

	if got := normalizeChapters(nil, 10); got != nil {
		t.Errorf("nil chapters → %v, want nil", got)
	}
	// Idempotent.
	once := normalizeChapters([]Chapter{{Start: 3}, {Start: 1}}, 5)
	twice := normalizeChapters(once, 5)
	expectChapters(t, twice, once...)
}

func TestTagMapPriorities(t *testing.T) {
	primary := tagMap{}
	primary.add("Title", " Main ")
	primary.add("PERFORMER", "Performer")
	primary.add("narrator", "Narrator")
	primary.add("album_artist", "AA")
	primary.add("Artist", "One", "Two", "One")
	primary.add("TRACKNUMBER", "03")
	primary.add("TRACKTOTAL", "12")
	primary.add("DISCNUMBER", "2/3")
	primary.add("DATE", "2011-05-03T00:00:00Z")
	primary.add("SERIES-PART", "1.5")
	primary.add("MVNM", "Movement Series")
	secondary := tagMap{}
	secondary.add("TITLE", "Fallback")
	secondary.add("ALBUM", "Fallback Album")
	secondary.add("SERIES", "Secondary Series") // primary's MVNM fallback still wins

	info := &Info{}
	primary.apply(info)
	secondary.apply(info)
	expectFields(t, info, Info{
		Title: "Main", Narrator: "Narrator", AlbumArtist: "AA", Artist: "One, Two",
		Track: 3, TrackTotal: 12, Disc: 2, DiscTotal: 3, Year: "2011", SeriesPart: "1.5",
		Series: "Movement Series", Album: "Fallback Album",
	})
}

func TestTextHelpers(t *testing.T) {
	if got := legacyText([]byte("caf\xe9")); got != "café" {
		t.Errorf("legacyText = %q", got)
	}
	if got := legacyText([]byte("café")); got != "café" { // UTF-8 mislabelled as Latin-1
		t.Errorf("legacyText(utf8) = %q", got)
	}
	if got := cleanText("\ufeff a\x00b\x01 \n"); got != "ab" {
		t.Errorf("cleanText = %q", got)
	}
	if got := cleanText("bad \xff utf8"); got != "bad � utf8" {
		t.Errorf("cleanText invalid utf8 = %q", got)
	}
	for in, want := range map[string]string{"2011": "2011", "2011-05-03": "2011", "20110": "20110", "c. 1813": "c. 1813", "": ""} {
		if got := yearOf(in); got != want {
			t.Errorf("yearOf(%q) = %q, want %q", in, got, want)
		}
	}
	if n, total := parsePair(" 03 / 12 "); n != 3 || total != 12 {
		t.Errorf("parsePair = %d/%d", n, total)
	}
	if got := bomText(utf16Bytes("Ünï", true, true)); got != "Ünï" {
		t.Errorf("bomText BE = %q", got)
	}
	if got := bomText(utf16Bytes("Ünï", false, true)); got != "Ünï" {
		t.Errorf("bomText LE = %q", got)
	}
}

func TestPictureMIME(t *testing.T) {
	tests := []struct {
		declared string
		data     []byte
		want     string
	}{
		{"", testJPEG, "image/jpeg"},
		{"image/png", testJPEG, "image/jpeg"}, // magic bytes win
		{"", testPNG, "image/png"},
		{"", []byte("RIFF\x00\x00\x00\x00WEBPVP8 "), "image/webp"},
		{"JPG", []byte("unknown"), "image/jpeg"},
		{"image/x-custom", []byte("unknown"), "image/x-custom"},
		{"-->", []byte("http://example.com/cover.jpg"), ""},
		{"", []byte("unknown"), ""},
	}
	for _, tt := range tests {
		if got := pictureMIME(tt.declared, tt.data); got != tt.want {
			t.Errorf("pictureMIME(%q, %q) = %q, want %q", tt.declared, tt.data[:4], got, tt.want)
		}
	}
}

func BenchmarkProbeFile(b *testing.B) {
	for _, name := range []string{"chapters.mp3", "book.m4b", "tagged.opus"} {
		b.Run(name, func(b *testing.B) {
			path := filepath.Join("testdata", name)
			for b.Loop() {
				if _, err := ProbeFile(path, Options{}); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
