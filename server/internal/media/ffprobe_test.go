package media

import (
	"errors"
	"os/exec"
	"path/filepath"
	"testing"
)

const ffprobeJSON = `{
  "streams": [
    {"codec_type": "audio", "codec_name": "opus", "sample_rate": "48000", "channels": 2,
     "tags": {"TITLE": "Stream Title", "ALBUM_ARTIST": "Album Artist", "PERFORMER": "Reader", "series-part": "2"},
     "disposition": {"attached_pic": 0}},
    {"codec_type": "video", "codec_name": "mjpeg", "disposition": {"attached_pic": 1}}
  ],
  "chapters": [
    {"start_time": "60.000000", "end_time": "120.000000", "tags": {"title": "Second"}},
    {"start_time": "0.000000", "end_time": "60.000000", "tags": {"TITLE": "First"}},
    {"start_time": "120.000000", "end_time": "180.000000"},
    {"start_time": "bogus", "end_time": "1"}
  ],
  "format": {"format_name": "ogg", "duration": "180.500000", "bit_rate": "32000",
             "tags": {"Album": "Format Album", "track": "4/10", "SERIES": "Saga", "date": "1999"}}
}`

func TestParseFFprobe(t *testing.T) {
	info, err := parseFFprobe([]byte(ffprobeJSON))
	if err != nil {
		t.Fatal(err)
	}
	expectFields(t, info, Info{
		Format: "opus", Bitrate: 32000, SampleRate: 48000, Channels: 2,
		Title: "Stream Title", Album: "Format Album", AlbumArtist: "Album Artist", Narrator: "Reader",
		Series: "Saga", SeriesPart: "2", Year: "1999", Track: 4, TrackTotal: 10,
	})
	expectDuration(t, info.Duration, 180.5, 1e-9)
	expectChapters(t, info.Chapters,
		Chapter{Title: "First", Start: 0, End: 60},
		Chapter{Title: "Second", Start: 60, End: 120},
		Chapter{Title: "Chapter 3", Start: 120, End: 180.5})
	if !info.HasPicture {
		t.Error("attached picture not reported")
	}

	for _, bad := range []string{"", "{", `{"format": {}}`} {
		if _, err := parseFFprobe([]byte(bad)); err == nil {
			t.Errorf("parseFFprobe(%q): want an error", bad)
		}
	}
}

func TestFFprobeFormatNames(t *testing.T) {
	tests := []struct{ name, codec, want string }{
		{"mov,mp4,m4a,3gp,3g2,mj2", "aac", "mp4"},
		{"matroska,webm", "opus", "webm"},
		{"ogg", "opus", "opus"},
		{"ogg", "vorbis", "ogg"},
		{"mp3", "mp3", "mp3"},
		{"wav", "pcm_s16le", "wav"},
	}
	for _, tt := range tests {
		if got := ffprobeFormat(tt.name, tt.codec); got != tt.want {
			t.Errorf("ffprobeFormat(%q, %q) = %q, want %q", tt.name, tt.codec, got, tt.want)
		}
	}
}

func TestMergeInfo(t *testing.T) {
	native := &Info{Format: "mp3", Title: "Native", Chapters: []Chapter{{Title: "N", Start: 0}}, Picture: &Picture{MIME: "image/png"}}
	ff := &Info{Format: "mp3", Duration: 99, Bitrate: 64000, Title: "FF", Artist: "FF Artist", Track: 2,
		Chapters: []Chapter{{Title: "F1"}, {Title: "F2", Start: 5}}, HasPicture: true}
	got := mergeInfo(native, ff)
	expectFields(t, got, Info{Format: "mp3", Bitrate: 64000, Title: "Native", Artist: "FF Artist", Track: 2})
	if got.Duration != 99 || len(got.Chapters) != 1 || got.Picture == nil || !got.HasPicture {
		t.Errorf("merged = %+v", got)
	}
	if native.Artist != "" {
		t.Error("mergeInfo modified its input")
	}
	if got := mergeInfo(nil, ff); got != ff {
		t.Error("nil native result should be replaced by ffprobe's")
	}
}

func TestFFprobeFallback(t *testing.T) {
	requireFFmpeg(t)
	if _, err := exec.LookPath("ffprobe"); err != nil {
		t.Skip("ffprobe not installed")
	}
	// A name that would confuse ffprobe without the file: prefix.
	path := filepath.Join(t.TempDir(), "odd #name? 100% – ü.webm")
	runFFmpeg(t, "-f", "lavfi", "-i", "sine=frequency=300:sample_rate=48000:duration=5",
		"-c:a", "libopus", "-metadata", "title=WebM Title", path)

	if _, err := ProbeFile(path, Options{}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("native WebM: err = %v, want ErrUnsupported", err)
	}
	info, err := ProbeFile(path, Options{FFprobe: true})
	if err != nil {
		t.Fatal(err)
	}
	expectDuration(t, info.Duration, 5, 0.02)
	expectFields(t, info, Info{Format: "webm", SampleRate: 48000, Channels: 1, Title: "WebM Title"})
}

func TestFFprobeUnavailable(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	path := filepath.Join(t.TempDir(), "x.webm")
	writeFile(t, path, []byte{0x1A, 0x45, 0xDF, 0xA3, 0, 0, 0, 0})
	if _, err := ProbeFile(path, Options{FFprobe: true}); !errors.Is(err, ErrUnsupported) {
		t.Errorf("err = %v, want ErrUnsupported", err)
	}
	if _, err := runFFprobe(path); err == nil {
		t.Error("runFFprobe without a binary: want an error")
	}
}
