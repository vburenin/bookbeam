package media

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// These tests generate real files with ffmpeg (skipped when it is not
// installed) and check what the native parsers make of them.

// ffmpegInputs are the shared sources for generated fixtures.
type ffmpegInputs struct {
	dir      string
	tone     string // 30 s, 22.05 kHz stereo WAV
	cover    string // JPEG
	chapters string // FFmetadata with three chapters
}

const ffmpegToneSeconds = 30

func requireFFmpeg(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("ffmpeg"); err != nil {
		t.Skip("ffmpeg not installed")
	}
}

func runFFmpeg(t *testing.T, args ...string) {
	t.Helper()
	cmd := exec.Command("ffmpeg", append([]string{"-hide_banner", "-loglevel", "error", "-y"}, args...)...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("ffmpeg %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

func newFFmpegInputs(t *testing.T) ffmpegInputs {
	t.Helper()
	requireFFmpeg(t)
	dir := t.TempDir()
	in := ffmpegInputs{
		dir:      dir,
		tone:     filepath.Join(dir, "tone.wav"),
		cover:    filepath.Join(dir, "cover.jpg"),
		chapters: filepath.Join(dir, "chapters.txt"),
	}
	runFFmpeg(t, "-f", "lavfi", "-i", "sine=frequency=440:sample_rate=22050:duration=30",
		"-f", "lavfi", "-i", "sine=frequency=550:sample_rate=22050:duration=30",
		"-filter_complex", "[0][1]amerge=inputs=2,volume=0.1", in.tone)
	runFFmpeg(t, "-f", "lavfi", "-i", "color=c=0x1d3557:s=64x64:d=1", "-frames:v", "1", in.cover)
	meta := ";FFMETADATA1\n" +
		"[CHAPTER]\nTIMEBASE=1/1000\nSTART=0\nEND=10000\ntitle=Prologue\n" +
		"[CHAPTER]\nTIMEBASE=1/1000\nSTART=10000\nEND=20250\ntitle=Chapter 1: Ünïcødé\n" +
		"[CHAPTER]\nTIMEBASE=1/1000\nSTART=20250\nEND=30000\ntitle=Epilogue\n"
	if err := os.WriteFile(in.chapters, []byte(meta), 0o644); err != nil {
		t.Fatal(err)
	}
	return in
}

// ffmpegTags is the metadata written to every tagged fixture.
var ffmpegTags = []string{
	"-metadata", "title=Generated Title", "-metadata", "album=Generated Album",
	"-metadata", "artist=Generated Author", "-metadata", "album_artist=Generated Author",
	"-metadata", "composer=Generated Reader", "-metadata", "genre=Audiobook",
	"-metadata", "date=2019-04-01", "-metadata", "track=3/9", "-metadata", "disc=1/2",
	"-metadata", "comment=Generated comment",
}

var ffmpegTagsWant = Info{
	Title: "Generated Title", Album: "Generated Album", Artist: "Generated Author",
	AlbumArtist: "Generated Author", Composer: "Generated Reader", Genre: "Audiobook",
	Year: "2019", Track: 3, TrackTotal: 9, Disc: 1, DiscTotal: 2, Comment: "Generated comment",
}

var ffmpegChaptersWant = []Chapter{
	{Title: "Prologue", Start: 0, End: 10},
	{Title: "Chapter 1: Ünïcødé", Start: 10, End: 20.25},
	{Title: "Epilogue", Start: 20.25, End: ffmpegToneSeconds},
}

func TestFFmpegFixtures(t *testing.T) {
	in := newFFmpegInputs(t)
	withArt := []string{"-i", in.tone, "-i", in.cover, "-i", in.chapters, "-map", "0:a", "-map", "1:v", "-map_chapters", "2"}
	tagsOnly := append(ffmpegTags[:len(ffmpegTags):len(ffmpegTags)], "-metadata", "description=Generated description")
	noise := []string{"-f", "lavfi", "-i", "anoisesrc=d=30:a=0.2:c=pink:r=44100",
		"-af", "volume='if(lt(t,8),0,1)':eval=frame", "-ac", "1"}

	tests := []struct {
		name     string
		file     string
		args     []string
		format   string
		tags     Info
		chapters []Chapter
		picture  bool // the cover JPEG must come back byte for byte
	}{
		{
			name: "mp3 CBR, ID3v2.3, cover, CHAP", file: "cbr.mp3", format: "mp3",
			args: argList(withArt, "-c:a", "libmp3lame", "-b:a", "64k", "-c:v", "copy", "-id3v2_version", "3",
				"-metadata:s:v", "comment=Cover (front)", ffmpegTags),
			tags: ffmpegTagsWant, chapters: ffmpegChaptersWant, picture: true,
		},
		{
			name: "mp3 CBR, ID3v2.4", file: "v24.mp3", format: "mp3",
			args: argList(withArt, "-c:a", "libmp3lame", "-b:a", "96k", "-c:v", "copy", "-id3v2_version", "4",
				"-metadata:s:v", "comment=Cover (front)", ffmpegTags),
			tags: ffmpegTagsWant, chapters: ffmpegChaptersWant, picture: true,
		},
		{
			name: "mp3 VBR with Xing", file: "vbr.mp3", format: "mp3",
			args: argList([]string{"-i", in.tone}, "-c:a", "libmp3lame", "-q:a", "5", ffmpegTags),
			tags: ffmpegTagsWant,
		},
		{
			name: "mp3 VBR without Xing, silent start", file: "vbr-noxing.mp3", format: "mp3",
			args: argList(noise, "-c:a", "libmp3lame", "-q:a", "2", "-write_xing", "0"),
		},
		{
			name: "mp2", file: "layer2.mp2", format: "mp3",
			args: []string{"-i", in.tone, "-c:a", "mp2", "-b:a", "128k"},
		},
		{
			name: "m4b chapters and covr", file: "book.m4b", format: "mp4",
			args: argList(withArt, "-c:a", "aac", "-b:a", "48k", "-c:v", "copy", "-disposition:v", "attached_pic",
				tagsOnly, "-f", "mp4"),
			tags: withDescription(ffmpegTagsWant, "Generated description"), chapters: ffmpegChaptersWant, picture: true,
		},
		{
			name: "m4b QuickTime chapters only", file: "qt.m4b", format: "mp4",
			args: argList(withArt, "-c:a", "aac", "-b:a", "48k", "-c:v", "copy", "-disposition:v", "attached_pic",
				"-movflags", "+disable_chpl", "-f", "mp4"),
			chapters: ffmpegChaptersWant, picture: true,
		},
		{
			name: "m4a without chapters, faststart", file: "plain.m4a", format: "mp4",
			args: argList([]string{"-i", in.tone}, "-c:a", "aac", "-b:a", "48k", "-movflags", "+faststart", ffmpegTags),
			tags: ffmpegTagsWant,
		},
		// FFmpeg stores the comment as Vorbis DESCRIPTION, so it doubles as
		// the description. It writes Vorbis-comment chapters only for Opus
		// (FLAC and Ogg Vorbis chapter parsing is covered by synthetic tests).
		{
			name: "flac picture and vorbis comments", file: "pic.flac", format: "flac",
			args: argList(withArt, "-c:a", "flac", "-c:v", "copy", "-disposition:v", "attached_pic", ffmpegTags),
			tags: withDescription(ffmpegTagsWant, "Generated comment"), picture: true,
		},
		{
			name: "ogg vorbis", file: "book.ogg", format: "ogg",
			args: argList([]string{"-i", in.tone}, "-c:a", "libvorbis", "-q:a", "1", ffmpegTags),
			tags: withDescription(ffmpegTagsWant, "Generated comment"),
		},
		{
			name: "opus with chapters", file: "book.opus", format: "opus",
			args: argList([]string{"-i", in.tone, "-i", in.chapters, "-map", "0", "-map_chapters", "1"}, "-c:a", "libopus", "-b:a", "32k", ffmpegTags),
			tags: withDescription(ffmpegTagsWant, "Generated comment"), chapters: ffmpegChaptersWant,
		},
		{
			name: "wav with INFO", file: "book.wav", format: "wav",
			args: argList([]string{"-i", in.tone}, "-c:a", "pcm_s16le", ffmpegTags),
			tags: Info{Title: "Generated Title", Album: "Generated Album", Artist: "Generated Author",
				Genre: "Audiobook", Year: "2019", Comment: "Generated comment"},
		},
		{
			name: "rf64 wav", file: "big.wav", format: "wav",
			args: []string{"-i", in.tone, "-c:a", "pcm_s24le", "-rf64", "always"},
		},
		{
			name: "aac adts", file: "book.aac", format: "aac",
			args: []string{"-i", in.tone, "-c:a", "aac", "-b:a", "48k", "-f", "adts"},
		},
	}
	cover, err := os.ReadFile(in.cover)
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(in.dir, tt.file)
			runFFmpeg(t, append(tt.args, path)...)
			info, err := ProbeFile(path, Options{WantPicture: true})
			if err != nil {
				t.Fatal(err)
			}
			expectDuration(t, info.Duration, ffmpegToneSeconds, 0.02)
			if info.Format != tt.format || info.SampleRate == 0 || info.Bitrate == 0 {
				t.Errorf("Format=%q SampleRate=%d Bitrate=%d", info.Format, info.SampleRate, info.Bitrate)
			}
			expectFields(t, info, tt.tags)
			expectChapters(t, info.Chapters, tt.chapters...)
			switch {
			case tt.picture && (info.Picture == nil || !bytes.Equal(info.Picture.Data, cover) || info.Picture.MIME != "image/jpeg"):
				t.Errorf("Picture = %v, want the cover JPEG", info.Picture != nil)
			case !tt.picture && info.HasPicture:
				t.Error("HasPicture = true for a file without art")
			}
		})
	}
}

// argList flattens string arguments and string slices into one argument list.
func argList(parts ...any) []string {
	var out []string
	for _, p := range parts {
		switch v := p.(type) {
		case string:
			out = append(out, v)
		case []string:
			out = append(out, v...)
		}
	}
	return out
}

func withDescription(i Info, description string) Info {
	i.Description = description
	return i
}

// TestFFmpegTruncatedMP3 cuts real LAME files (a VBR one with a Xing header,
// a CBR one with an Info header, both carrying cover art in an ID3v2 tag) in
// half: the duration must describe what is left, not what the header says.
func TestFFmpegTruncatedMP3(t *testing.T) {
	in := newFFmpegInputs(t)
	for name, codec := range map[string][]string{
		"vbr.mp3": {"-q:a", "4"},
		"cbr.mp3": {"-b:a", "64k"},
	} {
		full := filepath.Join(in.dir, name)
		runFFmpeg(t, argList("-i", in.tone, "-i", in.cover, "-map", "0", "-map", "1",
			"-c:a", "libmp3lame", codec, "-c:v", "copy", "-id3v2_version", "3", full)...)
		data, err := os.ReadFile(full)
		if err != nil {
			t.Fatal(err)
		}
		info := mustProbe(t, data, ".mp3", Options{})
		expectDuration(t, info.Duration, ffmpegToneSeconds, 0.01)

		// The tag (with the cover) stays whole; half of the audio goes.
		tagEnd := skipID3v2(newByteSource(data), 0)
		cut := data[:tagEnd+(int64(len(data))-tagEnd)/2]
		info = mustProbe(t, cut, ".mp3", Options{})
		expectDuration(t, info.Duration, ffmpegToneSeconds/2.0, 0.03)
	}
}
