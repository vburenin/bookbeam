package media

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestSniffAudio(t *testing.T) {
	jpeg := cat([]byte{0xFF, 0xD8, 0xFF, 0xE2, 0x00, 0x10}, bytes.Repeat([]byte{0xFF, 0xE2, 0x90, 0xC0, 0x41}, 300))
	tests := []struct {
		name string
		data []byte
		want string
	}{
		{"id3", id3TagBytes(3, 0, id3Frame23("TIT2", 0, id3Text("x"))), "id3"},
		{"bad id3 header", []byte("ID3\xff\x00\x00\x00\x00\x00\x00"), ""},
		{"mpeg", mpegStream(5, 128), "mpeg"},
		{"mpeg filling a tiny file", mpegFrame(64), "mpeg"},
		{"mpeg behind junk", cat(make([]byte, 5000), mpegStream(10, 64)), "mpeg"},
		{"adts", cat(adtsFrame(4, 2, 100), adtsFrame(4, 2, 100), adtsFrame(4, 2, 100)), "aac"},
		{"mp4 ftyp", cat(box("ftyp", []byte("M4B "), be32(0)), box("free")), "mp4"},
		{"mp4 moov first", box("moov", mvhd(1000, 1000)), "mp4"},
		{"flac", cat([]byte("fLaC"), flacBlock(0, true, flacStreamInfoBlock(44100, 2, 1000))), "flac"},
		{"ogg", []byte("OggS\x00\x02rest-of-page"), "ogg"},
		{"wav", wavFile(wavFmt(1, 1, 8000, 16), riffChunk("data", make([]byte, 100))), "wav"},
		{"webm", []byte{0x1A, 0x45, 0xDF, 0xA3, 0x9F, 0x42, 0x86, 0x81}, "webm"},

		{"empty", nil, ""},
		{"short", []byte("ID"), ""},
		{"text", []byte("I'm free to do what I want, any old time"), ""},
		{"json", []byte(`{"duration": 60, "title": "fake"}`), ""},
		{"riff webp", []byte("RIFF\x10\x00\x00\x00WEBPVP8 "), ""},
		{"jpeg with sync-like markers", jpeg, ""},
		{"lone frame behind junk", cat(make([]byte, 100), mpegFrame(64), make([]byte, 100)), ""},
		{"random secret", bytes.Repeat([]byte{0xFF, 0xFB, 0x07}, 11), ""},
	}
	for _, tt := range tests {
		if got := SniffAudio(bytes.NewReader(tt.data), int64(len(tt.data))); got != tt.want {
			t.Errorf("%s: SniffAudio = %q, want %q", tt.name, got, tt.want)
		}
	}
}

func TestSniffImage(t *testing.T) {
	bmp := cat([]byte("BM"), le32(1000), le32(0), le32(54), le32(40), make([]byte, 20))
	tests := []struct {
		name string
		data []byte
		want string
	}{
		{"jpeg", []byte{0xFF, 0xD8, 0xFF, 0xE0, 0, 0x10, 'J', 'F', 'I', 'F'}, "image/jpeg"},
		{"png", []byte("\x89PNG\r\n\x1a\n\x00\x00\x00\x0dIHDR"), "image/png"},
		{"webp", []byte("RIFF\x10\x00\x00\x00WEBPVP8 "), "image/webp"},
		{"gif87", []byte("GIF87a\x01\x00"), "image/gif"},
		{"gif89", []byte("GIF89a\x01\x00"), "image/gif"},
		{"bmp", bmp, "image/bmp"},
		{"BM text", []byte("BMW owners manual, chapter one........"), ""},
		{"svg", []byte(`<svg xmlns="http://www.w3.org/2000/svg"></svg>`), ""},
		{"riff wave", []byte("RIFF\x10\x00\x00\x00WAVEfmt "), ""},
		{"fake jpeg", []byte("jpeg-bytes"), ""},
		{"empty", nil, ""},
	}
	for _, tt := range tests {
		if got := SniffImage(tt.data); got != tt.want {
			t.Errorf("%s: SniffImage = %q, want %q", tt.name, got, tt.want)
		}
	}
}

func TestIsTransient(t *testing.T) {
	pathErr := &fs.PathError{Op: "read", Path: "/nas/a.mp3", Err: syscall.EIO}
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"path error", pathErr, true},
		{"wrapped path error", fmt.Errorf("media: reading x: %w", pathErr), true},
		{"errno", syscall.EACCES, true},
		{"syscall error", os.NewSyscallError("pread", syscall.ESTALE), true},
		{"ffprobe timeout", errors.Join(errors.New("media: mp3: no frames"), fmt.Errorf("media: ffprobe: %w", context.DeadlineExceeded)), true},
		{"not audio", ErrNotAudio, false},
		{"unsupported", fmt.Errorf("%w: Matroska/WebM", ErrUnsupported), false},
		{"parse failure", errors.New("media: mp3: no MPEG audio frames found"), false},
	}
	for _, tt := range tests {
		if got := IsTransient(tt.err); got != tt.want {
			t.Errorf("%s: IsTransient = %v, want %v", tt.name, got, tt.want)
		}
	}
}

// flakyReader serves data but fails reads that touch [badFrom, badTo).
type flakyReader struct {
	data           []byte
	badFrom, badTo int64
}

func (r flakyReader) ReadAt(p []byte, off int64) (int, error) {
	if off < r.badTo && off+int64(len(p)) > r.badFrom {
		return 0, &fs.PathError{Op: "read", Path: "/nas/book.mp3", Err: syscall.EIO}
	}
	return bytes.NewReader(r.data).ReadAt(p, off)
}

func TestProbeReadErrorsAreTransient(t *testing.T) {
	noFFprobe := func(string) (*Info, error) { return nil, errors.New("no ffprobe") }
	data := cat(xingFrame("Xing", 1000, 0, 0), mpegStream(1000, 128))

	// A read error while looking at the header region: the parsers would
	// carry on with a wrong (estimated) duration, so the probe must fail.
	r := flakyReader{data: data, badFrom: 20, badTo: 40}
	if info, err := probeOpen(r, int64(len(data)), "book.mp3", Options{}, noFFprobe); err == nil || !IsTransient(err) {
		t.Errorf("read error in header: info=%+v err=%v, want a transient error", info, err)
	}
	// A read error while sniffing is transient too, not "not audio".
	r = flakyReader{data: data, badFrom: 0, badTo: 4}
	if _, err := probeOpen(r, int64(len(data)), "book.mp3", Options{}, noFFprobe); errors.Is(err, ErrNotAudio) || !IsTransient(err) {
		t.Errorf("read error while sniffing: err = %v, want a transient error", err)
	}
	// Healthy reads succeed.
	r = flakyReader{data: data, badFrom: -1, badTo: -1}
	if _, err := probeOpen(r, int64(len(data)), "book.mp3", Options{}, noFFprobe); err != nil {
		t.Errorf("healthy read: %v", err)
	}

	// Content that is not audio never reaches ffprobe.
	called := false
	spy := func(string) (*Info, error) { called = true; return &Info{Duration: 1}, nil }
	text := []byte("definitely not audio")
	if _, err := probeOpen(bytes.NewReader(text), int64(len(text)), "x.mp3", Options{FFprobe: true}, spy); !errors.Is(err, ErrNotAudio) || called {
		t.Errorf("text: err = %v, ffprobe called = %v; want ErrNotAudio without ffprobe", err, called)
	}
	// An ffprobe timeout after a native failure is reported as transient.
	timeout := func(string) (*Info, error) { return nil, fmt.Errorf("media: ffprobe: %w", context.DeadlineExceeded) }
	ebml := []byte{0x1A, 0x45, 0xDF, 0xA3, 0, 0, 0, 0}
	if _, err := probeOpen(bytes.NewReader(ebml), int64(len(ebml)), "x.webm", Options{FFprobe: true}, timeout); !errors.Is(err, ErrUnsupported) || !IsTransient(err) {
		t.Errorf("ffprobe timeout: err = %v, want ErrUnsupported and transient", err)
	}
}

func TestProbeFileRejectsNonAudio(t *testing.T) {
	dir := t.TempDir()
	for name, data := range map[string][]byte{
		"secret.mp3": bytes.Repeat([]byte{0x5A, 0x11}, 16),
		"page.m4b":   []byte("<html><body>hello</body></html>"),
		"empty.mp3":  nil,
	} {
		p := filepath.Join(dir, name)
		writeFile(t, p, data)
		if _, err := ProbeFile(p, Options{FFprobe: true}); !errors.Is(err, ErrNotAudio) || IsTransient(err) {
			t.Errorf("%s: err = %v, want ErrNotAudio", name, err)
		}
	}
}

// xingNoBytes is xingFrame with only a frame count (no byte count).
func xingNoBytes(tag string, frames int) []byte {
	f := mpegFrame(128)
	copy(f[4+17:], cat([]byte(tag), be32(0x1), be32(frames)))
	return f
}

func TestMP3TruncatedWithVBRHeader(t *testing.T) {
	frameDur := 1152 / 44100.0
	half := func(b []byte) []byte { return b[:len(b)/2] }
	tests := []struct {
		name string
		data []byte
		want float64 // seconds
		tol  float64 // relative
	}{
		{
			name: "complete Xing",
			data: cat(xingFrame("Xing", 1000, 0, 0), mpegStream(1000, 128)),
			want: 1000 * frameDur, tol: 1e-9,
		},
		{
			name: "Xing cut in half (CBR body)",
			data: half(cat(xingFrame("Xing", 1000, 0, 0), mpegStream(1000, 128))),
			want: 500 * frameDur, tol: 0.01,
		},
		{
			name: "Xing cut in half (VBR body)",
			data: half(cat(xingFrame("Xing", 1000, 0, 0), mpegStream(500, 128, 64))),
			want: 0, tol: 0, // computed below from the frames present
		},
		{
			name: "Info without byte count, cut in half",
			data: half(cat(xingNoBytes("Info", 1000), mpegStream(1000, 128))),
			want: 500 * frameDur, tol: 0.01,
		},
		{
			name: "complete Info without byte count",
			data: cat(xingNoBytes("Info", 1000), mpegStream(1000, 128)),
			want: 1000 * frameDur, tol: 1e-9,
		},
		{
			name: "Xing without byte count, a tenth left",
			data: cat(xingNoBytes("Xing", 1000), mpegStream(50, 128, 64)),
			want: 100 * frameDur, tol: 1e-9,
		},
		{
			// Some encoders count a leading ID3v2 tag in the byte count; a
			// complete file must keep its header duration.
			name: "complete, byte count includes a big tag",
			data: func() []byte {
				tag := id3TagBytes(3, 0, id3Frame23("TXXX", 0, make([]byte, 100<<10)))
				x := xingFrame("Xing", 1000, 0, 0)
				copy(x[4+17+12:], be32(len(tag)+417+1000*417))
				return cat(tag, x, mpegStream(1000, 128))
			}(),
			want: 1000 * frameDur, tol: 1e-9,
		},
	}
	for _, tt := range tests {
		info := mustProbe(t, tt.data, ".mp3", Options{})
		want := tt.want
		if want == 0 {
			// Count the whole frames after the header frame.
			for pos := 417; ; {
				h, ok := parseMPEGHeader(tt.data[pos:])
				if !ok || pos+h.size > len(tt.data) {
					break
				}
				want += frameDur
				pos += h.size
			}
		}
		if diff := info.Duration - want; diff > want*tt.tol+1e-9 || -diff > want*tt.tol+1e-9 {
			t.Errorf("%s: Duration = %.3f, want %.3f", tt.name, info.Duration, want)
		}
	}
	// A header frame alone is not playable audio.
	if _, err := probeBytes(xingFrame("Xing", 1000, 0, 0), ".mp3", Options{}); err == nil || !strings.Contains(err.Error(), "no audio") {
		t.Errorf("header only: err = %v", err)
	}
}
