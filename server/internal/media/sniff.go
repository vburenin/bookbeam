package media

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"sync"
	"syscall"
)

// ErrNotAudio is returned by ProbeFile for a file whose leading bytes are not
// those of a supported audio container, whatever its extension says. Such a
// file must not be indexed or served as audio. It wraps ErrUnsupported.
var ErrNotAudio = fmt.Errorf("%w: content is not audio", ErrUnsupported)

// sniffJunkWindow bounds how far behind leading junk SniffAudio looks for
// MPEG or ADTS frames (the MP3 parser searches the same distance).
const sniffJunkWindow = 1 << 20

// sniffMinFrames is how many consecutive matching frames prove a raw MPEG or
// ADTS stream found behind junk (sync-like byte pairs are common in binary
// data such as JPEG markers).
const sniffMinFrames = 3

// SniffAudio reports which kind of audio data r holds, judging by its
// leading bytes: "id3" (an ID3v2 tag, which fronts MP3 and sometimes AAC or
// FLAC), "mpeg" (MPEG audio frames), "aac" (ADTS frames), "mp4", "flac",
// "ogg", "wav" or "webm". It returns "" for anything else, such as text,
// images or random bytes. Raw MPEG/ADTS streams may start with up to 1 MiB of
// junk, as the parsers allow.
func SniffAudio(r io.ReaderAt, size int64) string {
	return sniffAudio(&source{r: r, size: size})
}

func sniffAudio(src *source) string {
	head := src.peek(0, 12)
	if len(head) < 4 {
		return ""
	}
	switch {
	case bytes.HasPrefix(head, []byte("ID3")):
		if _, ok := readID3Header(src, 0); ok {
			return "id3"
		}
		return ""
	case bytes.HasPrefix(head, []byte("fLaC")):
		return "flac"
	case bytes.HasPrefix(head, []byte("OggS")):
		return "ogg"
	case bytes.HasPrefix(head, []byte{0x1A, 0x45, 0xDF, 0xA3}):
		return "webm"
	case len(head) == 12 && (string(head[:4]) == "RIFF" || string(head[:4]) == "RF64" || string(head[:4]) == "BW64") &&
		string(head[8:12]) == "WAVE":
		return "wav"
	case len(head) >= 8 && isMP4TopLevel(string(head[4:8])) && plausibleBoxSize(binary.BigEndian.Uint32(head), src.size):
		return "mp4"
	}
	for _, k := range rawStreams {
		if n, toEnd := frameRun(src, 0, k.parse); n >= sniffMinFrames || (n > 0 && toEnd) {
			return k.name
		}
	}
	// Behind junk (zero padding, a stray tag) a stream needs a proper run of
	// frames before it counts as audio.
	window := src.peek(0, sniffJunkWindow)
	for i := 1; i+4 <= len(window); i++ {
		if window[i] != 0xFF {
			continue
		}
		for _, k := range rawStreams {
			if n, _ := frameRun(src, int64(i), k.parse); n >= sniffMinFrames {
				return k.name
			}
		}
	}
	return ""
}

// plausibleBoxSize reports whether n can be the size field of a top-level
// ISO BMFF box in a file of the given size (0 = "to the end", 1 = 64-bit).
func plausibleBoxSize(n uint32, size int64) bool {
	return n == 0 || n == 1 || (n >= 8 && int64(n) <= size)
}

// frameParser decodes a frame header, returning the frame length and a key
// that all frames of one stream share.
type frameParser func(b []byte) (size int, stream int, ok bool)

// rawStreams are the headerless frame formats SniffAudio recognises.
var rawStreams = []struct {
	name  string
	parse frameParser
}{
	{"aac", func(b []byte) (int, int, bool) {
		h, ok := parseADTS(b)
		return h.size, h.sampleRate, ok
	}},
	{"mpeg", func(b []byte) (int, int, bool) {
		h, ok := parseMPEGHeader(b)
		return h.size, h.version<<20 | h.layer<<18 | h.sampleRate, ok
	}},
}

// frameRun counts consecutive frames of one stream starting at pos, up to
// sniffMinFrames, and reports whether the run reached the end of the data.
func frameRun(src *source, pos int64, parse frameParser) (n int, toEnd bool) {
	stream := -1
	for n < sniffMinFrames {
		size, key, ok := parse(src.peek(pos, 9))
		if !ok || size <= 0 || (stream >= 0 && key != stream) {
			return n, false
		}
		stream = key
		n++
		if pos += int64(size); pos >= src.size {
			return n, true
		}
	}
	return n, false
}

// SniffImage returns the MIME type of a JPEG, PNG, WebP, GIF or BMP image
// judging by its leading bytes (at least 32 should be given), or "" for
// anything else.
func SniffImage(head []byte) string {
	switch {
	case bytes.HasPrefix(head, []byte{0xFF, 0xD8, 0xFF}):
		return "image/jpeg"
	case bytes.HasPrefix(head, []byte("\x89PNG\r\n\x1a\n")):
		return "image/png"
	case len(head) >= 12 && string(head[:4]) == "RIFF" && string(head[8:12]) == "WEBP":
		return "image/webp"
	case bytes.HasPrefix(head, []byte("GIF87a")) || bytes.HasPrefix(head, []byte("GIF89a")):
		return "image/gif"
	case len(head) >= 18 && bytes.HasPrefix(head, []byte("BM")):
		// "BM" alone is too weak (plain text can start with it): require a
		// known DIB header size as well.
		switch binary.LittleEndian.Uint32(head[14:18]) {
		case 12, 16, 40, 52, 56, 64, 108, 124:
			return "image/bmp"
		}
	}
	return ""
}

// IsTransient reports whether a ProbeFile error came from the environment
// (an I/O or permission error, a timeout) rather than from the file's
// content, so that probing the unchanged file again later may succeed.
func IsTransient(err error) bool {
	if err == nil {
		return false
	}
	var (
		pathErr *fs.PathError
		sysErr  *os.SyscallError
		errno   syscall.Errno
	)
	return errors.As(err, &pathErr) || errors.As(err, &sysErr) || errors.As(err, &errno) ||
		errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded)
}

// readErrTracker remembers the first read failure (other than EOF) of the
// file being probed. Parsers treat unreadable regions like missing data, so
// without it a NAS hiccup would look like a damaged file, and a wrong result
// would be cached as if it were final.
type readErrTracker struct {
	r io.ReaderAt

	mu  sync.Mutex
	err error
}

func (t *readErrTracker) ReadAt(p []byte, off int64) (int, error) {
	n, err := t.r.ReadAt(p, off)
	if err != nil && !errors.Is(err, io.EOF) {
		t.mu.Lock()
		if t.err == nil {
			t.err = err
		}
		t.mu.Unlock()
	}
	return n, err
}

func (t *readErrTracker) Err() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.err
}
