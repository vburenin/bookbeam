package media

import (
	"bytes"
	"cmp"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// Hard limits that keep corrupt or hostile files from causing huge
// allocations or unbounded work.
const (
	maxPictureSize = 16 << 20 // largest embedded picture that is loaded
	maxTagSize     = 32 << 20 // largest single tag frame, block or packet read
	maxScanBytes   = 64 << 20 // most audio read when summing frame headers
	maxChapters    = 10000    // chapters kept per file
)

// pictureFrontCover is the ID3v2/FLAC picture type of a front cover.
const pictureFrontCover = 3

// ProbeFile extracts format, duration, tags, chapters and (optionally) cover
// art from the audio file at path. The container is recognised from its
// leading bytes, with the extension only as a fallback; unknown formats yield
// an error wrapping ErrUnsupported. Only headers and tags are read, except
// for MP3 files without a VBR header and ADTS AAC, whose frame headers are
// summed (bounded by maxScanBytes).
//
// Files whose leading bytes are not audio (see SniffAudio) fail with
// ErrNotAudio before any parser or ffprobe looks at them. When opts.FFprobe
// is set and the ffprobe binary is on PATH, it is consulted if the native
// parsers fail or cannot determine the duration; native values win wherever
// both have one.
//
// A read error anywhere in the file fails the probe even if the parsers
// coped, since their result may be incomplete; IsTransient recognises such
// errors (and ffprobe timeouts) so callers can retry later.
func ProbeFile(path string, opts Options) (*Info, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("media: %s: not a regular file", path)
	}
	return probeOpen(f, st.Size(), path, opts, runFFprobe)
}

// probeOpen is ProbeFile once the file is open; ffprobe runs the fallback.
func probeOpen(f io.ReaderAt, size int64, path string, opts Options, ffprobe func(string) (*Info, error)) (*Info, error) {
	r := &readErrTracker{r: f}
	readErr := func() error {
		if err := r.Err(); err != nil {
			return fmt.Errorf("media: reading %s: %w", path, err)
		}
		return nil
	}
	if sniffAudio(&source{r: r, size: size}) == "" {
		if err := readErr(); err != nil {
			return nil, err
		}
		return nil, ErrNotAudio
	}
	info, err := probeSafely(r, size, filepath.Ext(path), opts)
	if rerr := readErr(); rerr != nil {
		info, err = nil, rerr
	}
	if opts.FFprobe && (err != nil || info.Duration <= 0) {
		ff, ffErr := ffprobe(path)
		switch {
		case ffErr == nil:
			info, err = mergeInfo(info, ff), nil
			info.normalize()
		case err != nil && IsTransient(ffErr):
			// Keep the native error but let callers see that a retry may help.
			err = errors.Join(err, ffErr)
		}
	}
	return info, err
}

// probeSafely runs the native parsers, turning a panic caused by malformed
// input into an error so that one bad file cannot take down a library scan.
func probeSafely(r io.ReaderAt, size int64, ext string, opts Options) (info *Info, err error) {
	defer func() {
		if v := recover(); v != nil {
			info, err = nil, fmt.Errorf("media: parser failure: %v", v)
		}
	}()
	return probe(r, size, ext, opts)
}

// prober holds the state of one probe while a container parser runs.
type prober struct {
	src        *source
	opts       Options
	info       *Info
	tagSets    []tagMap // in priority order; see newTagSet
	coverFront bool     // info.Picture is a front cover
}

// probe detects the container format and runs its parser.
func probe(r io.ReaderAt, size int64, ext string, opts Options) (*Info, error) {
	p := &prober{src: &source{r: r, size: size}, opts: opts, info: &Info{}}
	parse, err := p.detect(strings.ToLower(ext))
	if err != nil {
		return nil, err
	}
	if err := parse(); err != nil {
		return nil, err
	}
	for _, t := range p.tagSets {
		t.apply(p.info)
	}
	p.info.normalize()
	return p.info, nil
}

// newTagSet starts a new group of tags. Groups are applied in creation order
// and only fill fields that are still empty, so a file's primary tag (say
// ID3v2) wins over secondary ones (ID3v1) without values being merged.
func (p *prober) newTagSet() tagMap {
	t := tagMap{}
	p.tagSets = append(p.tagSets, t)
	return t
}

// detect picks the parser for the data by its magic bytes, falling back to
// the file extension for raw streams that may start with junk.
func (p *prober) detect(ext string) (func() error, error) {
	head := p.src.peek(0, 12)
	switch {
	case len(head) == 0:
		return nil, fmt.Errorf("%w: empty file", ErrUnsupported)
	case bytes.HasPrefix(head, []byte("ID3")):
		// ID3v2 tags front MP3, ADTS AAC and occasionally FLAC: look past them.
		after := p.src.peek(skipID3v2(p.src, 0), 7)
		switch {
		case bytes.HasPrefix(after, []byte("fLaC")):
			return p.flac, nil
		case isADTS(after) || ext == ".aac":
			return p.aac, nil
		}
		return p.mp3, nil
	case bytes.HasPrefix(head, []byte("fLaC")):
		return p.flac, nil
	case bytes.HasPrefix(head, []byte("OggS")):
		return p.ogg, nil
	case len(head) == 12 && (string(head[:4]) == "RIFF" || string(head[:4]) == "RF64") && string(head[8:12]) == "WAVE":
		return p.wav, nil
	case len(head) >= 8 && isMP4TopLevel(string(head[4:8])):
		return p.mp4, nil
	case bytes.HasPrefix(head, []byte{0x1A, 0x45, 0xDF, 0xA3}):
		return nil, fmt.Errorf("%w: Matroska/WebM", ErrUnsupported)
	case isADTS(head):
		return p.aac, nil
	case isMPEGFrame(head):
		return p.mp3, nil
	}
	switch ext {
	case ".mp3", ".mp2", ".mpga":
		return p.mp3, nil
	case ".aac":
		return p.aac, nil
	}
	return nil, ErrUnsupported
}

// wantPicture is called when usable embedded art of the given picture type
// is found. It records that art exists and reports whether its bytes should
// be loaded: only when requested, and only if it beats the picture already
// held (a front cover beats any other type; otherwise the first one wins).
func (p *prober) wantPicture(typ int) bool {
	if !p.opts.WantPicture {
		p.info.HasPicture = true
		return false
	}
	return p.info.Picture == nil || (!p.coverFront && typ == pictureFrontCover)
}

// setPicture stores loaded art if it is a recognisable image within limits.
func (p *prober) setPicture(typ int, mime string, data []byte) {
	mime = pictureMIME(mime, data)
	if mime == "" || len(data) == 0 || len(data) > maxPictureSize {
		return
	}
	p.info.HasPicture = true
	p.info.Picture = &Picture{MIME: mime, Data: bytes.Clone(data)}
	p.coverFront = typ == pictureFrontCover
}

// pictureMIME determines an image's MIME type from its magic bytes, falling
// back to the declared type. It returns "" for data that is not an image
// (for example an ID3 "-->" URL link).
func pictureMIME(declared string, data []byte) string {
	switch {
	case bytes.HasPrefix(data, []byte{0xFF, 0xD8, 0xFF}):
		return "image/jpeg"
	case bytes.HasPrefix(data, []byte("\x89PNG\r\n\x1a\n")):
		return "image/png"
	case len(data) >= 12 && string(data[:4]) == "RIFF" && string(data[8:12]) == "WEBP":
		return "image/webp"
	case bytes.HasPrefix(data, []byte("GIF8")):
		return "image/gif"
	case bytes.HasPrefix(data, []byte("BM")):
		return "image/bmp"
	}
	switch declared = strings.ToLower(strings.TrimSpace(declared)); declared {
	case "jpg", "jpeg", "image/jpg":
		return "image/jpeg"
	case "png":
		return "image/png"
	}
	if strings.HasPrefix(declared, "image/") {
		return declared
	}
	return ""
}

// addChapter appends a chapter unless the per-file cap has been reached.
func (p *prober) addChapter(c Chapter) {
	if len(p.info.Chapters) < maxChapters {
		p.info.Chapters = append(p.info.Chapters, c)
	}
}

// normalize sanitises the duration and puts chapters into canonical form.
// It is idempotent, so it can run again after an ffprobe merge.
func (info *Info) normalize() {
	if !(info.Duration > 0) || math.IsInf(info.Duration, 0) {
		info.Duration = 0
	}
	info.Chapters = normalizeChapters(info.Chapters, info.Duration)
}

// normalizeChapters sorts chapters by start, drops ones that start outside
// the file or duplicate another's start (keeping a titled one), names
// untitled chapters "Chapter N" and fills every End with the next start
// (the last one with the file duration, when known).
func normalizeChapters(chs []Chapter, duration float64) []Chapter {
	out := make([]Chapter, 0, len(chs))
	for _, c := range chs {
		if math.IsNaN(c.Start) || math.IsInf(c.Start, 0) || (duration > 0 && c.Start >= duration) {
			continue
		}
		c.Start = max(c.Start, 0)
		c.Title = cleanText(c.Title)
		out = append(out, c)
	}
	slices.SortStableFunc(out, func(a, b Chapter) int { return cmp.Compare(a.Start, b.Start) })

	const sameStart = 0.001 // seconds
	dedup := out[:0]
	for _, c := range out {
		if n := len(dedup); n > 0 && c.Start-dedup[n-1].Start < sameStart {
			if dedup[n-1].Title == "" {
				dedup[n-1].Title = c.Title
			}
			continue
		}
		dedup = append(dedup, c)
	}
	if len(dedup) == 0 {
		return nil
	}

	for i := range dedup {
		c := &dedup[i]
		switch {
		case i+1 < len(dedup):
			c.End = dedup[i+1].Start
		case duration > 0:
			c.End = duration
		case !(c.End > c.Start) || math.IsInf(c.End, 0):
			c.End = c.Start
		}
		if c.Title == "" {
			c.Title = fmt.Sprintf("Chapter %d", i+1)
		}
	}
	return dedup
}
