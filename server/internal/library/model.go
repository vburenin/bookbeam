package library

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path"
	"slices"
)

// Book is one audiobook. Books inside a published Index are immutable.
type Book struct {
	ID string `json:"id"`
	// Path is the book directory, or the audio file for single-file books,
	// relative to the library root with "/" separators.
	Path string `json:"path"`
	// Folder is Path's parent directory ("" for the library root).
	Folder      string    `json:"folder"`
	Title       string    `json:"title"`
	Author      string    `json:"author,omitempty"`
	Narrator    string    `json:"narrator,omitempty"`
	Series      string    `json:"series,omitempty"`
	SeriesPart  string    `json:"seriesPart,omitempty"`
	Year        string    `json:"year,omitempty"`
	Genre       string    `json:"genre,omitempty"`
	Description string    `json:"description,omitempty"`
	Duration    float64   `json:"duration"` // seconds; sum of track durations
	Size        int64     `json:"size"`     // bytes; sum of track sizes
	AddedAt     int64     `json:"addedAt"`  // ms since epoch
	Cover       *Cover    `json:"cover,omitempty"`
	Tracks      []Track   `json:"tracks"`
	Chapters    []Chapter `json:"chapters"`
}

// Track is one audio file of a book.
type Track struct {
	Title    string  `json:"title"`
	Path     string  `json:"path"` // library-relative
	Format   string  `json:"format"`
	Duration float64 `json:"duration"` // seconds; 0 when unknown
	Start    float64 `json:"start"`    // offset within the book
	Size     int64   `json:"size"`
	ModTime  int64   `json:"mtime"` // unix ns
	// Fingerprint identifies this exact version of the file (see
	// TrackFingerprint); it changes whenever the file is replaced, so it can
	// version cacheable URLs.
	Fingerprint string `json:"fingerprint"`
}

// TrackFingerprint is the first 12 hex digits of
// sha1("<rel path>|<size>|<mtime unix ns>").
func TrackFingerprint(rel string, size, mtime int64) string {
	return shortHash(fmt.Sprintf("%s|%d|%d", rel, size, mtime), 12)
}

// Chapter is a navigation point: an embedded chapter, or a whole track.
type Chapter struct {
	Title     string  `json:"title"`
	Track     int     `json:"track"`
	Start     float64 `json:"start"` // within the track
	End       float64 `json:"end"`   // within the track
	BookStart float64 `json:"bookStart"`
}

// Cover kinds.
const (
	CoverFile     = "file"     // an image file inside the library
	CoverEmbedded = "embedded" // art extracted into the covers cache
)

// Cover locates a book's cover image.
type Cover struct {
	Kind string `json:"kind"`
	// Source is a library-relative path (CoverFile) or a file name inside the
	// covers cache directory (CoverEmbedded).
	Source string `json:"source"`
	MIME   string `json:"mime"`
	// Version changes whenever the image does (cache-busting URL param).
	Version string `json:"version"`
}

// Index is an immutable snapshot of the library.
type Index struct {
	Version   string
	ScannedAt int64   // ms since epoch; 0 if never scanned
	Books     []*Book // natural order by Path

	byID     map[string]*Book
	byTrack  map[string]TrackRef
	byBaseSz map[baseSize][]TrackRef
}

// TrackRef locates a track inside an index.
type TrackRef struct {
	Book  *Book
	Track int // index into Book.Tracks
}

// baseSize keys tracks by file name and size, which survive a folder rename.
type baseSize struct {
	base string
	size int64
}

// NewIndex builds an index over books (which must not be modified
// afterwards), ordered as given. Tracks lacking a Fingerprint (indexes
// persisted by older versions) get one.
func NewIndex(books []*Book, scannedAt int64) *Index {
	x := &Index{
		ScannedAt: scannedAt,
		Books:     books,
		byID:      make(map[string]*Book, len(books)),
		byTrack:   map[string]TrackRef{},
		byBaseSz:  map[baseSize][]TrackRef{},
	}
	for _, b := range books {
		x.byID[b.ID] = b
		for i := range b.Tracks {
			t := &b.Tracks[i]
			if t.Fingerprint == "" {
				t.Fingerprint = TrackFingerprint(t.Path, t.Size, t.ModTime)
			}
			ref := TrackRef{Book: b, Track: i}
			x.byTrack[t.Path] = ref
			k := baseSize{path.Base(t.Path), t.Size}
			x.byBaseSz[k] = append(x.byBaseSz[k], ref)
		}
	}
	x.Version = versionOf(books)
	return x
}

// withScannedAt returns a copy of the index carrying a new scan time.
func (x *Index) withScannedAt(ms int64) *Index {
	cp := *x
	cp.ScannedAt = ms
	return &cp
}

// Book returns the book with the given id, or nil.
func (x *Index) Book(id string) *Book {
	if x == nil {
		return nil
	}
	return x.byID[id]
}

// TrackByPath finds the book and track index for a library-relative file.
func (x *Index) TrackByPath(rel string) (*Book, int, bool) {
	if x == nil {
		return nil, 0, false
	}
	r, ok := x.byTrack[rel]
	return r.Book, r.Track, ok
}

// TracksByBaseAndSize lists the tracks whose file name (the last path
// element) is base and whose size is size, in index order. It finds a track
// again after its folder was renamed or moved.
func (x *Index) TracksByBaseAndSize(base string, size int64) []TrackRef {
	if x == nil {
		return nil
	}
	return slices.Clone(x.byBaseSz[baseSize{base, size}])
}

// Len returns the number of books.
func (x *Index) Len() int {
	if x == nil {
		return 0
	}
	return len(x.Books)
}

// versionOf hashes everything clients render (ids, metadata, tracks with
// sizes, mtimes and durations, chapters, covers), so any visible change
// yields a new version.
func versionOf(books []*Book) string {
	h := sha1.New()
	enc := json.NewEncoder(h)
	for _, b := range books {
		_ = enc.Encode(b) // hashing into memory cannot fail
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// BookID derives a stable id from a book's library-relative path.
func BookID(rel string) string {
	return "b_" + shortHash(rel, 12)
}

func shortHash(s string, n int) string {
	sum := sha1.Sum([]byte(s))
	return hex.EncodeToString(sum[:])[:n]
}
