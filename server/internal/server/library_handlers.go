package server

import (
	"errors"
	"io/fs"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/vburenin/bookbeam/server/internal/auth"
	"github.com/vburenin/bookbeam/server/internal/library"
)

// audioTypes maps audio extensions to the Content-Type browsers expect.
var audioTypes = map[string]string{
	".mp3":  "audio/mpeg",
	".m4a":  "audio/mp4",
	".m4b":  "audio/mp4",
	".mp4":  "audio/mp4",
	".aac":  "audio/aac",
	".ogg":  "audio/ogg",
	".oga":  "audio/ogg",
	".opus": "audio/ogg",
	".flac": "audio/flac",
	".wav":  "audio/wav",
	".webm": "audio/webm",
}

// bookSummary is a book in GET api/library.
type bookSummary struct {
	ID           string  `json:"id"`
	Path         string  `json:"path"`
	Folder       string  `json:"folder"`
	Title        string  `json:"title"`
	Author       string  `json:"author,omitempty"`
	Narrator     string  `json:"narrator,omitempty"`
	Series       string  `json:"series,omitempty"`
	SeriesPart   string  `json:"seriesPart,omitempty"`
	Year         string  `json:"year,omitempty"`
	Genre        string  `json:"genre,omitempty"`
	Duration     float64 `json:"duration"`
	TrackCount   int     `json:"trackCount"`
	ChapterCount int     `json:"chapterCount"`
	Cover        string  `json:"cover"`
	AddedAt      int64   `json:"addedAt"`
	Size         int64   `json:"size"`
}

type trackDTO struct {
	Index    int     `json:"index"`
	Title    string  `json:"title"`
	Path     string  `json:"path"`
	Duration float64 `json:"duration"`
	Start    float64 `json:"start"`
	Size     int64   `json:"size"`
	Format   string  `json:"format"`
	URL      string  `json:"url"`
}

type chapterDTO struct {
	Index     int     `json:"index"`
	Title     string  `json:"title"`
	Track     int     `json:"track"`
	Start     float64 `json:"start"`
	End       float64 `json:"end"`
	BookStart float64 `json:"bookStart"`
}

// bookDetail is GET api/books/{id}.
type bookDetail struct {
	bookSummary
	Description string       `json:"description,omitempty"`
	Tracks      []trackDTO   `json:"tracks"`
	Chapters    []chapterDTO `json:"chapters"`
}

// libraryEvent is the SSE "library" payload.
type libraryEvent struct {
	Version  string `json:"version"`
	Scanning bool   `json:"scanning"`
	// Refused is "empty" when a requested rescan found no audio at all and
	// kept the previous library (the folder is most likely not mounted).
	// A forced rescan accepts an empty library.
	Refused string `json:"refused,omitempty"`
}

func summarize(b *library.Book) bookSummary {
	cover := ""
	if b.Cover != nil {
		cover = "api/books/" + b.ID + "/cover?v=" + b.Cover.Version
	}
	return bookSummary{
		ID: b.ID, Path: b.Path, Folder: b.Folder, Title: b.Title,
		Author: b.Author, Narrator: b.Narrator, Series: b.Series, SeriesPart: b.SeriesPart,
		Year: b.Year, Genre: b.Genre, Duration: b.Duration,
		TrackCount: len(b.Tracks), ChapterCount: len(b.Chapters),
		Cover: cover, AddedAt: b.AddedAt, Size: b.Size,
	}
}

func detail(b *library.Book) bookDetail {
	d := bookDetail{
		bookSummary: summarize(b),
		Description: b.Description,
		Tracks:      make([]trackDTO, len(b.Tracks)),
		Chapters:    make([]chapterDTO, len(b.Chapters)),
	}
	for i, t := range b.Tracks {
		d.Tracks[i] = trackDTO{
			Index: i, Title: t.Title, Path: t.Path, Duration: t.Duration, Start: t.Start,
			Size: t.Size, Format: t.Format, URL: trackURL(b, i),
		}
	}
	for i, c := range b.Chapters {
		d.Chapters[i] = chapterDTO{Index: i, Title: c.Title, Track: c.Track, Start: c.Start, End: c.End, BookStart: c.BookStart}
	}
	return d
}

// trackURL is a track's audio URL. It carries the file's fingerprint, so
// the URL changes whenever the index→file mapping or the file does, and
// the audio can be cached for good (see handleAudio). Clients use it
// verbatim.
func trackURL(b *library.Book, i int) string {
	return "api/books/" + b.ID + "/tracks/" + strconv.Itoa(i) + "/audio?v=" + b.Tracks[i].Fingerprint
}

// libraryETag is the validator of GET api/library. It describes the whole
// body: the index version, the scan time and whether a scan is running.
// (A body saying "scanning" must not stay valid once the scan is over,
// even when the scan changed nothing.) Clients echo the ETag they got.
func libraryETag(idx *library.Index, scanning bool) string {
	etag := idx.Version + "." + strconv.FormatInt(idx.ScannedAt, 36)
	if scanning {
		etag += ".scanning"
	}
	return `"` + etag + `"`
}

// handleLibrary lists all books, with ETag/If-None-Match revalidation.
func (s *Server) handleLibrary(w http.ResponseWriter, r *http.Request, _ auth.Session) {
	idx := s.lib.Index()
	scanning := s.lib.Scanning()
	etag := libraryETag(idx, scanning)
	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", "no-cache")
	if etagMatches(r.Header.Get("If-None-Match"), etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	books := make([]bookSummary, len(idx.Books))
	for i, b := range idx.Books {
		books[i] = summarize(b)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"version":   idx.Version,
		"scannedAt": idx.ScannedAt,
		"scanning":  scanning,
		"books":     books,
	})
}

func (s *Server) handleRescan(w http.ResponseWriter, r *http.Request, _ auth.Session) {
	var body struct {
		// Force publishes the result even when no audio is found (the
		// library really was emptied); otherwise such a scan is refused.
		Force bool `json:"force"`
	}
	if err := decodeJSON(w, r, &body); err != nil && !errors.Is(err, errEmptyBody) {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	s.lib.RequestRescan(library.RescanOptions{Force: body.Force})
	s.hub.publishAll("library", libraryEvent{Version: s.lib.Index().Version, Scanning: true})
	writeJSON(w, http.StatusAccepted, map[string]bool{"scanning": true})
}

// bookFor resolves {id}, answering 404 when unknown.
func (s *Server) bookFor(w http.ResponseWriter, r *http.Request) *library.Book {
	b := s.lib.Index().Book(r.PathValue("id"))
	if b == nil {
		writeError(w, http.StatusNotFound, "book not found")
	}
	return b
}

func (s *Server) handleBook(w http.ResponseWriter, r *http.Request, _ auth.Session) {
	if b := s.bookFor(w, r); b != nil {
		writeJSON(w, http.StatusOK, detail(b))
	}
}

func (s *Server) handleCover(w http.ResponseWriter, r *http.Request, _ auth.Session) {
	b := s.bookFor(w, r)
	if b == nil {
		return
	}
	if b.Cover == nil {
		writeError(w, http.StatusNotFound, "no cover")
		return
	}
	cover := b.Cover
	// The URL carries ?v=<version>, so the image can be cached forever.
	s.serveFile(w, r, b.Cover.MIME, func() (string, error) { return s.lib.ResolveCover(cover) },
		func(fs.FileInfo) string { return "private, max-age=31536000, immutable" })
}

// handleAudio streams one track. Only files in the index are reachable,
// never arbitrary paths.
func (s *Server) handleAudio(w http.ResponseWriter, r *http.Request, _ auth.Session) {
	b := s.bookFor(w, r)
	if b == nil {
		return
	}
	n, err := strconv.Atoi(r.PathValue("n"))
	if err != nil || n < 0 || n >= len(b.Tracks) {
		writeError(w, http.StatusNotFound, "track not found")
		return
	}
	t := b.Tracks[n]
	ctype, ok := audioTypes[strings.ToLower(path.Ext(t.Path))]
	if !ok {
		ctype = "application/octet-stream"
	}
	v := r.URL.Query().Get("v")
	s.serveFile(w, r, ctype, func() (string, error) { return s.lib.ResolveFile(t.Path) }, func(st fs.FileInfo) string {
		// Cache for good only what the URL's fingerprint promises: the
		// indexed version of the file. A file replaced since the last scan
		// (or an old/missing ?v=) is revalidated on every use instead.
		if v != "" && v == t.Fingerprint && st.Size() == t.Size && st.ModTime().UnixNano() == t.ModTime {
			return "private, max-age=31536000, immutable"
		}
		return "private, no-cache"
	})
}

// serveFile streams a media file with Range/HEAD/conditional support.
// resolve returns the file's real path; it re-checks at serve time where
// the file really is, so a symlink in the library swapped after the scan
// cannot hand out BookBeam's state (session key, users' data) or v1's.
// The content type and caching policy (cacheControl, given the file's
// current state) apply only when the file can be served. The ETag follows
// the file's size and modification time, so revalidation notices a file
// replaced within the same second.
func (s *Server) serveFile(w http.ResponseWriter, r *http.Request, ctype string, resolve func() (string, error), cacheControl func(fs.FileInfo) string) {
	real, err := resolve()
	if errors.Is(err, library.ErrForbidden) {
		s.log.Warn("refusing to serve a media file that resolves into BookBeam's own files", "path", r.URL.Path)
		writeError(w, http.StatusNotFound, "file not found")
		return
	}
	var f *os.File
	if err == nil {
		f, err = os.Open(real)
	}
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// The index is stale (file removed since the last scan).
			writeError(w, http.StatusNotFound, "file not found")
		} else {
			s.log.Error("opening media", "path", r.URL.Path, "err", err)
			writeError(w, http.StatusInternalServerError, "cannot read file")
		}
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		writeError(w, http.StatusNotFound, "file not found")
		return
	}
	h := w.Header()
	h.Set("Content-Type", ctype)
	h.Set("Cache-Control", cacheControl(st))
	h.Set("ETag", `"`+strconv.FormatInt(st.Size(), 36)+"-"+strconv.FormatInt(st.ModTime().UnixNano(), 36)+`"`)
	http.ServeContent(w, r, "", st.ModTime().Truncate(time.Second), f)
}
