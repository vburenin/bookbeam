package library

import (
	"cmp"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/vburenin/bookbeam/server/internal/fsutil"
	"github.com/vburenin/bookbeam/server/internal/media"
)

// coverBaseNames are conventional cover file names, in priority order.
var coverBaseNames = []string{"cover", "folder", "front", "album", "art"}

// coverExt maps the image types served as covers to cache file extensions.
// Images are recognised by content (media.SniffImage), never by name.
var coverExt = map[string]string{
	"image/jpeg": "jpg",
	"image/png":  "png",
	"image/webp": "webp",
	"image/gif":  "gif",
	"image/bmp":  "bmp",
}

// sniffLen is how many leading bytes identify an image.
const sniffLen = 32

// imageEntry caches what an image file's content is, validated by size and
// mtime like probe entries.
type imageEntry struct {
	Size    int64  `json:"size"`
	ModTime int64  `json:"mtime"`
	MIME    string `json:"mime,omitempty"` // "" when it is not an image we serve
}

// pickCover chooses a book's cover:
//   - directory books: a conventionally named image (cover.jpg, folder.png,
//     ...) in the book folder, else in its part and disc folders; else the
//     first embedded picture among the tracks; else the largest image in
//     those folders.
//   - single-file books: an image named like the audio file; else its
//     embedded picture. Folder images are shared by every book in the
//     folder, so they are not used.
//
// Image files whose content is not a JPEG, PNG, WebP, GIF or BMP image are
// passed over whatever their names.
func (s *scanner) pickCover(spec bookSpec) *Cover {
	if spec.Single {
		base := strings.ToLower(stripExt(spec.Files[0].Name))
		for _, img := range spec.Dir.Images {
			if strings.ToLower(stripExt(img.Name)) == base {
				if c := s.fileCover(img); c != nil {
					return c
				}
			}
		}
		return s.embeddedCover(spec.Files)
	}

	for _, d := range spec.Dirs {
		for _, want := range coverBaseNames {
			for _, img := range d.Images {
				if strings.ToLower(stripExt(img.Name)) == want {
					if c := s.fileCover(img); c != nil {
						return c
					}
				}
			}
		}
	}
	if c := s.embeddedCover(spec.Files); c != nil {
		return c
	}
	var imgs []fileEntry
	for _, d := range spec.Dirs {
		imgs = append(imgs, d.Images...)
	}
	slices.SortStableFunc(imgs, func(a, b fileEntry) int { return cmp.Compare(b.Size, a.Size) })
	for _, img := range imgs {
		if c := s.fileCover(img); c != nil {
			return c
		}
	}
	return nil
}

// fileCover returns a cover backed by an image file, or nil when the file
// is not an image.
func (s *scanner) fileCover(img fileEntry) *Cover {
	mime := s.imageMIME(img)
	if mime == "" {
		return nil
	}
	return &Cover{Kind: CoverFile, Source: img.Rel, MIME: mime, Version: fileVersion(img)}
}

// imageMIME identifies an image file by its leading bytes, reading each
// file version once.
func (s *scanner) imageMIME(img fileEntry) string {
	l := s.lib
	if e := s.images[img.Rel]; e != nil {
		return e.MIME
	}
	if e := l.images[img.Rel]; e != nil && e.Size == img.Size && e.ModTime == img.ModTime {
		s.images[img.Rel] = e
		return e.MIME
	}
	head, err := readHead(l.AbsPath(img.Rel), sniffLen)
	if err != nil {
		l.log.Warn("cannot read image", "path", img.Rel, "err", err)
		return "" // not remembered: the next scan tries again
	}
	e := &imageEntry{Size: img.Size, ModTime: img.ModTime, MIME: media.SniffImage(head)}
	if e.MIME == "" {
		l.log.Warn("ignoring an image file that is not a JPEG, PNG, WebP, GIF or BMP image", "path", img.Rel)
	}
	s.images[img.Rel] = e
	s.cacheDirty = true
	return e.MIME
}

// readHead reads up to n leading bytes of a file.
func readHead(abs string, n int) ([]byte, error) {
	f, err := os.Open(abs)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	buf := make([]byte, n)
	m, err := io.ReadFull(f, buf)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return buf[:m], nil
}

// fileVersion is a short fingerprint of a file's identity and content state.
func fileVersion(f fileEntry) string {
	return shortHash(fmt.Sprintf("%s|%d|%d", f.Rel, f.Size, f.ModTime), 8)
}

// embeddedCover returns the art embedded in the first track that has some,
// extracting it into the covers cache once per file version. A failed
// extraction is remembered in the probe entry (until the file changes) so
// that it is not retried, and logged, on every scan; only failures that
// may be transient (I/O errors) are retried.
func (s *scanner) embeddedCover(files []fileEntry) *Cover {
	for _, f := range files {
		e := s.entries[f.Rel]
		if e == nil || e.Info == nil || !e.Info.HasPicture || e.CoverErr != "" {
			continue
		}
		if e.Cover == "" || !fsutil.Exists(filepath.Join(s.lib.coversDir, e.Cover)) {
			name, err := s.extractCover(f)
			if err != nil {
				s.lib.log.Warn("extracting embedded cover", "path", f.Rel, "err", err)
				if !media.IsTransient(err) {
					e.CoverErr = err.Error()
					s.cacheDirty = true
				}
				continue
			}
			e.Cover = name
			s.cacheDirty = true
		}
		return &Cover{
			Kind:    CoverEmbedded,
			Source:  e.Cover,
			MIME:    cachedCoverMIME(e.Cover),
			Version: fileVersion(f),
		}
	}
	return nil
}

// cachedCoverMIME is the MIME type of a file in the covers cache, named
// after the type it was sniffed as.
func cachedCoverMIME(name string) string {
	ext := strings.TrimPrefix(filepath.Ext(name), ".")
	for mime, e := range coverExt {
		if e == ext {
			return mime
		}
	}
	return "application/octet-stream"
}

func (s *scanner) extractCover(f fileEntry) (string, error) {
	info, err := s.lib.probe(s.lib.AbsPath(f.Rel), media.Options{WantPicture: true, FFprobe: s.lib.opts.FFprobe})
	if err != nil {
		return "", err
	}
	if info.Picture == nil || len(info.Picture.Data) == 0 {
		return "", errors.New("no picture data")
	}
	// The bytes decide the type: a declared MIME type can be anything.
	mime := media.SniffImage(info.Picture.Data)
	ext := coverExt[mime]
	if ext == "" {
		return "", fmt.Errorf("embedded picture is not a JPEG, PNG, WebP, GIF or BMP image (declared %q)", info.Picture.MIME)
	}
	name := shortHash(fmt.Sprintf("%s|%d|%d", f.Rel, f.Size, f.ModTime), 40) + "." + ext
	if err := fsutil.WriteFileAtomic(filepath.Join(s.lib.coversDir, name), info.Picture.Data, 0o644); err != nil {
		return "", err
	}
	return name, nil
}

// pruneCovers deletes cached covers no longer referenced by any probe entry
// (entries of vanished files are kept for a grace period, and so are their
// covers).
func (l *Library) pruneCovers() {
	keep := map[string]bool{}
	for _, e := range l.files {
		if e.Cover != "" {
			keep[e.Cover] = true
		}
	}
	dir, err := os.ReadDir(l.coversDir)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			l.log.Warn("listing cover cache", "err", err)
		}
		return
	}
	for _, d := range dir {
		if d.Type().IsRegular() && !keep[d.Name()] {
			if err := os.Remove(filepath.Join(l.coversDir, d.Name())); err != nil {
				l.log.Warn("removing stale cover", "file", d.Name(), "err", err)
			}
		}
	}
}
