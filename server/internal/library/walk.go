package library

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
)

// audioFormats maps supported audio extensions to their format names.
var audioFormats = map[string]string{
	".mp3":  "mp3",
	".m4a":  "m4a",
	".m4b":  "m4b",
	".aac":  "aac",
	".ogg":  "ogg",
	".oga":  "ogg",
	".opus": "opus",
	".flac": "flac",
	".wav":  "wav",
	".webm": "webm",
}

// imageExts are the cover image extensions the walk collects. A file's
// content decides whether it is really an image (see coverMIME).
var imageExts = map[string]bool{
	".jpg":  true,
	".jpeg": true,
	".png":  true,
	".webp": true,
	".gif":  true,
	".bmp":  true,
}

// metaTextFiles are the per-book text files the scanner reads.
var metaTextFiles = map[string]bool{
	"desc.txt":        true,
	"description.txt": true,
	"summary.txt":     true,
	"reader.txt":      true,
}

// skipDirNames are NAS/OS housekeeping folders that never hold books.
var skipDirNames = map[string]bool{
	"@eaDir":                    true,
	"#recycle":                  true,
	"#snapshot":                 true,
	"lost+found":                true,
	"$RECYCLE.BIN":              true,
	"System Volume Information": true,
}

// maxWalkDepth guards against absurdly deep (or adversarial) trees.
const maxWalkDepth = 64

// fileEntry is a file found by the walk.
type fileEntry struct {
	Name    string
	Rel     string // library-relative, "/"-separated
	Size    int64
	ModTime int64 // unix ns
}

// dirNode is a directory found by the walk, with its relevant contents.
type dirNode struct {
	Name   string
	Rel    string // "" for the root
	Audio  []fileEntry
	Images []fileEntry
	Texts  map[string]string // lower-cased name -> rel path (metaTextFiles)
	Dirs   []*dirNode
	// AudioBelow reports audio anywhere in this subtree (including here).
	AudioBelow bool
}

// denyList holds real (symlink-free) paths whose contents must never be
// indexed or served: BookBeam's state and the legacy v1 secret and state
// files.
type denyList []string

func (d denyList) contains(real string) bool {
	for _, p := range d {
		if real == p || strings.HasPrefix(real, p+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// walker builds the dirNode tree for a scan.
type walker struct {
	ctx     context.Context
	root    string
	log     *slog.Logger
	deny    denyList
	visited map[string]bool // real directories already walked (cycle safety)
	// links are symlinked directories found so far, walked only after every
	// real directory has been claimed.
	links []pendingLink
	// failed lists library-relative paths that could not be read for a
	// reason other than not existing (EACCES, EIO, a NAS timeout...). The
	// previous scan's books there are kept rather than dropped.
	failed []string
}

// pendingLink is a symlinked directory waiting to be walked.
type pendingLink struct {
	parent         *dirNode
	abs, rel, name string
	depth          int
}

// walk scans the library root. Unreadable sub-directories are logged and
// recorded in failed; an unreadable root is an error (the library is
// probably not mounted, and an empty result would wipe the index).
//
// Symlinked directories are followed once every real directory has been
// walked, so an alias ("By Series/Dune" -> "../Herbert/Dune") never claims a
// book in place of the folder it points at, whatever the names' order.
func (w *walker) walk() (*dirNode, error) {
	real, err := filepath.EvalSymlinks(w.root)
	if err != nil {
		return nil, fmt.Errorf("library root: %w", err)
	}
	w.visited = map[string]bool{real: true}
	root, err := w.dir(w.root, real, "", "", 0)
	if err != nil {
		return nil, fmt.Errorf("library root: %w", err)
	}
	for len(w.links) > 0 {
		link := w.links[0]
		w.links = w.links[1:]
		if err := w.follow(link); err != nil {
			return nil, err
		}
	}
	finishTree(root)
	return root, nil
}

// follow walks a symlinked directory unless its target was already walked
// (the real folder, another alias of it, or a cycle).
func (w *walker) follow(link pendingLink) error {
	real, err := filepath.EvalSymlinks(link.abs)
	if err != nil {
		w.unreadable(link.rel, err)
		return nil
	}
	if w.deny.contains(real) || w.visited[real] {
		return nil
	}
	w.visited[real] = true
	child, err := w.dir(link.abs, real, link.rel, link.name, link.depth)
	if err != nil {
		if w.ctx.Err() != nil {
			return w.ctx.Err()
		}
		w.unreadable(link.rel, err)
		return nil
	}
	link.parent.Dirs = append(link.parent.Dirs, child)
	return nil
}

// unreadable logs a path that could not be read and, unless it simply no
// longer exists (or is a dangling symlink), records it as failed.
func (w *walker) unreadable(rel string, err error) {
	if errors.Is(err, fs.ErrNotExist) {
		w.log.Warn("skipping vanished entry or dangling symlink", "path", rel, "err", err)
		return
	}
	w.log.Warn("cannot read; keeping what the previous scan found there", "path", rel, "err", err)
	w.failed = append(w.failed, rel)
}

// dir reads one directory. real is its symlink-free path, from which the
// real paths of its plain entries follow without further system calls.
func (w *walker) dir(abs, real, rel, name string, depth int) (*dirNode, error) {
	if err := w.ctx.Err(); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(abs)
	if err != nil {
		return nil, err
	}
	node := &dirNode{Name: name, Rel: rel, Texts: map[string]string{}}
	for _, e := range entries {
		ename := e.Name()
		if strings.HasPrefix(ename, ".") {
			continue // dot-files, dot-dirs (incl. .bookbeam), macOS "._" forks
		}
		eabs := filepath.Join(abs, ename)
		erel := path.Join(rel, ename)
		ereal := filepath.Join(real, ename)
		link := e.Type()&fs.ModeSymlink != 0

		// Resolve symlinks: follow them to directories and regular files.
		var info fs.FileInfo
		if link {
			info, err = os.Stat(eabs)
		} else {
			info, err = e.Info()
		}
		if err != nil {
			w.unreadable(erel, err)
			continue
		}

		if info.IsDir() {
			if skipDirNames[ename] || (rel == "" && ename == "state") {
				continue
			}
			if depth+1 > maxWalkDepth {
				w.log.Warn("skipping directory nested too deeply", "path", erel)
				continue
			}
			if link {
				w.links = append(w.links, pendingLink{parent: node, abs: eabs, rel: erel, name: ename, depth: depth + 1})
				continue
			}
			if w.deny.contains(ereal) || w.visited[ereal] {
				continue
			}
			w.visited[ereal] = true
			child, err := w.dir(eabs, ereal, erel, ename, depth+1)
			if err != nil {
				if w.ctx.Err() != nil {
					return nil, w.ctx.Err()
				}
				w.unreadable(erel, err)
				continue
			}
			node.Dirs = append(node.Dirs, child)
			continue
		}
		if !info.Mode().IsRegular() {
			continue
		}

		ext := strings.ToLower(filepath.Ext(ename))
		lower := strings.ToLower(ename)
		isAudio, isImage, isText := audioFormats[ext] != "", imageExts[ext], metaTextFiles[lower]
		if !isAudio && !isImage && !isText {
			continue
		}
		if info.Size() == 0 {
			// Failed downloads and sync placeholders. A file still being
			// copied is picked up by the next scan.
			w.log.Debug("skipping empty file", "path", erel)
			continue
		}
		if link {
			if ereal, err = filepath.EvalSymlinks(eabs); err != nil {
				w.unreadable(erel, err)
				continue
			}
		}
		if w.deny.contains(ereal) {
			w.log.Warn("skipping a file that resolves into BookBeam's own state", "path", erel)
			continue
		}

		fe := fileEntry{Name: ename, Rel: erel, Size: info.Size(), ModTime: info.ModTime().UnixNano()}
		switch {
		case isAudio:
			node.Audio = append(node.Audio, fe)
		case isImage:
			node.Images = append(node.Images, fe)
		default:
			node.Texts[lower] = erel
		}
	}
	slices.SortFunc(node.Audio, compareFiles)
	slices.SortFunc(node.Images, compareFiles)
	return node, nil
}

// compareFiles orders files naturally by name without the extension first,
// so "Chapter 1.mp3" plays before "Chapter 1 (continued).mp3" (the '.' of
// the extension would otherwise sort after ' ', '(' and '-').
func compareFiles(a, b fileEntry) int {
	return cmp.Or(NaturalCompare(stripExt(a.Name), stripExt(b.Name)), NaturalCompare(a.Name, b.Name))
}

// finishTree sorts every directory's sub-directories (symlinked ones are
// appended late) and computes AudioBelow.
func finishTree(d *dirNode) bool {
	slices.SortFunc(d.Dirs, func(a, b *dirNode) int { return NaturalCompare(a.Name, b.Name) })
	d.AudioBelow = len(d.Audio) > 0
	for _, sub := range d.Dirs {
		if finishTree(sub) {
			d.AudioBelow = true
		}
	}
	return d.AudioBelow
}

// dropAudio removes the audio files rejected by keep from the tree and
// recomputes AudioBelow.
func dropAudio(root *dirNode, keep func(fileEntry) bool) {
	var filter func(d *dirNode)
	filter = func(d *dirNode) {
		d.Audio = slices.DeleteFunc(d.Audio, func(f fileEntry) bool { return !keep(f) })
		for _, sub := range d.Dirs {
			filter(sub)
		}
	}
	filter(root)
	finishTree(root)
}
