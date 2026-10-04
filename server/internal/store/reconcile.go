package store

import (
	"math"
	"path"
	"slices"
	"sort"

	"github.com/vburenin/bookbeam/server/internal/library"
)

// Re-linking: keep everyone's place when the library's files change.
//
// A saved place is a file (TrackPath, TrackSize) and a position in it. The
// book id (a hash of the book's folder or file path) and the track index (a
// position in the book's sorted file list) are derived from the library and
// change when files are added, removed, renamed or regrouped: a missing
// chapter restored shifts every index after it, a second .m4b dropped into
// a folder splits a folder book into single-file books, and a parent
// tidying up into Author/Series folders renames everything. reconcile
// re-derives them from the current index:
//
//  1. The entry's book exists but tracks[TrackIndex] is another file:
//     re-point it to its file within the same book (by path; else by name
//     and size, or by size alone, for a renamed file).
//  2. The entry's book is gone: find its file by exact path anywhere in the
//     library (the folder was regrouped), else by a unique name+size match
//     (the folder was renamed or moved), and move the entry to that book.
//     When the target already has progress, the more recently updated one
//     wins.
//  3. Bookmarks the same way, one by one. Bookmarks saved before they
//     carried a path are anchored to the file at their index while their
//     book still exists.
//
// Entries that match nothing are kept untouched, never deleted: the files
// may come back (an unmounted share), and a later pass re-links them.
// Re-linking changes how a place is described, not the place itself, so
// UpdatedAt is left alone (a device's newer local position must still win).

// Change kinds.
const (
	ChangeProgress  = "progress"
	ChangeBookmarks = "bookmarks"
)

// Change is user data the store changed on its own (re-linked after a
// library change, or created by the v1 migration) that connected clients
// should be told about.
type Change struct {
	Kind   string // ChangeProgress or ChangeBookmarks
	BookID string
	// Progress is the book's progress after the change; nil when the
	// entry moved to another book.
	Progress *Progress
	// MovedTo names the book a progress entry moved to (Progress is nil):
	// a device that has the old book loaded can carry on under the new id.
	MovedTo string
	// Bookmarks is the book's complete bookmark list after the change
	// (empty when they all moved away).
	Bookmarks []Bookmark
}

// durationTolerance is how far two duration snapshots of the same files
// may differ (re-probing is deterministic, but rounding is not free).
const durationTolerance = 1.0

// reconcileLocked re-links u's data against idx unless that was already
// done for this or a newer index. The caller holds u.mu.
func (s *Store) reconcileLocked(u *user, idx *library.Index) []Change {
	if idx.Len() == 0 || idx.Version == u.reconciled || idx.ScannedAt < u.reconciledAt {
		// An empty index resolves nothing (the library is not scanned or
		// not mounted). An older index can arrive from a request that
		// started before a scan finished; re-linking against it would
		// undo the newer pass.
		return nil
	}
	changes := relink(u.data, idx)
	u.reconciled, u.reconciledAt = idx.Version, idx.ScannedAt
	if len(changes) > 0 {
		s.log.Info("re-linked saved places to changed library files", "user", u.name, "changes", len(changes))
		if err := s.save(u); err != nil {
			u.reconciled = "" // retry (and persist) on the next request
		}
	}
	return changes
}

// relink applies the re-linking rules to d and reports what changed.
func relink(d *UserData, idx *library.Index) []Change {
	var out []Change
	progressChanged := map[string]bool{}
	for _, id := range sortedKeys(d.Progress) {
		p := d.Progress[id]
		if p == nil {
			continue
		}
		b := idx.Book(id)
		if b != nil {
			if ok, backfilled := resolveInPlace(p, b); ok {
				if refresh(p, b) || backfilled {
					progressChanged[id] = true
				}
				continue
			}
		}
		nb, ti, ok := locate(idx, b, p.TrackPath, p.TrackSize, p.Duration)
		if !ok {
			continue
		}
		repoint(p, nb, ti)
		if nb == b {
			progressChanged[id] = true
			continue
		}
		delete(d.Progress, id)
		out = append(out, Change{Kind: ChangeProgress, BookID: id, MovedTo: nb.ID})
		delete(progressChanged, id)
		if cur := d.Progress[nb.ID]; cur != nil {
			p = mergeProgress(cur, p)
		}
		d.Progress[nb.ID] = p
		progressChanged[nb.ID] = true
	}
	for _, id := range sortedKeys(progressChanged) {
		cp := *d.Progress[id]
		out = append(out, Change{Kind: ChangeProgress, BookID: id, Progress: &cp})
	}

	bookmarksChanged := map[string]bool{}
	for _, id := range sortedKeys(d.Bookmarks) {
		b := idx.Book(id)
		var keep []Bookmark
		for _, bm := range d.Bookmarks[id] {
			if b != nil {
				if ok, backfilled := resolveBookmarkInPlace(&bm, b); ok {
					if refreshBookmark(&bm, b) || backfilled {
						bookmarksChanged[id] = true
					}
					keep = append(keep, bm)
					continue
				}
			}
			nb, ti, ok := locate(idx, b, bm.TrackPath, bm.TrackSize, 0)
			if !ok {
				keep = append(keep, bm)
				continue
			}
			repointBookmark(&bm, nb, ti)
			bookmarksChanged[id] = true
			if nb == b {
				keep = append(keep, bm)
				continue
			}
			bookmarksChanged[nb.ID] = true
			if !slices.ContainsFunc(d.Bookmarks[nb.ID], func(x Bookmark) bool { return x.ID == bm.ID }) {
				d.Bookmarks[nb.ID] = append(d.Bookmarks[nb.ID], bm)
			}
		}
		if bookmarksChanged[id] {
			d.Bookmarks[id] = keep
		}
	}
	for _, id := range sortedKeys(bookmarksChanged) {
		list := d.Bookmarks[id]
		sortBookmarks(list)
		if len(list) == 0 {
			delete(d.Bookmarks, id)
			list = []Bookmark{}
		}
		out = append(out, Change{Kind: ChangeBookmarks, BookID: id, Bookmarks: slices.Clone(list)})
	}
	return out
}

// resolveInPlace reports whether p's place is the file at p.TrackIndex of
// its (existing) book b. An entry without a path is anchored to the file
// at its index (backfilled reports that).
func resolveInPlace(p *Progress, b *library.Book) (ok, backfilled bool) {
	if p.TrackIndex < 0 || p.TrackIndex >= len(b.Tracks) {
		return false, false
	}
	if p.TrackPath == "" {
		p.TrackPath, backfilled = b.Tracks[p.TrackIndex].Path, true
	}
	return b.Tracks[p.TrackIndex].Path == p.TrackPath, backfilled
}

// resolveBookmarkInPlace is resolveInPlace for bookmarks. Bookmarks saved
// before they carried a path are anchored to the file at their index the
// first time they are seen while their book still exists, unless their
// book position shows the book's files have shifted since they were saved
// (then the file at the index is not theirs, and they are left alone).
func resolveBookmarkInPlace(bm *Bookmark, b *library.Book) (ok, backfilled bool) {
	if bm.TrackIndex < 0 || bm.TrackIndex >= len(b.Tracks) {
		return false, false
	}
	t := b.Tracks[bm.TrackIndex]
	if bm.TrackPath == "" {
		if knownStart(b, bm.TrackIndex) && math.Abs(t.Start+bm.Position-bm.BookPosition) > durationTolerance {
			return false, false
		}
		bm.TrackPath, backfilled = t.Path, true
	}
	return t.Path == bm.TrackPath, backfilled
}

// refresh brings p's derived fields up to date with its (unchanged) track
// and reports whether anything changed.
func refresh(p *Progress, b *library.Book) bool {
	t := b.Tracks[p.TrackIndex]
	changed := false
	if p.TrackSize != t.Size {
		p.TrackSize, changed = t.Size, true
	}
	if p.Path != b.Path {
		p.Path, changed = b.Path, true
	}
	if knownStart(b, p.TrackIndex) && math.Abs(p.BookPosition-(t.Start+p.Position)) > 0.5 {
		// An earlier file was replaced by one of another length.
		p.BookPosition, changed = t.Start+p.Position, true
	}
	if p.Duration != b.Duration {
		p.Duration, changed = b.Duration, true
	}
	return changed
}

func refreshBookmark(bm *Bookmark, b *library.Book) bool {
	t := b.Tracks[bm.TrackIndex]
	changed := false
	if bm.TrackSize != t.Size {
		bm.TrackSize, changed = t.Size, true
	}
	if knownStart(b, bm.TrackIndex) && math.Abs(bm.BookPosition-(t.Start+bm.Position)) > 0.5 {
		bm.BookPosition, changed = t.Start+bm.Position, true
	}
	return changed
}

// repoint files p under track ti of book b, keeping the position in the
// file.
func repoint(p *Progress, b *library.Book, ti int) {
	t := b.Tracks[ti]
	p.BookID = b.ID
	p.Path = b.Path
	p.TrackIndex = ti
	p.TrackPath = t.Path
	p.TrackSize = t.Size
	p.BookPosition = t.Start + p.Position
	p.Duration = b.Duration
}

func repointBookmark(bm *Bookmark, b *library.Book, ti int) {
	t := b.Tracks[ti]
	bm.TrackIndex = ti
	bm.TrackPath = t.Path
	bm.TrackSize = t.Size
	bm.BookPosition = t.Start + bm.Position
}

// knownStart reports whether track ti's offset in the book is exact (every
// earlier track has a known duration).
func knownStart(b *library.Book, ti int) bool {
	for i := range ti {
		if b.Tracks[i].Duration <= 0 {
			return false
		}
	}
	return true
}

// locate finds the track a saved place refers to. With inBook set (the
// entry's book still exists) only that book is searched; otherwise the
// whole library. bookDuration (0 = unknown) breaks ties between equally
// named and sized files in different books.
func locate(idx *library.Index, inBook *library.Book, trackPath string, size int64, bookDuration float64) (*library.Book, int, bool) {
	if trackPath == "" {
		return nil, 0, false
	}
	if b, ti, ok := idx.TrackByPath(trackPath); ok && (inBook == nil || b == inBook) {
		return b, ti, true
	}
	if size <= 0 {
		return nil, 0, false // a size is needed to tell files with generic names apart
	}
	refs := idx.TracksByBaseAndSize(path.Base(trackPath), size)
	if inBook != nil {
		refs = slices.DeleteFunc(refs, func(r library.TrackRef) bool { return r.Book != inBook })
		if len(refs) == 0 {
			// A file renamed inside its book keeps its size.
			for i, t := range inBook.Tracks {
				if t.Size == size {
					refs = append(refs, library.TrackRef{Book: inBook, Track: i})
				}
			}
		}
	}
	if len(refs) > 1 && bookDuration > 0 {
		refs = slices.DeleteFunc(refs, func(r library.TrackRef) bool {
			return math.Abs(r.Book.Duration-bookDuration) > durationTolerance
		})
	}
	if len(refs) != 1 {
		return nil, 0, false // nothing, or ambiguous: leave the entry alone
	}
	return refs[0].Book, refs[0].Track, true
}

// mergeProgress combines two entries for the same book (after re-linking
// moved one onto the other): the more recently updated place wins, and
// listening time adds up.
func mergeProgress(a, b *Progress) *Progress {
	win, lose := a, b
	if b.UpdatedAt > a.UpdatedAt {
		win, lose = b, a
	}
	out := *win
	out.Listened = a.Listened + b.Listened
	if lose.StartedAt > 0 && (out.StartedAt == 0 || lose.StartedAt < out.StartedAt) {
		out.StartedAt = lose.StartedAt
	}
	return &out
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
