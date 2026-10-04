package store

import (
	"cmp"
	"crypto/rand"
	"fmt"
	"math"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/vburenin/bookbeam/server/internal/library"
)

const (
	maxNoteLen           = 2000 // runes
	maxBookmarksPerBook  = 1000
	bookmarkIDAlphabet   = "0123456789abcdefghijklmnopqrstuvwxyz"
	bookmarkIDRandomPart = 10
)

// NewBookmark is the body of POST api/books/{id}/bookmarks.
type NewBookmark struct {
	TrackIndex int `json:"trackIndex"`
	// TrackPath, when it names a track of the book, wins over TrackIndex.
	TrackPath string  `json:"trackPath"`
	Position  float64 `json:"position"`
	Note      string  `json:"note"`
}

// AddBookmark saves a bookmark in a book and returns it together with the
// book's (sorted) bookmarks.
func (s *Store) AddBookmark(name string, idx *library.Index, bookID string, in NewBookmark) (Bookmark, []Bookmark, error) {
	b := idx.Book(bookID)
	if b == nil {
		return Bookmark{}, nil, ErrBookNotFound
	}
	trackIndex := trackIndexOf(idx, b, in.TrackPath, in.TrackIndex)
	if trackIndex < 0 || trackIndex >= len(b.Tracks) {
		return Bookmark{}, nil, invalid("trackIndex out of range")
	}
	note, err := cleanNote(in.Note)
	if err != nil {
		return Bookmark{}, nil, err
	}
	position := math.Max(0, in.Position)

	var bm Bookmark
	var all []Bookmark
	err = s.withUser(name, idx, func(u *user) error {
		list := u.data.Bookmarks[bookID]
		if len(list) >= maxBookmarksPerBook {
			return invalid("too many bookmarks in this book")
		}
		id, err := newBookmarkID()
		if err != nil {
			return err
		}
		bm = Bookmark{
			ID:           id,
			TrackIndex:   trackIndex,
			TrackPath:    b.Tracks[trackIndex].Path,
			TrackSize:    b.Tracks[trackIndex].Size,
			Position:     position,
			BookPosition: bookPosition(b, trackIndex, position, nil),
			Note:         note,
			CreatedAt:    s.now().UnixMilli(),
		}
		list = append(list, bm)
		sortBookmarks(list)
		u.data.Bookmarks[bookID] = list
		all = slices.Clone(list)
		return s.save(u)
	})
	return bm, all, err
}

// UpdateBookmark changes a bookmark's note.
func (s *Store) UpdateBookmark(name string, idx *library.Index, bookID, bmID, note string) (Bookmark, []Bookmark, error) {
	note, err := cleanNote(note)
	if err != nil {
		return Bookmark{}, nil, err
	}
	var bm Bookmark
	var all []Bookmark
	err = s.withUser(name, idx, func(u *user) error {
		list := u.data.Bookmarks[bookID]
		i := slices.IndexFunc(list, func(b Bookmark) bool { return b.ID == bmID })
		if i < 0 {
			return ErrBookmarkNotFound
		}
		list[i].Note = note
		bm = list[i]
		all = slices.Clone(list)
		return s.save(u)
	})
	return bm, all, err
}

// DeleteBookmark removes a bookmark and returns the remaining ones.
func (s *Store) DeleteBookmark(name string, idx *library.Index, bookID, bmID string) ([]Bookmark, error) {
	var all []Bookmark
	err := s.withUser(name, idx, func(u *user) error {
		list := u.data.Bookmarks[bookID]
		i := slices.IndexFunc(list, func(b Bookmark) bool { return b.ID == bmID })
		if i < 0 {
			return ErrBookmarkNotFound
		}
		list = slices.Delete(list, i, i+1)
		if len(list) == 0 {
			delete(u.data.Bookmarks, bookID)
		} else {
			u.data.Bookmarks[bookID] = list
		}
		all = slices.Clone(list)
		return s.save(u)
	})
	if all == nil && err == nil {
		all = []Bookmark{}
	}
	return all, err
}

// sortBookmarks orders a book's bookmarks by position, then age.
func sortBookmarks(list []Bookmark) {
	slices.SortStableFunc(list, func(x, y Bookmark) int {
		return cmp.Or(cmp.Compare(x.BookPosition, y.BookPosition), cmp.Compare(x.CreatedAt, y.CreatedAt))
	})
}

func cleanNote(note string) (string, error) {
	note = strings.TrimSpace(strings.ToValidUTF8(note, ""))
	if utf8.RuneCountInString(note) > maxNoteLen {
		return "", invalid(fmt.Sprintf("note is longer than %d characters", maxNoteLen))
	}
	return note, nil
}

// newBookmarkID returns "k" followed by random base-36 characters.
func newBookmarkID() (string, error) {
	var raw [bookmarkIDRandomPart]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	id := make([]byte, 1, 1+len(raw))
	id[0] = 'k'
	for _, b := range raw {
		id = append(id, bookmarkIDAlphabet[int(b)%len(bookmarkIDAlphabet)])
	}
	return string(id), nil
}
