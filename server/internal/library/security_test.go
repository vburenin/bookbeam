package library

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func symlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}

// TestScanNeverIndexesState: symlinks cannot smuggle BookBeam's state or
// the legacy v1 secret files into the library, whatever they are named.
func TestScanNeverIndexesState(t *testing.T) {
	base := t.TempDir()
	lib, state := filepath.Join(base, "lib"), filepath.Join(base, "state")
	audio := tags(10, "Secret", "Secret", "")
	// Everything an attacker would want, made to look like audio and art.
	writeAudio(t, state, "secret.key", audio)
	writeAudio(t, state, "users/vlad.json", audio)
	writeFile(t, state, "covers/abc.jpg", jpegData("cached"))
	writeAudio(t, lib, "session_secret", audio)
	writeAudio(t, lib, "audiobooks.json", audio)
	writeAudio(t, lib, "state/vlad.json", audio)

	writeAudio(t, lib, "Evil/real.mp3", tags(10, "", "Evil", ""))
	symlink(t, filepath.Join(state, "secret.key"), filepath.Join(lib, "Evil", "a.mp3"))
	symlink(t, "../session_secret", filepath.Join(lib, "Evil", "b.mp3"))
	symlink(t, "../state/vlad.json", filepath.Join(lib, "Evil", "c.m4b"))
	symlink(t, filepath.Join(state, "covers", "abc.jpg"), filepath.Join(lib, "Evil", "cover.jpg"))
	symlink(t, "../audiobooks.json", filepath.Join(lib, "Evil", "desc.txt"))
	symlink(t, "../session_secret", filepath.Join(lib, "Evil", "reader.txt"))
	symlink(t, state, filepath.Join(lib, "StateLink"))
	symlink(t, filepath.Join(state, "users"), filepath.Join(lib, "Users"))
	symlink(t, "state", filepath.Join(lib, "Legacy"))

	tl := openTestLib(t, lib, state)
	tl.scan(t)
	x := tl.Index()
	if got := bookPaths(x); !reflect.DeepEqual(got, []string{"Evil"}) {
		t.Fatalf("books: %q", got)
	}
	evil := bookByPath(t, x, "Evil")
	if got := trackNames(evil); !reflect.DeepEqual(got, []string{"real.mp3"}) {
		t.Errorf("tracks: %q", got)
	}
	if evil.Cover != nil || evil.Description != "" || evil.Narrator != "" {
		t.Errorf("state leaked into metadata: cover %+v, description %q, narrator %q", evil.Cover, evil.Description, evil.Narrator)
	}
}

func TestResolveFile(t *testing.T) {
	base := t.TempDir()
	lib, state := filepath.Join(base, "lib"), filepath.Join(base, "state")
	writeAudio(t, lib, "Book/1.mp3", tags(10, "", "Book", ""))
	writeFile(t, lib, "Book/cover.jpg", jpegData("cover"))
	writeAudio(t, lib, "Emb/1.mp3", withArt(tags(10, "", "Emb", ""), "image/png", pngData("art")))
	writeFile(t, lib, "session_secret", []byte("legacy secret"))
	writeFile(t, state, "secret.key", []byte("current secret"))
	tl := openTestLib(t, lib, state)
	tl.scan(t)
	x := tl.Index()

	real, err := tl.ResolveFile("Book/1.mp3")
	if err != nil || filepath.Base(real) != "1.mp3" {
		t.Fatalf("ResolveFile = %q, %v", real, err)
	}
	cover := bookByPath(t, x, "Book").Cover
	if p, err := tl.ResolveCover(cover); err != nil || filepath.Base(p) != "cover.jpg" {
		t.Fatalf("file cover = %q, %v", p, err)
	}
	emb := bookByPath(t, x, "Emb").Cover
	if p, err := tl.ResolveCover(emb); err != nil || filepath.Dir(p) != mustReal(t, filepath.Join(state, "covers")) {
		t.Fatalf("embedded cover = %q, %v", p, err)
	}

	// Files swapped for symlinks into the state after the scan.
	swap := func(rel, target string) {
		t.Helper()
		p := filepath.Join(lib, filepath.FromSlash(rel))
		if err := os.Remove(p); err != nil {
			t.Fatal(err)
		}
		symlink(t, target, p)
	}
	swap("Book/1.mp3", filepath.Join(state, "secret.key"))
	if _, err := tl.ResolveFile("Book/1.mp3"); !errors.Is(err, ErrForbidden) {
		t.Errorf("track swapped for the secret: err = %v", err)
	}
	swap("Book/1.mp3", filepath.Join(lib, "session_secret"))
	if _, err := tl.ResolveFile("Book/1.mp3"); !errors.Is(err, ErrForbidden) {
		t.Errorf("track swapped for the legacy secret: err = %v", err)
	}
	swap("Book/cover.jpg", filepath.Join(state, "library.json"))
	if _, err := tl.ResolveCover(cover); !errors.Is(err, ErrForbidden) {
		t.Errorf("cover swapped for library.json: err = %v", err)
	}
	// An embedded cover must stay inside the covers cache.
	symlink(t, filepath.Join(lib, "session_secret"), filepath.Join(state, "covers", "evil.jpg"))
	if _, err := tl.ResolveCover(&Cover{Kind: CoverEmbedded, Source: "evil.jpg"}); !errors.Is(err, ErrForbidden) {
		t.Errorf("cache entry linking out: err = %v", err)
	}
	if _, err := tl.ResolveCover(&Cover{Kind: CoverEmbedded, Source: "../library.json"}); err == nil {
		t.Error("cover source escaping the cache must not resolve")
	}
	if _, err := tl.ResolveFile("Gone/1.mp3"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("missing file: err = %v", err)
	}
}

func mustReal(t *testing.T, p string) string {
	t.Helper()
	r, err := filepath.EvalSymlinks(p)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// TestSymlinkAliasDoesNotShadow: an alias of a book folder that sorts first
// must not claim the book; links to folders outside the library still work.
func TestSymlinkAliasDoesNotShadow(t *testing.T) {
	base := t.TempDir()
	lib, outside := filepath.Join(base, "lib"), filepath.Join(base, "outside")
	writeAudio(t, lib, "Loose/Hatchet/1.mp3", tags(10, "", "Hatchet", ""))
	writeAudio(t, lib, "Loose/Holes/1.mp3", tags(10, "", "Holes", ""))
	symlink(t, "../Loose/Hatchet", filepath.Join(lib, "Links", "Hatchet Link"))
	symlink(t, "Loose", filepath.Join(lib, "A Alias"))
	// The alias comes first even inside one folder.
	symlink(t, "Holes", filepath.Join(lib, "Loose", "Aaa Holes"))
	writeAudio(t, outside, "Book/1.mp3", tags(10, "", "Outside", ""))
	symlink(t, filepath.Join(outside, "Book"), filepath.Join(lib, "Elsewhere"))
	// Links inside linked trees are followed too, once.
	symlink(t, filepath.Join(lib, "Loose"), filepath.Join(outside, "Book", "Back"))

	tl := openTestLib(t, lib, filepath.Join(base, "state"))
	tl.scan(t)
	if got := bookPaths(tl.Index()); !reflect.DeepEqual(got, []string{"Elsewhere", "Loose/Hatchet", "Loose/Holes"}) {
		t.Errorf("books: %q", got)
	}
}
