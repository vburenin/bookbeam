package fsutil

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWriteFileAtomic(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "nested", "a.json")
	if err := WriteFileAtomic(p, []byte("one"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteFileAtomic(p, []byte("two"), 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil || string(b) != "two" {
		t.Fatalf("content = %q, %v", b, err)
	}
	st, _ := os.Stat(p)
	if st.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v", st.Mode())
	}
	entries, _ := os.ReadDir(filepath.Dir(p))
	if len(entries) != 1 {
		t.Errorf("temporary files left behind: %v", entries)
	}
}

func TestJSONRoundTrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "v.json")
	in := map[string]any{"a": "<b>&", "n": 1.5}
	if err := WriteJSON(p, in, 0o644); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p); string(b) != "{\n  \"a\": \"<b>&\",\n  \"n\": 1.5\n}\n" {
		t.Errorf("encoded = %q", b)
	}
	var out map[string]any
	if err := ReadJSON(p, &out); err != nil || out["a"] != "<b>&" {
		t.Fatalf("ReadJSON = %v, %v", out, err)
	}
	if err := ReadJSON(filepath.Join(t.TempDir(), "missing"), &out); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("missing file: %v", err)
	}
	if err := os.WriteFile(p, []byte("{"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ReadJSON(p, &out); err == nil || errors.Is(err, fs.ErrNotExist) {
		t.Errorf("corrupt file: %v", err)
	}
	if !Exists(p) || Exists(p+".nope") {
		t.Error("Exists")
	}
}

func TestMoveAside(t *testing.T) {
	p := filepath.Join(t.TempDir(), "s.json")
	if err := os.WriteFile(p, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	aside, err := MoveAside(p, time.Unix(1700000000, 0))
	if err != nil || aside != p+".corrupt-1700000000" {
		t.Fatalf("MoveAside = %q, %v", aside, err)
	}
	if Exists(p) || !Exists(aside) {
		t.Fatal("file not moved")
	}
}
