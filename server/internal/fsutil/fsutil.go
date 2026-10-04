// Package fsutil holds small file-system helpers shared by BookBeam's
// persistence layers: crash-safe atomic writes and JSON load/save.
package fsutil

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// WriteFileAtomic writes data to path so that readers (and a crash at any
// moment) observe either the old content or the new content, never a mix:
// the bytes go to a temporary file in the same directory, are fsynced, and
// the file is renamed over the target. Parent directories are created.
func WriteFileAtomic(path string, data []byte, perm fs.FileMode) (err error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmp.Name())
		}
	}()
	if _, err = tmp.Write(data); err != nil {
		return err
	}
	if err = tmp.Chmod(perm); err != nil {
		return err
	}
	if err = tmp.Sync(); err != nil {
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// MarshalJSON encodes v the way WriteJSON stores it: indented (for humans
// inspecting backups), without HTML escaping, newline-terminated.
func MarshalJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// WriteJSON marshals v with MarshalJSON and writes it atomically to path.
func WriteJSON(path string, v any, perm fs.FileMode) error {
	b, err := MarshalJSON(v)
	if err != nil {
		return fmt.Errorf("encode %s: %w", filepath.Base(path), err)
	}
	return WriteFileAtomic(path, b, perm)
}

// MoveAside renames a damaged file to "<path>.corrupt-<unix time>" so it is
// kept for inspection but no longer read, and returns the new name.
func MoveAside(path string, now time.Time) (string, error) {
	aside := fmt.Sprintf("%s.corrupt-%d", path, now.Unix())
	if err := os.Rename(path, aside); err != nil {
		return "", err
	}
	return aside, nil
}

// ReadJSON decodes the JSON file at path into v. It returns an error
// satisfying errors.Is(err, fs.ErrNotExist) when the file does not exist.
func ReadJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, v); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	return nil
}

// Exists reports whether path exists (any file type). Errors other than
// "not exist" are reported as existing so callers never clobber files they
// could not inspect.
func Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil || !errors.Is(err, fs.ErrNotExist)
}
