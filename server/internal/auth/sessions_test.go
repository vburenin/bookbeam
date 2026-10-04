package auth

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A damaged sessions.json must not keep the server from starting (under
// `restart: unless-stopped` that is a crash loop with nobody listening).
func TestDamagedSessionRegistry(t *testing.T) {
	setup := func(t *testing.T) (dir string, clk *fakeClock, kept, last string) {
		dir = t.TempDir()
		clk = newClock()
		s := newTestService(t, dir, "", clk)
		var err error
		if kept, _, err = s.Login("vlad", "pw", "", "", ""); err != nil {
			t.Fatal(err)
		}
		// The second write leaves the first state as the backup.
		if last, _, err = s.Login("kid", "pw2", "", "", ""); err != nil {
			t.Fatal(err)
		}
		return dir, clk, kept, last
	}
	asides := func(t *testing.T, dir, pattern string) int {
		m, _ := filepath.Glob(filepath.Join(dir, pattern))
		return len(m)
	}

	for _, damage := range []struct {
		name string
		data []byte
	}{
		{"empty", nil},
		{"truncated", []byte(`{"abc": {"user": "vl`)},
	} {
		t.Run("backup restores "+damage.name, func(t *testing.T) {
			dir, clk, kept, last := setup(t)
			if err := os.WriteFile(filepath.Join(dir, "sessions.json"), damage.data, 0o600); err != nil {
				t.Fatal(err)
			}
			s := newTestService(t, dir, "", clk)
			if _, err := s.Authenticate(kept, "", ""); err != nil {
				t.Fatalf("session from the backup lost: %v", err)
			}
			if n := asides(t, dir, "sessions.json.corrupt-*"); n != 1 {
				t.Fatalf("%d damaged files kept, want 1", n)
			}
			// The newest session was not in the backup; its validly signed
			// token is adopted again on use, so the device stays signed in.
			if _, err := s.Authenticate(last, "", ""); err != nil {
				t.Fatalf("newest session: %v", err)
			}
			// sessions.json was rewritten and is readable again.
			if _, _, err := readRegistry(filepath.Join(dir, "sessions.json")); err != nil {
				t.Fatal(err)
			}
		})
	}

	t.Run("both damaged starts empty", func(t *testing.T) {
		dir, clk, kept, _ := setup(t)
		for _, name := range []string{"sessions.json", "sessions.json.bak"} {
			if err := os.WriteFile(filepath.Join(dir, name), []byte("{"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		var logs bytes.Buffer
		s, err := NewService(Config{StateDir: dir, Users: mustUsers(t, "vlad:pw", "kid:pw2"), Now: clk.Now, Logger: textLogger(&logs)})
		if err != nil {
			t.Fatal(err)
		}
		if n := asides(t, dir, "sessions.json*.corrupt-*"); n != 2 {
			t.Fatalf("%d damaged files kept, want 2", n)
		}
		if !strings.Contains(logs.String(), "delete secret.key") {
			t.Errorf("log does not explain how to sign everyone out:\n%s", logs.String())
		}
		// The signing key was not rotated: devices stay signed in.
		if _, err := s.Authenticate(kept, "", ""); err != nil {
			t.Fatalf("device signed out: %v", err)
		}
	})

	t.Run("missing file restored from backup", func(t *testing.T) {
		dir, clk, kept, _ := setup(t)
		if err := os.Remove(filepath.Join(dir, "sessions.json")); err != nil {
			t.Fatal(err)
		}
		s := newTestService(t, dir, "", clk)
		if list := s.Sessions().List("vlad"); len(list) != 1 {
			t.Fatalf("sessions = %+v", list)
		}
		if _, err := s.Authenticate(kept, "", ""); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("unreadable file is an error", func(t *testing.T) {
		dir, clk, _, _ := setup(t)
		p := filepath.Join(dir, "sessions.json")
		if err := os.Remove(p); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(p, 0o700); err != nil { // reading a directory fails with EISDIR
			t.Fatal(err)
		}
		_, err := NewService(Config{StateDir: dir, Users: mustUsers(t, "vlad:pw"), Now: clk.Now})
		if err == nil || errors.Is(err, errCorrupt) {
			t.Fatalf("NewService = %v, want an I/O error", err)
		}
	})
}

// Every write keeps the previous version as the backup.
func TestSessionBackupKeepsPreviousVersion(t *testing.T) {
	dir := t.TempDir()
	clk := newClock()
	s := newTestService(t, dir, "", clk)
	if _, _, err := s.Login("vlad", "pw", "", "", ""); err != nil {
		t.Fatal(err)
	}
	cur, _ := os.ReadFile(filepath.Join(dir, "sessions.json"))
	if _, _, err := s.Login("kid", "pw2", "", "", ""); err != nil {
		t.Fatal(err)
	}
	if bak, _ := os.ReadFile(filepath.Join(dir, "sessions.json.bak")); !bytes.Equal(bak, cur) {
		t.Fatalf("backup = %s\nwant the previous version %s", bak, cur)
	}
}

func textLogger(w io.Writer) *slog.Logger { return slog.New(slog.NewTextHandler(w, nil)) }
