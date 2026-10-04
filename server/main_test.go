package main

import (
	"io"
	"log/slog"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/vburenin/bookbeam/server/internal/server"
)

func envMap(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestParseConfigDefaults(t *testing.T) {
	c, err := parseConfig([]string{"-u", "vlad:pw"}, envMap(nil), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if c.addr != ":8080" || c.dataDir != "/data" || c.stateDir != filepath.Join("/data", ".bookbeam") ||
		c.scanInterval != 30*time.Minute || c.trustProxy != server.TrustProxyAuto || !c.ffprobe || c.basePath != "" ||
		c.cookieSecure || c.logLevel != slog.LevelInfo || c.logJSON {
		t.Fatalf("defaults = %+v", c)
	}
}

func TestParseConfigEnvAndFlags(t *testing.T) {
	env := envMap(map[string]string{
		"BOOKBEAM_ADDR":          ":9000",
		"BOOKBEAM_DATA_DIR":      "/books",
		"BOOKBEAM_STATE":         "/config",
		"BOOKBEAM_USERS":         "mom:a, dad:b;kid:c\nnan:d",
		"BOOKBEAM_BASE_PATH":     "/books",
		"BOOKBEAM_SCAN_INTERVAL": "5m",
		"BOOKBEAM_TRUST_PROXY":   "false",
		"BOOKBEAM_FFPROBE":       "off",
		"COOKIE_SECURE":          "1",
		"LOG_LEVEL":              "debug",
		"LOG_JSON":               "1",
		"BOOKBEAM_WEB_DIR":       "/src/web/public",
	})
	c, err := parseConfig([]string{"-addr", "127.0.0.1:1", "-u", "dad:override", "-scan-interval", "0"}, env, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	want := config{
		addr: "127.0.0.1:1", dataDir: "/books", stateDir: "/config",
		envUsers: []string{"mom:a", "dad:b", "kid:c", "nan:d"}, flagUsers: []string{"dad:override"},
		basePath: "/books", scanInterval: 0, trustProxy: server.TrustProxyNever, ffprobe: false, cookieSecure: true,
		webDir: "/src/web/public", logLevel: slog.LevelDebug, logJSON: true,
	}
	if !reflect.DeepEqual(c, want) {
		t.Fatalf("config:\n got %+v\nwant %+v", c, want)
	}
	users, err := loadUsers(c)
	if err != nil {
		t.Fatal(err)
	}
	if !users.Verify("dad", "override") || users.Verify("dad", "b") || !users.Verify("nan", "d") {
		t.Fatal("-u must win over BOOKBEAM_USERS")
	}
}

func TestParseConfigTrustProxy(t *testing.T) {
	for v, want := range map[string]server.ProxyTrust{
		"auto": server.TrustProxyAuto, "AUTO": server.TrustProxyAuto,
		"true": server.TrustProxyAlways, "1": server.TrustProxyAlways,
		"false": server.TrustProxyNever, "0": server.TrustProxyNever,
	} {
		c, err := parseConfig([]string{"-u", "a:b", "-trust-proxy", v}, envMap(nil), io.Discard)
		if err != nil || c.trustProxy != want {
			t.Errorf("-trust-proxy %s = %v, %v", v, c.trustProxy, err)
		}
	}
}

// User errors must help without leaking passwords into docker logs.
func TestLoadUsersErrors(t *testing.T) {
	c, err := parseConfig(nil, envMap(map[string]string{"BOOKBEAM_USERS": "mom:correct horse battery"}), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	_, err = loadUsers(c)
	if err == nil || strings.Contains(err.Error(), "horse") || strings.Contains(err.Error(), "correct") ||
		!strings.Contains(err.Error(), "-u") || !strings.Contains(err.Error(), "#2") {
		t.Fatalf("loadUsers = %v", err)
	}
	c, _ = parseConfig([]string{"-u", "dad"}, envMap(nil), io.Discard)
	if _, err := loadUsers(c); err == nil || !strings.HasPrefix(err.Error(), "-u:") {
		t.Fatalf("-u error = %v", err)
	}
}

func TestParseConfigErrors(t *testing.T) {
	cases := []struct {
		args []string
		env  map[string]string
	}{
		{nil, nil}, // no users
		{[]string{"-u", "a:b", "-ffprobe", "maybe"}, nil},
		{[]string{"-u", "a:b", "extra"}, nil},
		{[]string{"-u", "a:b"}, map[string]string{"BOOKBEAM_SCAN_INTERVAL": "soon"}},
		{[]string{"-u", "a:b"}, map[string]string{"BOOKBEAM_TRUST_PROXY": "perhaps"}},
	}
	for _, c := range cases {
		if _, err := parseConfig(c.args, envMap(c.env), io.Discard); err == nil {
			t.Errorf("parseConfig(%q, %v) accepted", c.args, c.env)
		}
	}
}
