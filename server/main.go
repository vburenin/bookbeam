// Command bookbeam serves a family audiobook library: it scans a folder of
// audiobooks, streams them to a web app built for the car and phones, and
// keeps everyone's place in every book.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/vburenin/bookbeam/server/internal/auth"
	"github.com/vburenin/bookbeam/server/internal/library"
	"github.com/vburenin/bookbeam/server/internal/server"
	"github.com/vburenin/bookbeam/server/internal/store"
	"github.com/vburenin/bookbeam/server/web"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

// Shutdown budget. Docker sends SIGKILL 10 s after SIGTERM by default, and
// audio downloads in flight never finish on their own, so the whole
// shutdown must fit well inside that: sessions are flushed first, then
// requests get shutdownTimeout to finish and background work (a scan, a
// probe) bgStopTimeout to notice the cancellation.
const (
	shutdownTimeout = 5 * time.Second
	bgStopTimeout   = 3 * time.Second
)

func main() {
	if err := run(os.Args[1:], os.Getenv, os.Stderr); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		fmt.Fprintln(os.Stderr, "bookbeam:", err)
		os.Exit(1)
	}
}

// config is the parsed command line and environment.
type config struct {
	addr      string
	dataDir   string
	stateDir  string
	envUsers  []string // BOOKBEAM_USERS entries
	flagUsers []string // -u values (win over envUsers)
	basePath  string
	// scanInterval is the periodic rescan interval (0 disables it).
	scanInterval time.Duration
	trustProxy   server.ProxyTrust
	ffprobe      bool
	cookieSecure bool
	webDir       string
	logLevel     slog.Level
	logJSON      bool
}

// userList collects repeated -u flags.
type userList []string

func (u *userList) String() string { return fmt.Sprintf("%d user(s)", len(*u)) }

func (u *userList) Set(v string) error {
	*u = append(*u, v)
	return nil
}

// parseConfig reads flags, falling back to environment variables for
// defaults. Users from BOOKBEAM_USERS and -u are merged (-u wins on
// conflicts).
func parseConfig(args []string, getenv func(string) string, out io.Writer) (config, error) {
	var c config
	fset := flag.NewFlagSet("bookbeam", flag.ContinueOnError)
	fset.SetOutput(out)

	envOr := func(key, def string) string {
		if v := strings.TrimSpace(getenv(key)); v != "" {
			return v
		}
		return def
	}
	scanDefault, err := time.ParseDuration(envOr("BOOKBEAM_SCAN_INTERVAL", "30m"))
	if err != nil {
		return c, fmt.Errorf("BOOKBEAM_SCAN_INTERVAL: %w", err)
	}
	var flagUsers userList
	var ffprobe, trustProxy string
	fset.StringVar(&c.addr, "addr", envOr("BOOKBEAM_ADDR", ":8080"), "listen address (env BOOKBEAM_ADDR)")
	fset.StringVar(&c.dataDir, "data", envOr("BOOKBEAM_DATA_DIR", "/data"), "audiobook library root; never written to")
	fset.StringVar(&c.stateDir, "state", envOr("BOOKBEAM_STATE", ""), "state directory (default <data>/.bookbeam; env BOOKBEAM_STATE)")
	fset.Var(&flagUsers, "u", "login as user:password or user:sha256:<hex>; repeatable (env BOOKBEAM_USERS)")
	fset.StringVar(&c.basePath, "base-path", envOr("BOOKBEAM_BASE_PATH", ""), "URL prefix when a reverse proxy does not strip it, e.g. /books (env BOOKBEAM_BASE_PATH)")
	fset.DurationVar(&c.scanInterval, "scan-interval", scanDefault, "periodic library rescan interval; 0 disables (env BOOKBEAM_SCAN_INTERVAL)")
	fset.StringVar(&trustProxy, "trust-proxy", envOr("BOOKBEAM_TRUST_PROXY", "auto"),
		"honour X-Forwarded-For/-Proto/-Prefix: auto (from loopback/private-network peers only), true or false (env BOOKBEAM_TRUST_PROXY)")
	fset.StringVar(&ffprobe, "ffprobe", envOr("BOOKBEAM_FFPROBE", "auto"), "auto: use ffprobe as a fallback if installed; off: never (env BOOKBEAM_FFPROBE)")
	if err := fset.Parse(args); err != nil {
		return c, err
	}
	if fset.NArg() > 0 {
		return c, fmt.Errorf("unexpected arguments: %q", fset.Args())
	}

	switch strings.ToLower(ffprobe) {
	case "auto":
		c.ffprobe = true
	case "off":
		c.ffprobe = false
	default:
		return c, fmt.Errorf("-ffprobe must be auto or off, got %q", ffprobe)
	}
	if c.trustProxy, err = server.ParseProxyTrust(trustProxy); err != nil {
		return c, fmt.Errorf("-trust-proxy / BOOKBEAM_TRUST_PROXY: %w", err)
	}
	c.envUsers = strings.FieldsFunc(getenv("BOOKBEAM_USERS"), func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
	})
	c.flagUsers = flagUsers
	if len(c.envUsers) == 0 && len(c.flagUsers) == 0 {
		return c, errors.New("no users configured: pass -u user:password or set BOOKBEAM_USERS")
	}
	if c.stateDir == "" {
		c.stateDir = filepath.Join(c.dataDir, ".bookbeam")
	}
	c.cookieSecure = getenv("COOKIE_SECURE") == "1"
	c.webDir = strings.TrimSpace(getenv("BOOKBEAM_WEB_DIR"))
	c.logJSON = getenv("LOG_JSON") == "1"
	switch strings.ToLower(strings.TrimSpace(getenv("LOG_LEVEL"))) {
	case "debug":
		c.logLevel = slog.LevelDebug
	case "warn", "warning":
		c.logLevel = slog.LevelWarn
	case "error":
		c.logLevel = slog.LevelError
	default:
		c.logLevel = slog.LevelInfo
	}
	return c, nil
}

// loadUsers parses the configured logins; -u entries win over
// BOOKBEAM_USERS ones for the same name. Errors never echo passwords.
func loadUsers(c config) (*auth.Users, error) {
	env, err := auth.ParseUsers(c.envUsers)
	if err != nil {
		return nil, fmt.Errorf("BOOKBEAM_USERS: %w (entries are separated by spaces, commas or semicolons; "+
			"pass a password containing those with -u instead)", err)
	}
	flags, err := auth.ParseUsers(c.flagUsers)
	if err != nil {
		return nil, fmt.Errorf("-u: %w", err)
	}
	return env.Merge(flags), nil
}

func newLogger(c config, w io.Writer) *slog.Logger {
	opts := &slog.HandlerOptions{Level: c.logLevel}
	if c.logJSON {
		return slog.New(slog.NewJSONHandler(w, opts))
	}
	return slog.New(slog.NewTextHandler(w, opts))
}

// buildVersion returns the -ldflags version, or the VCS revision for dev
// builds.
func buildVersion() string {
	if version != "dev" {
		return version
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return version
	}
	var rev, dirty string
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			if s.Value == "true" {
				dirty = "-dirty"
			}
		}
	}
	if len(rev) > 7 {
		rev = rev[:7]
	}
	if rev == "" {
		return version
	}
	return version + "-" + rev + dirty
}

// webFiles returns the web app: embedded, or BOOKBEAM_WEB_DIR for
// development (served live from disk).
func webFiles(dir string) (fs.FS, bool, error) {
	if dir == "" {
		return web.Public(), false, nil
	}
	st, err := os.Stat(dir)
	if err != nil {
		return nil, false, fmt.Errorf("BOOKBEAM_WEB_DIR: %w", err)
	}
	if !st.IsDir() {
		return nil, false, fmt.Errorf("BOOKBEAM_WEB_DIR: %s is not a directory", dir)
	}
	return os.DirFS(dir), true, nil
}

func run(args []string, getenv func(string) string, stderr io.Writer) error {
	cfg, err := parseConfig(args, getenv, stderr)
	if err != nil {
		return err
	}
	log := newLogger(cfg, os.Stdout)
	slog.SetDefault(log)
	ver := buildVersion()

	users, err := loadUsers(cfg)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(cfg.stateDir, 0o755); err != nil {
		return fmt.Errorf("state directory: %w (use -state to put it somewhere writable)", err)
	}
	webFS, webLive, err := webFiles(cfg.webDir)
	if err != nil {
		return err
	}

	authSvc, err := auth.NewService(auth.Config{
		StateDir:         cfg.stateDir,
		LegacySecretPath: filepath.Join(cfg.dataDir, "session_secret"),
		Users:            users,
		Logger:           log,
	})
	if err != nil {
		return err
	}
	lib, err := library.Open(library.Options{
		Root:     cfg.dataDir,
		StateDir: cfg.stateDir,
		FFprobe:  cfg.ffprobe,
		Logger:   log,
	})
	if err != nil {
		return err
	}
	st, err := store.New(store.Options{
		Dir:       filepath.Join(cfg.stateDir, "users"),
		LegacyDir: filepath.Join(cfg.dataDir, "state"),
		Logger:    log,
	})
	if err != nil {
		return err
	}
	srv := server.New(server.Config{
		Auth:         authSvc,
		Library:      lib,
		Store:        st,
		Web:          webFS,
		WebLive:      webLive,
		BasePath:     cfg.basePath,
		TrustProxy:   cfg.trustProxy,
		CookieSecure: cfg.cookieSecure,
		Version:      ver,
		Logger:       log,
	})

	ln, err := net.Listen("tcp", cfg.addr)
	if err != nil {
		return err
	}
	httpSrv := &http.Server{
		Handler:           srv,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
		// No write timeout: audio downloads and event streams are long-lived.
	}
	httpSrv.RegisterOnShutdown(srv.CloseStreams)

	_, ffprobeErr := exec.LookPath("ffprobe")
	log.Info("BookBeam starting",
		"version", ver, "addr", ln.Addr().String(), "data", cfg.dataDir, "state", cfg.stateDir,
		"users", len(users.Names()), "basePath", cfg.basePath, "trustProxy", cfg.trustProxy.String(),
		"scanInterval", cfg.scanInterval, "ffprobe", cfg.ffprobe && ffprobeErr == nil, "webDir", cfg.webDir)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var bg sync.WaitGroup
	bg.Go(func() { lib.Run(ctx, cfg.scanInterval) })
	bg.Go(func() { authSvc.Run(ctx) })

	serveErr := make(chan error, 1)
	go func() { serveErr <- httpSrv.Serve(ln) }()

	select {
	case <-ctx.Done():
		log.Info("shutting down")
	case err = <-serveErr:
		stop()
	}

	// Save batched session activity before anything that can take time, so
	// it survives even if the container manager loses patience. (Progress
	// and bookmarks are written synchronously and need no flush.)
	if cerr := authSvc.Close(); cerr != nil {
		log.Error("saving sessions", "err", cerr)
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if serr := httpSrv.Shutdown(shutdownCtx); serr != nil {
		log.Warn("http shutdown: closing streams still in flight", "err", serr)
		_ = httpSrv.Close()
	}
	bgDone := make(chan struct{})
	go func() {
		bg.Wait()
		close(bgDone)
	}()
	select {
	case <-bgDone:
	case <-time.After(bgStopTimeout):
		// A probe of a damaged file (or ffprobe) may ignore cancellation;
		// library.json is written atomically, so leaving it is safe.
		log.Warn("background work still running; exiting anyway")
	}
	// Activity recorded while requests drained.
	if cerr := authSvc.Close(); cerr != nil {
		log.Error("saving sessions", "err", cerr)
	}
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	log.Info("stopped")
	return nil
}
