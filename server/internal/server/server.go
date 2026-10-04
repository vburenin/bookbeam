// Package server is BookBeam's HTTP layer: routing, middleware, the JSON
// API, media streaming, Server-Sent Events and the embedded web app.
package server

import (
	"errors"
	"io/fs"
	"log/slog"
	"net/http"

	"github.com/vburenin/bookbeam/server/internal/auth"
	"github.com/vburenin/bookbeam/server/internal/library"
	"github.com/vburenin/bookbeam/server/internal/store"
)

// Config wires the server to its collaborators.
type Config struct {
	Auth    *auth.Service
	Library *library.Library
	Store   *store.Store
	// Web is the web app's file tree (index.html, sw.js, assets/, ...).
	Web fs.FS
	// WebLive disables asset caching (files served from a dev directory).
	WebLive bool
	// BasePath is the URL prefix used when a proxy does not strip it.
	BasePath string
	// TrustProxy says when X-Forwarded-For/-Proto/-Prefix and Forwarded are
	// honoured (zero value: from loopback/private-network peers only).
	TrustProxy ProxyTrust
	// CookieSecure forces the Secure cookie attribute.
	CookieSecure bool
	// Version is reported by api/me.
	Version string
	Logger  *slog.Logger
}

// Server handles HTTP requests. Create it with New.
type Server struct {
	auth    *auth.Service
	lib     *library.Library
	store   *store.Store
	static  *staticFiles
	hub     *hub
	log     *slog.Logger
	handler http.Handler

	basePath     string
	trustProxy   ProxyTrust
	cookieSecure bool
	version      string
}

// New builds the server and subscribes it to library scan results.
func New(cfg Config) *Server {
	log := cfg.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	s := &Server{
		auth:         cfg.Auth,
		lib:          cfg.Library,
		store:        cfg.Store,
		static:       &staticFiles{fsys: cfg.Web, live: cfg.WebLive, cache: map[string]*staticFile{}},
		hub:          newHub(),
		log:          log,
		basePath:     normalizePrefix(cfg.BasePath),
		trustProxy:   cfg.TrustProxy,
		cookieSecure: cfg.CookieSecure,
		version:      cfg.Version,
	}
	mux := http.NewServeMux()
	s.routes(mux)
	s.handler = s.withLogging(withSecurityHeaders(s.withPrefix(withVersionedAssets(withCSRF(withGzip(mux))))))
	s.lib.Subscribe(s.onScan)
	s.store.Subscribe(s.publishStoreChanges)
	return s
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.handler.ServeHTTP(w, r) }

// CloseStreams ends all event streams; call it when shutting down so
// http.Server.Shutdown does not wait for long-lived connections.
func (s *Server) CloseStreams() { s.hub.close() }

func (s *Server) routes(mux *http.ServeMux) {
	// Web app shell and assets (no auth: the app decides what to show).
	mux.HandleFunc("GET /{$}", s.staticFile("index.html"))
	mux.HandleFunc("GET /index.html", s.staticFile("index.html"))
	mux.HandleFunc("GET /sw.js", s.staticFile("sw.js"))
	mux.HandleFunc("GET /manifest.webmanifest", s.staticFile("manifest.webmanifest"))
	mux.HandleFunc("GET /favicon.ico", s.staticFile("favicon.ico"))
	mux.HandleFunc("GET /assets/{path...}", s.staticDir("assets"))
	mux.HandleFunc("GET /icons/{path...}", s.staticDir("icons"))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok"))
	})

	// Sign-in.
	mux.HandleFunc("GET /login", func(w http.ResponseWriter, _ *http.Request) { redirectRelative(w, "./") })
	mux.HandleFunc("POST /login", s.handleLogin)
	mux.HandleFunc("GET /pair-qr.svg", s.handlePairQR)
	mux.HandleFunc("POST /api/pair/start", s.handlePairStart)
	mux.HandleFunc("POST /api/pair/poll", s.handlePairPoll)

	// Unknown API paths get a JSON 404 rather than the plain-text default.
	mux.HandleFunc("/api/", func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, http.StatusNotFound, "not found")
	})

	authed := map[string]authedHandler{
		"POST /api/logout":                 s.handleLogout,
		"GET /api/me":                      s.handleMe,
		"GET /api/device/accounts":         s.handleDeviceAccounts,
		"POST /api/device/switch":          s.handleDeviceSwitch,
		"GET /api/pair/{code}":             s.handlePairInfo,
		"POST /api/pair/{code}/approve":    s.handlePairApprove,
		"POST /api/pair/{code}/deny":       s.handlePairDeny,
		"GET /api/sessions":                s.handleSessions,
		"PATCH /api/sessions/{id}":         s.handleSessionRename,
		"DELETE /api/sessions/{id}":        s.handleSessionRevoke,
		"POST /api/sessions/revoke-others": s.handleRevokeOthers,

		"GET /api/library":                        s.handleLibrary,
		"POST /api/library/rescan":                s.handleRescan,
		"GET /api/books/{id}":                     s.handleBook,
		"GET /api/books/{id}/cover":               s.handleCover,
		"GET /api/books/{id}/tracks/{n}/audio":    s.handleAudio,
		"POST /api/books/{id}/bookmarks":          s.handleBookmarkAdd,
		"PATCH /api/books/{id}/bookmarks/{bmId}":  s.handleBookmarkUpdate,
		"DELETE /api/books/{id}/bookmarks/{bmId}": s.handleBookmarkDelete,

		"GET /api/state":            s.handleState,
		"PUT /api/progress/{id}":    s.handleProgressPut,
		"PATCH /api/progress/{id}":  s.handleProgressPatch,
		"DELETE /api/progress/{id}": s.handleProgressDelete,
		"PATCH /api/settings":       s.handleSettings,
		"GET /api/stats":            s.handleStats,
		"GET /api/events":           s.handleEvents,
	}
	for pattern, h := range authed {
		mux.Handle(pattern, s.requireAuth(h))
	}
}

// onScan reacts to library scans: brings loaded users' data up to date
// with the new index (legacy migrations waiting for it, places re-linked to
// moved files; see publishStoreChanges) and tells clients about library
// changes.
func (s *Server) onScan(ev library.ScanEvent) {
	s.store.Reconcile(s.lib.Index())
	if ev.Changed || ev.Manual {
		e := libraryEvent{Version: ev.Version, Scanning: s.lib.Scanning()}
		if ev.Manual && errors.Is(ev.Err, library.ErrLibraryEmpty) {
			e.Refused = "empty"
		}
		s.hub.publishAll("library", e)
	}
}

// publishStoreChanges forwards changes the store made on its own to the
// user's open streams (all of them: no client caused these).
func (s *Server) publishStoreChanges(user string, changes []store.Change) {
	for _, c := range changes {
		switch c.Kind {
		case store.ChangeProgress:
			s.hub.publish(user, "", "progress", progressEvent{BookID: c.BookID, Progress: c.Progress, MovedTo: c.MovedTo})
		case store.ChangeBookmarks:
			bms := c.Bookmarks
			if bms == nil {
				bms = []store.Bookmark{}
			}
			s.hub.publish(user, "", "bookmarks", bookmarksEvent{BookID: c.BookID, Bookmarks: bms})
		}
	}
}
