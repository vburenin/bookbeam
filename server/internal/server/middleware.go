package server

import (
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"path"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"
)

type ctxKey int

const (
	ctxPrefix ctxKey = iota
	ctxLogInfo
	ctxSessionToken
	ctxAssetVersion
)

// ProxyTrust says when proxy headers (X-Forwarded-For/-Proto/-Prefix,
// X-Real-IP, Forwarded) are believed. Believing them from anyone would let
// a client pick its own IP (dodging the per-IP login limit) and prefix.
type ProxyTrust int

const (
	// TrustProxyAuto believes them only from loopback and private-network
	// peers (RFC 1918, unique-local and link-local addresses): a reverse
	// proxy on the same host, in Docker or on the LAN.
	TrustProxyAuto ProxyTrust = iota
	// TrustProxyAlways believes them from every peer.
	TrustProxyAlways
	// TrustProxyNever ignores them.
	TrustProxyNever
)

// ParseProxyTrust parses "auto" or a boolean ("true"/"false", "1"/"0", ...).
func ParseProxyTrust(v string) (ProxyTrust, error) {
	if strings.EqualFold(strings.TrimSpace(v), "auto") {
		return TrustProxyAuto, nil
	}
	b, err := strconv.ParseBool(strings.TrimSpace(v))
	if err != nil {
		return TrustProxyAuto, fmt.Errorf("want auto, true or false, got %q", v)
	}
	if b {
		return TrustProxyAlways, nil
	}
	return TrustProxyNever, nil
}

func (p ProxyTrust) String() string {
	switch p {
	case TrustProxyAlways:
		return "true"
	case TrustProxyNever:
		return "false"
	default:
		return "auto"
	}
}

// trustsProxy reports whether r's proxy headers are believed.
func (s *Server) trustsProxy(r *http.Request) bool {
	switch s.trustProxy {
	case TrustProxyAlways:
		return true
	case TrustProxyNever:
		return false
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	ip = ip.Unmap()
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
}

// sessionToken returns the cookie value that authenticated r (set by
// requireAuth).
func sessionToken(r *http.Request) string {
	t, _ := r.Context().Value(ctxSessionToken).(string)
	return t
}

// logInfo lets inner handlers annotate the access log line.
type logInfo struct{ user string }

func setLogUser(r *http.Request, user string) {
	if li, ok := r.Context().Value(ctxLogInfo).(*logInfo); ok {
		li.user = user
	}
}

// prefixOf returns the effective URL prefix ("" or "/x/y") of a request.
func prefixOf(r *http.Request) string {
	p, _ := r.Context().Value(ctxPrefix).(string)
	return p
}

// statusRecorder captures the status and size of a response.
type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (s *statusRecorder) WriteHeader(code int) {
	if s.status == 0 {
		s.status = code
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	n, err := s.ResponseWriter.Write(b)
	s.bytes += int64(n)
	return n, err
}

// ReadFrom keeps sendfile(2) available for audio streaming.
func (s *statusRecorder) ReadFrom(src io.Reader) (int64, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	var (
		n   int64
		err error
	)
	if rf, ok := s.ResponseWriter.(io.ReaderFrom); ok {
		n, err = rf.ReadFrom(src)
	} else {
		n, err = io.Copy(writerOnly{s.ResponseWriter}, src)
	}
	s.bytes += n
	return n, err
}

func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// writerOnly hides any ReadFrom method to avoid recursion in io.Copy.
type writerOnly struct{ io.Writer }

// withLogging writes one access-log line per request and recovers panics.
func (s *Server) withLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		li := &logInfo{}
		rec := &statusRecorder{ResponseWriter: w}
		r = r.WithContext(context.WithValue(r.Context(), ctxLogInfo, li))
		origPath := r.URL.Path
		defer func() {
			if p := recover(); p != nil {
				if p == http.ErrAbortHandler {
					panic(p)
				}
				s.log.Error("panic serving request", "path", origPath, "panic", p, "stack", string(debug.Stack()))
				if rec.status == 0 {
					writeError(rec, http.StatusInternalServerError, "internal error")
				}
			}
			level := slog.LevelInfo
			switch {
			case rec.status >= http.StatusInternalServerError:
				level = slog.LevelError
			case origPath == "/healthz":
				level = slog.LevelDebug
			}
			s.log.Log(r.Context(), level, "http",
				"method", r.Method, "path", origPath, "status", rec.status, "bytes", rec.bytes,
				"dur", time.Since(start).Round(time.Microsecond), "user", li.user, "ip", s.clientIP(r))
		}()
		next.ServeHTTP(rec, r)
	})
}

// withSecurityHeaders sets headers every response carries.
func withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "same-origin")
		h.Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

// withPrefix determines the effective URL prefix, which cookies and
// redirects are scoped to, and strips it from the request path when the
// proxy forwarded it unstripped:
//   - X-Forwarded-Prefix from a trusted proxy: a stripping proxy, so the
//     browser's URL carries the prefix although the request path does not.
//   - -base-path: only when the request path carries it. The same server
//     is often also reached directly (the LAN URL, without the proxy); the
//     app then lives at "/", and a cookie scoped to the prefix would never
//     be sent back (a sign-in loop).
func (s *Server) withPrefix(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		prefix, forwarded := s.basePath, false
		if s.trustsProxy(r) {
			if fp := r.Header.Get("X-Forwarded-Prefix"); fp != "" {
				first, _, _ := strings.Cut(fp, ",")
				prefix, forwarded = normalizePrefix(first), true
			}
		}
		if prefix != "" {
			switch p := r.URL.Path; {
			case p == prefix:
				// "/books" -> "books/" (relative, resolves to "/books/").
				redirectRelative(w, path.Base(prefix)+"/")
				return
			case strings.HasPrefix(p, prefix+"/"):
				r = r.Clone(context.WithValue(r.Context(), ctxPrefix, prefix))
				r.URL.Path = p[len(prefix):]
				if strings.HasPrefix(r.URL.RawPath, prefix+"/") {
					r.URL.RawPath = r.URL.RawPath[len(prefix):]
				} else {
					r.URL.RawPath = ""
				}
				next.ServeHTTP(w, r)
				return
			case !forwarded:
				prefix = "" // reached without the -base-path prefix
			}
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxPrefix, prefix)))
	})
}

// normalizePrefix turns " /books/ " into "/books" and "/" into "".
func normalizePrefix(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	p = path.Clean("/" + p)
	if p == "/" {
		return ""
	}
	return p
}

// csrfExempt lists non-GET API routes callable without the X-BookBeam
// header (unauthenticated pairing endpoints).
var csrfExempt = map[string]bool{
	"/api/pair/start": true,
	"/api/pair/poll":  true,
}

// withCSRF requires "X-BookBeam: 1" on state-changing API requests. A
// cross-site form or simple request cannot set custom headers.
func withCSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
		default:
			if strings.HasPrefix(r.URL.Path, "/api/") && !csrfExempt[r.URL.Path] && r.Header.Get("X-BookBeam") != "1" {
				writeError(w, http.StatusForbidden, "missing X-BookBeam header")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

var gzipPool = sync.Pool{New: func() any { return gzip.NewWriter(io.Discard) }}

// withGzip compresses textual responses for clients that accept gzip.
// Audio, images, ranges and pre-encoded bodies pass through untouched.
func withGzip(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead || !acceptsGzip(r.Header.Get("Accept-Encoding")) {
			next.ServeHTTP(w, r)
			return
		}
		gw := &gzipWriter{ResponseWriter: w}
		defer gw.finish()
		next.ServeHTTP(gw, r)
	})
}

// acceptsGzip parses Accept-Encoding, honouring an explicit "gzip;q=0".
func acceptsGzip(ae string) bool {
	for _, part := range strings.Split(ae, ",") {
		coding, params, _ := strings.Cut(strings.TrimSpace(part), ";")
		if !strings.EqualFold(strings.TrimSpace(coding), "gzip") {
			continue
		}
		for _, param := range strings.Split(params, ";") {
			if k, v, ok := strings.Cut(strings.TrimSpace(param), "="); ok && strings.EqualFold(k, "q") {
				q, err := strconv.ParseFloat(v, 64)
				return err == nil && q > 0
			}
		}
		return true
	}
	return false
}

// compressible reports whether a Content-Type is worth gzipping.
func compressible(ct string) bool {
	mt, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return false
	}
	switch {
	case mt == "text/html", mt == "text/css", mt == "text/javascript",
		mt == "application/javascript", mt == "application/json", mt == "image/svg+xml":
		return true
	case strings.HasSuffix(mt, "+json"):
		return true
	}
	return false
}

type gzipWriter struct {
	http.ResponseWriter
	gz       *gzip.Writer
	decided  bool
	compress bool
}

func (g *gzipWriter) decide(code int) {
	g.decided = true
	h := g.Header()
	if code < http.StatusOK || code == http.StatusNoContent || code == http.StatusPartialContent ||
		code == http.StatusNotModified || h.Get("Content-Encoding") != "" || h.Get("Content-Range") != "" ||
		!compressible(h.Get("Content-Type")) {
		return
	}
	h.Del("Content-Length")
	h.Set("Content-Encoding", "gzip")
	h.Add("Vary", "Accept-Encoding")
	g.gz = gzipPool.Get().(*gzip.Writer)
	g.gz.Reset(g.ResponseWriter)
	g.compress = true
}

func (g *gzipWriter) WriteHeader(code int) {
	if !g.decided {
		g.decide(code)
	}
	g.ResponseWriter.WriteHeader(code)
}

func (g *gzipWriter) Write(b []byte) (int, error) {
	if !g.decided {
		if g.Header().Get("Content-Type") == "" {
			g.Header().Set("Content-Type", http.DetectContentType(b))
		}
		g.WriteHeader(http.StatusOK)
	}
	if g.compress {
		return g.gz.Write(b)
	}
	return g.ResponseWriter.Write(b)
}

func (g *gzipWriter) ReadFrom(src io.Reader) (int64, error) {
	if !g.decided {
		g.WriteHeader(http.StatusOK)
	}
	if g.compress {
		return io.Copy(g.gz, src)
	}
	return io.Copy(g.ResponseWriter, src)
}

func (g *gzipWriter) Flush() {
	if g.compress {
		_ = g.gz.Flush()
	}
	if f, ok := g.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (g *gzipWriter) Unwrap() http.ResponseWriter { return g.ResponseWriter }

func (g *gzipWriter) finish() {
	if g.compress {
		_ = g.gz.Close()
		g.gz.Reset(io.Discard)
		gzipPool.Put(g.gz)
	}
}

// clientIP returns the caller's address, honouring proxy headers when the
// proxy is trusted.
func (s *Server) clientIP(r *http.Request) string {
	ip := ""
	if s.trustsProxy(r) {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			first, _, _ := strings.Cut(xff, ",")
			ip = strings.TrimSpace(first)
		}
		if ip == "" {
			ip = strings.TrimSpace(r.Header.Get("X-Real-IP"))
		}
	}
	if ip == "" {
		if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
			ip = host
		} else {
			ip = r.RemoteAddr
		}
	}
	if len(ip) > 64 {
		ip = ip[:64]
	}
	return ip
}

// isHTTPS reports whether the client connection is (or is proxied as) TLS.
func (s *Server) isHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	if !s.trustsProxy(r) {
		return false
	}
	if proto, _, _ := strings.Cut(r.Header.Get("X-Forwarded-Proto"), ","); strings.EqualFold(strings.TrimSpace(proto), "https") {
		return true
	}
	// RFC 7239: Forwarded: for=192.0.2.60;proto=https;by=203.0.113.43
	for _, part := range strings.FieldsFunc(strings.ToLower(r.Header.Get("Forwarded")), func(c rune) bool { return c == ';' || c == ',' }) {
		if k, v, ok := strings.Cut(strings.TrimSpace(part), "="); ok && k == "proto" && strings.Trim(v, `"`) == "https" {
			return true
		}
	}
	return false
}
