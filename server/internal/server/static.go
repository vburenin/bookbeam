package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// contentSecurityPolicy is sent with HTML. The web app uses no inline
// scripts or event-handler attributes.
const contentSecurityPolicy = "default-src 'self'; img-src 'self' data: blob:; media-src 'self' blob:; " +
	"style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; font-src 'self'; " +
	"manifest-src 'self'; worker-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"

// staticTypes pins Content-Types so they don't depend on the host's MIME
// database (minimal containers have none).
var staticTypes = map[string]string{
	".html":        "text/html; charset=utf-8",
	".js":          "text/javascript; charset=utf-8",
	".mjs":         "text/javascript; charset=utf-8",
	".css":         "text/css; charset=utf-8",
	".json":        "application/json",
	".map":         "application/json",
	".webmanifest": "application/manifest+json",
	".svg":         "image/svg+xml",
	".png":         "image/png",
	".jpg":         "image/jpeg",
	".jpeg":        "image/jpeg",
	".webp":        "image/webp",
	".ico":         "image/x-icon",
	".woff2":       "font/woff2",
	".woff":        "font/woff",
	".txt":         "text/plain; charset=utf-8",
}

func staticType(name string) string {
	ext := strings.ToLower(path.Ext(name))
	if t, ok := staticTypes[ext]; ok {
		return t
	}
	if t := mime.TypeByExtension(ext); t != "" {
		return t
	}
	return "application/octet-stream"
}

type staticFile struct {
	data  []byte
	etag  string
	ctype string
}

// Versioned assets. Everything under assets/ (modules, CSS, fonts) is
// fingerprinted as a whole: index.html is served with its "assets/..."
// references rewritten to "assets-<version>/...", and those URLs are
// cached by browsers for good, so a warm start of the app costs no
// revalidation round trips (they add up to seconds on a car's LTE link).
// The modules import each other relatively, so they inherit the prefix.
// Any change to any asset changes the version, and with it every URL.
// Plain "assets/..." keeps working, revalidated on every use.
const assetsDir = "assets"

// assetRefRE finds asset references in index.html attributes ("assets/x",
// "./assets/x", srcset lists, url(...)).
var assetRefRE = regexp.MustCompile(`(^|[\s"'(=,])(\./)?` + assetsDir + `/`)

// versionAssetRefs points index.html's asset references at version.
func versionAssetRefs(html []byte, version string) []byte {
	return assetRefRE.ReplaceAll(html, []byte("${1}${2}"+assetsDir+"-"+version+"/"))
}

// withVersionedAssets serves "/assets-<version>/x" from "assets/x",
// remembering the requested version for serveStatic's caching decision.
func withVersionedAssets(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if rest, ok := strings.CutPrefix(r.URL.Path, "/"+assetsDir+"-"); ok {
			if ver, sub, ok := strings.Cut(rest, "/"); ok && validAssetVersion(ver) {
				r = r.Clone(context.WithValue(r.Context(), ctxAssetVersion, ver))
				r.URL.Path = "/" + assetsDir + "/" + sub
				r.URL.RawPath = ""
			}
		}
		next.ServeHTTP(w, r)
	})
}

func validAssetVersion(v string) bool {
	if v == "" || len(v) > 64 {
		return false
	}
	for _, c := range []byte(v) {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// staticFiles serves the web app. Embedded files are hashed once; a live
// directory (BOOKBEAM_WEB_DIR, for development) is re-read on every request
// so edits show up on reload.
type staticFiles struct {
	fsys fs.FS
	live bool

	mu    sync.Mutex
	cache map[string]*staticFile

	versionOnce sync.Once
	version     string
}

// assetsVersion fingerprints everything under assets/ ("" when there is
// nothing to version). Embedded files never change, so it is computed
// once; a live directory is re-hashed on every call (every index request).
func (sf *staticFiles) assetsVersion() string {
	if sf.live {
		return hashAssets(sf.fsys)
	}
	sf.versionOnce.Do(func() { sf.version = hashAssets(sf.fsys) })
	return sf.version
}

func hashAssets(fsys fs.FS) string {
	h := sha256.New()
	files := 0
	err := fs.WalkDir(fsys, assetsDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() {
			return err
		}
		data, err := fs.ReadFile(fsys, p)
		if err != nil {
			return err
		}
		fmt.Fprintf(h, "%s\x00%x\n", p, sha256.Sum256(data))
		files++
		return nil
	})
	if err != nil || files == 0 {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))[:12]
}

func (sf *staticFiles) get(name string) (*staticFile, error) {
	if !sf.live {
		sf.mu.Lock()
		f, ok := sf.cache[name]
		sf.mu.Unlock()
		if ok {
			return f, nil
		}
	}
	data, err := fs.ReadFile(sf.fsys, name)
	if err != nil {
		return nil, err
	}
	if name == "index.html" {
		if ver := sf.assetsVersion(); ver != "" {
			data = versionAssetRefs(data, ver)
		}
	}
	sum := sha256.Sum256(data)
	f := &staticFile{data: data, etag: `"` + hex.EncodeToString(sum[:]) + `"`, ctype: staticType(name)}
	if !sf.live {
		sf.mu.Lock()
		sf.cache[name] = f
		sf.mu.Unlock()
	}
	return f, nil
}

// serveStatic writes one web-app file: assets requested under the current
// version are cached for good, everything else is revalidated on use.
func (s *Server) serveStatic(w http.ResponseWriter, r *http.Request, name string) {
	if !fs.ValidPath(name) {
		http.NotFound(w, r)
		return
	}
	f, err := s.static.get(name)
	if err != nil {
		// Missing files, directories and unreadable files are all "not
		// found" to the browser; only the unexpected ones are worth a log.
		if !errors.Is(err, fs.ErrNotExist) {
			s.log.Debug("cannot serve web asset", "name", name, "err", err)
		}
		http.NotFound(w, r)
		return
	}
	h := w.Header()
	h.Set("Content-Type", f.ctype)
	h.Set("Cache-Control", "no-cache")
	if ver, ok := r.Context().Value(ctxAssetVersion).(string); ok && !s.static.live && ver == s.static.assetsVersion() {
		h.Set("Cache-Control", "public, max-age=31536000, immutable")
	}
	h.Set("ETag", f.etag)
	if strings.HasPrefix(f.ctype, "text/html") {
		h.Set("Content-Security-Policy", contentSecurityPolicy)
	}
	if name == "sw.js" {
		h.Set("Service-Worker-Allowed", "./")
	}
	if etagMatches(r.Header.Get("If-None-Match"), f.etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	h.Set("Content-Length", strconv.Itoa(len(f.data)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(f.data)
}

// staticFile returns a handler for one fixed file.
func (s *Server) staticFile(name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) { s.serveStatic(w, r, name) }
}

// staticDir returns a handler for files below dir ("GET /dir/{path...}").
func (s *Server) staticDir(dir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.serveStatic(w, r, dir+"/"+r.PathValue("path"))
	}
}
