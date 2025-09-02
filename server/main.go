package main

import (
    "crypto/hmac"
    "crypto/rand"
    "crypto/sha256"
    "encoding/hex"
    "encoding/json"
    "errors"
    "flag"
    "fmt"
    "io"
    "log"
    "net/http"
    neturl "net/url"
    "os"
    "path/filepath"
    "sort"
    "strconv"
    "strings"
    "sync"
    "time"

    // Structured HTTP logging
    "github.com/rs/zerolog"
    "github.com/rs/zerolog/hlog"
)

// ---------------- CLI flags ----------------

type usersFlag struct{ pairs [][2]string }

func (u *usersFlag) String() string {
    arr := make([]string, 0, len(u.pairs))
    for _, p := range u.pairs {
        arr = append(arr, p[0]+":****")
    }
    return strings.Join(arr, ", ")
}

func (u *usersFlag) Set(v string) error {
    i := strings.IndexByte(v, ':')
    if i <= 0 || i == len(v)-1 {
        return fmt.Errorf("-u must be in form user:pass, got %q", v)
    }
    user := v[:i]
    pass := v[i+1:]
    u.pairs = append(u.pairs, [2]string{user, pass})
    return nil
}

// ---------------- Types ----------------

type TreeNode struct {
    Name     string     `json:"name"`
    Type     string     `json:"type"` // "directory" or "file"
    Children []TreeNode `json:"children,omitempty"`
    URL      string     `json:"url,omitempty"`
}

// ---------------- Globals ----------------

var (
    addrFlag   = flag.String("addr", ":8080", "listen address")
    dataDir    = flag.String("data", "/data", "data directory mount")
    users      usersFlag

    userMapMu sync.RWMutex
    userMap   = map[string]string{} // username->password

    cacheMu      sync.RWMutex
    cachedTree   *TreeNode
    cacheModTime time.Time

    stateMu sync.Mutex

    sigMu   sync.RWMutex
    lastSig string

    // Playback lease (single active player per user)
    leaseMu     sync.Mutex
    leases      = map[string]*Lease{}
    subscribers = map[string]map[chan string]struct{}{}

    // Optional external UI directory inside container (set via BOOKBEAM_UI_DIR or BOOKBEAM_UI)
    uiDir string

    // Verbose logging toggle
    verbose = strings.TrimSpace(os.Getenv("LOG_VERBOSE")) == "1"
)

func main() {
    flag.Var(&users, "u", "user:pass pair (repeatable)")
    flag.Parse()

    // Load users from env BOOKBEAM_USERS as fallback or supplement
    loadUsersFromEnv(&users)
    if len(users.pairs) == 0 {
        log.Println("WARNING: no users configured (flags or BOOKBEAM_USERS); the server will refuse all logins.")
    }
    for _, p := range users.pairs {
        userMap[p[0]] = p[1]
    }

    if err := os.MkdirAll(*dataDir, 0o755); err != nil {
        log.Fatalf("creating data dir: %v", err)
    }

    // Optional external UI directory
    uiDir = strings.TrimSpace(os.Getenv("BOOKBEAM_UI_DIR"))
    if uiDir == "" {
        uiDir = strings.TrimSpace(os.Getenv("BOOKBEAM_UI"))
    }

    // Load or build index
    if err := loadOrInitIndex(); err != nil {
        log.Fatalf("index init: %v", err)
    }
    // Start hourly reindex scheduler (efficient signature-based check)
    go startIndexScheduler()

    mux := http.NewServeMux()

    // Auth endpoints
    mux.HandleFunc("/login", handleLogin)
    mux.HandleFunc("/logout", handleLogout)

    // Public health
    mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK); _, _ = w.Write([]byte("ok")) })

    // Protected API
    mux.Handle("/api/me", requireAuth(http.HandlerFunc(handleMe)))
    mux.Handle("/api/state", requireAuth(http.HandlerFunc(handleState)))
    mux.Handle("/api/books", requireAuth(http.HandlerFunc(handleBooks)))
    // Playback lease endpoints
    mux.Handle("/api/lease/acquire", requireAuth(http.HandlerFunc(handleLeaseAcquire)))
    mux.Handle("/api/lease/heartbeat", requireAuth(http.HandlerFunc(handleLeaseHeartbeat)))
    mux.Handle("/api/lease/release", requireAuth(http.HandlerFunc(handleLeaseRelease)))
    mux.Handle("/api/lease/stream", requireAuth(http.HandlerFunc(handleLeaseStream)))
    mux.Handle("/api/lease/current", requireAuth(http.HandlerFunc(handleLeaseCurrent)))

    // Serve cached audiobooks.json under auth as well
    mux.Handle("/audiobooks.json", requireAuth(http.HandlerFunc(handleAudiobooksJSON)))

    // Static helper JS
    mux.Handle("/static/mirror.js", requireAuth(http.HandlerFunc(serveMirrorJS)))
    mux.Handle("/static/solo.js", requireAuth(http.HandlerFunc(serveSoloJS)))

    // Media streaming from /data
    mux.Handle("/media/", requireAuth(http.HandlerFunc(handleMedia)))

    // Static favicon (served from web/static/favicon.ico)
    mux.Handle("/static/favicon.ico", requireAuth(http.HandlerFunc(serveStaticFavicon)))

    // Also allow direct URLs like /Expanse/... by mapping to /data path.
    mux.Handle("/", requireAuth(http.HandlerFunc(handleRootOrData)))

    // Build logging middleware stack
    handler := withRequestLogging(mux)

    log.Printf("listening on %s, data dir %s", *addrFlag, *dataDir)
    if err := http.ListenAndServe(*addrFlag, handler); err != nil {
        log.Fatalf("server error: %v", err)
    }
}

func loadUsersFromEnv(u *usersFlag) {
    raw := os.Getenv("BOOKBEAM_USERS")
    if strings.TrimSpace(raw) == "" {
        return
    }
    // Split on commas/whitespace/semicolons
    f := func(r rune) bool { return r == ',' || r == ';' || r == ' ' || r == '\n' || r == '\t' }
    parts := strings.FieldsFunc(raw, f)
    for _, p := range parts {
        if p == "" { continue }
        _ = u.Set(p)
    }
}

// ---------------- Middleware & helpers ----------------

// withRequestLogging adds structured request logging using zerolog's hlog middleware.
func withRequestLogging(next http.Handler) http.Handler {
    // Default to human-friendly console logs. Set LOG_JSON=1 for JSON.
    var zl zerolog.Logger
    if strings.TrimSpace(os.Getenv("LOG_JSON")) == "1" {
        zerolog.TimeFieldFormat = time.RFC3339
        zl = zerolog.New(os.Stdout).With().Timestamp().Logger()
    } else {
        cw := zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339}
        zl = zerolog.New(cw).With().Timestamp().Logger()
    }
    switch strings.ToLower(strings.TrimSpace(os.Getenv("LOG_LEVEL"))) {
    case "debug":
        zerolog.SetGlobalLevel(zerolog.DebugLevel)
    case "warn":
        zerolog.SetGlobalLevel(zerolog.WarnLevel)
    case "error":
        zerolog.SetGlobalLevel(zerolog.ErrorLevel)
    default:
        zerolog.SetGlobalLevel(zerolog.InfoLevel)
    }

    h := hlog.NewHandler(zl)(next)
    // Attach common fields
    h = hlog.RequestIDHandler("request_id", "X-Request-ID")(h)
    h = hlog.RemoteAddrHandler("ip")(h)
    h = hlog.UserAgentHandler("user_agent")(h)
    h = hlog.RefererHandler("referer")(h)
    // Access log
    h = hlog.AccessHandler(func(r *http.Request, status, size int, duration time.Duration) {
        // Prefer X-Forwarded-For when present
        ip := clientIPFromRequest(r)
        user, _ := currentUser(r)
        // Human-friendly single-line summary (still via zerolog so ConsoleWriter formats nicely)
        zl.Info().Msgf("%s %s %d %dB %s ip=%s user=%s ua=%s", r.Method, r.URL.Path, status, size, duration, ip, user, r.UserAgent())
    })(h)
    return h
}

func clientIPFromRequest(r *http.Request) string {
    // X-Forwarded-For may contain a list; take the first
    if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
        if i := strings.IndexByte(xff, ','); i > 0 { return strings.TrimSpace(xff[:i]) }
        return strings.TrimSpace(xff)
    }
    if rip := r.Header.Get("X-Real-IP"); rip != "" { return strings.TrimSpace(rip) }
    host, _, err := netSplitHostPort(r.RemoteAddr)
    if err == nil && host != "" { return host }
    return r.RemoteAddr
}

// net.SplitHostPort but tolerant of missing port
func netSplitHostPort(hostport string) (host, port string, err error) {
    if i := strings.LastIndex(hostport, ":"); i != -1 {
        return hostport[:i], hostport[i+1:], nil
    }
    return hostport, "", nil
}

// (favicon generation removed; now served from static file)

func wantsHTML(r *http.Request) bool {
    a := r.Header.Get("Accept")
    return strings.Contains(a, "text/html") || strings.HasPrefix(r.Header.Get("User-Agent"), "Mozilla/")
}

func forwardedPrefix(r *http.Request) string {
    p := r.Header.Get("X-Forwarded-Prefix")
    if p == "" { return "" }
    if !strings.HasPrefix(p, "/") { p = "/" + p }
    // drop trailing slash for concatenation consistency
    if len(p) > 1 && strings.HasSuffix(p, "/") { p = strings.TrimRight(p, "/") }
    return p
}

// ---------------- Sessions ----------------

const cookieName = "ab_session"

func getSecret() ([]byte, error) {
    path := filepath.Join(*dataDir, "session_secret")
    if b, err := os.ReadFile(path); err == nil && len(b) >= 32 {
        return b, nil
    }
    b := make([]byte, 32)
    if _, err := rand.Read(b); err != nil {
        return nil, err
    }
    if err := os.WriteFile(path, b, 0o600); err != nil {
        return nil, err
    }
    return b, nil
}

func sign(secret []byte, parts ...string) string {
    mac := hmac.New(sha256.New, secret)
    for _, p := range parts {
        mac.Write([]byte("|"))
        mac.Write([]byte(p))
    }
    return hex.EncodeToString(mac.Sum(nil))
}

func makeToken(username string) (string, time.Time, error) {
    secret, err := getSecret()
    if err != nil { return "", time.Time{}, err }
    // 10 years
    exp := time.Now().AddDate(10, 0, 0)
    nonce := make([]byte, 16)
    if _, err := rand.Read(nonce); err != nil { return "", time.Time{}, err }
    n := hex.EncodeToString(nonce)
    expUnix := strconv.FormatInt(exp.Unix(), 10)
    sig := sign(secret, username, expUnix, n)
    token := strings.Join([]string{username, expUnix, n, sig}, "|")
    return token, exp, nil
}

func parseToken(tok string) (string, error) {
    parts := strings.Split(tok, "|")
    if len(parts) != 4 { return "", errors.New("bad token format") }
    username, expUnix, nonce, gotSig := parts[0], parts[1], parts[2], parts[3]
    secret, err := getSecret()
    if err != nil { return "", err }
    want := sign(secret, username, expUnix, nonce)
    if !hmac.Equal([]byte(gotSig), []byte(want)) {
        return "", errors.New("bad signature")
    }
    exp, err := strconv.ParseInt(expUnix, 10, 64)
    if err != nil { return "", errors.New("bad expiry") }
    if time.Now().After(time.Unix(exp, 0)) {
        return "", errors.New("expired")
    }
    return username, nil
}

func requireAuth(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        c, err := r.Cookie(cookieName)
        if err != nil || c == nil || c.Value == "" {
            if wantsHTML(r) { http.Redirect(w, r, forwardedPrefix(r)+"/login", http.StatusFound); return }
            http.Error(w, "unauthorized", http.StatusUnauthorized); return
        }
        if _, err := parseToken(c.Value); err != nil {
            if wantsHTML(r) { http.Redirect(w, r, forwardedPrefix(r)+"/login", http.StatusFound); return }
            http.Error(w, "unauthorized", http.StatusUnauthorized); return
        }
        next.ServeHTTP(w, r)
    })
}

func currentUser(r *http.Request) (string, bool) {
    c, err := r.Cookie(cookieName)
    if err != nil { return "", false }
    u, err := parseToken(c.Value)
    return u, err == nil
}

// ---------------- Handlers ----------------

type loginRequest struct {
    Username string `json:"username"`
    Password string `json:"password"`
}

type Lease struct {
    ClientID string    `json:"client_id"`
    Expires  time.Time `json:"expires"`
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
    switch r.Method {
    case http.MethodGet:
        // Serve login page
        serveStaticLogin(w, r)
        return
    case http.MethodPost:
        var req loginRequest
        ct := r.Header.Get("Content-Type")
        if strings.HasPrefix(ct, "application/json") {
            if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
                http.Error(w, "bad json", http.StatusBadRequest); return
            }
        } else {
            // Accept standard form posts for better password manager support
            _ = r.ParseForm()
            req.Username = r.FormValue("username")
            req.Password = r.FormValue("password")
        }
        userMapMu.RLock()
        pass, ok := userMap[req.Username]
        userMapMu.RUnlock()
        if !ok || pass != req.Password {
            if strings.HasPrefix(ct, "application/json") {
                http.Error(w, "invalid credentials", http.StatusUnauthorized); return
            }
            // Return simple HTML with link back
            w.Header().Set("Content-Type", "text/html; charset=utf-8")
            w.WriteHeader(http.StatusUnauthorized)
            fmt.Fprintf(w, "<html><body><p>Invalid credentials.</p><a href='%s/login'>Back to login</a></body></html>", forwardedPrefix(r))
            return
        }
        tok, exp, err := makeToken(req.Username)
        if err != nil { http.Error(w, "server error", http.StatusInternalServerError); return }
        p := forwardedPrefix(r)
        if p == "" { p = "/" } else { p = p + "/" }
        cookie := &http.Cookie{
            Name:     cookieName,
            Value:    tok,
            Path:     p,
            HttpOnly: true,
            SameSite: http.SameSiteLaxMode,
            Expires:  exp,
            MaxAge:   int(time.Until(exp).Seconds()),
        }
        // Mark cookie Secure if either explicitly requested or the request is HTTPS (directly or via proxy headers)
        if os.Getenv("COOKIE_SECURE") == "1" || requestIsHTTPS(r) { cookie.Secure = true }
        http.SetCookie(w, cookie)
        if strings.HasPrefix(ct, "application/json") {
            w.Header().Set("Content-Type", "application/json")
            io.WriteString(w, `{"ok":true}`)
        } else {
            // Redirect to app root so password managers can capture successful login
            http.Redirect(w, r, p, http.StatusFound)
        }
        return
    default:
        http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
    }
}

// requestIsHTTPS detects HTTPS considering reverse proxy headers.
func requestIsHTTPS(r *http.Request) bool {
    if r.TLS != nil { return true }
    if strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") { return true }
    if strings.EqualFold(r.Header.Get("X-Forwarded-Ssl"), "on") { return true }
    // RFC 7239 Forwarded: for=...; proto=https; by=...
    if f := r.Header.Get("Forwarded"); f != "" {
        lf := strings.ToLower(f)
        if strings.Contains(lf, "proto=https") { return true }
    }
    return false
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost { http.Error(w, "method not allowed", http.StatusMethodNotAllowed); return }
    // Expire both prefix-scoped and root-scoped cookies to be safe
    http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", Expires: time.Unix(0,0), MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteLaxMode})
    pp := forwardedPrefix(r); if pp == "" { pp = "/" } else { pp = pp + "/" }
    http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: pp, Expires: time.Unix(0,0), MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteLaxMode})
    w.WriteHeader(http.StatusOK)
}

func handleMe(w http.ResponseWriter, r *http.Request) {
    if u, ok := currentUser(r); ok {
        w.Header().Set("Content-Type", "application/json")
        fmt.Fprintf(w, `{"username":"%s"}`, u)
        return
    }
    http.Error(w, "unauthorized", http.StatusUnauthorized)
}

func handleBooks(w http.ResponseWriter, r *http.Request) {
    // Return the in-memory cached tree as JSON
    cacheMu.RLock()
    defer cacheMu.RUnlock()
    if cachedTree == nil {
        http.Error(w, "no cache", http.StatusServiceUnavailable); return
    }
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(cachedTree)
}

// ---------------- Playback Lease (single active player per user) ----------------

func leaseFor(user string) *Lease {
    leaseMu.Lock()
    defer leaseMu.Unlock()
    l := leases[user]
    if l != nil && time.Now().After(l.Expires) {
        leases[user] = nil
        l = nil
    }
    return l
}

func broadcast(user string, payload string) {
    leaseMu.Lock()
    subs := subscribers[user]
    for ch := range subs {
        select { case ch <- payload: default: }
    }
    leaseMu.Unlock()
}

func handleLeaseAcquire(w http.ResponseWriter, r *http.Request) {
    u, _ := currentUser(r)
    var body struct{ ClientID string `json:"client_id"` }
    if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.ClientID == "" {
        http.Error(w, "bad json", http.StatusBadRequest); return
    }
    leaseMu.Lock()
    leases[u] = &Lease{ClientID: body.ClientID, Expires: time.Now().Add(90 * time.Second)}
    l := leases[u]
    leaseMu.Unlock()
    // notify others
    b, _ := json.Marshal(l)
    broadcast(u, string(b))
    // Include owner=true in response for convenience
    w.Header().Set("Content-Type", "application/json")
    io.WriteString(w, fmt.Sprintf(`{"client_id":"%s","expires":%d,"owner":true}`, l.ClientID, l.Expires.Unix()))
}

func handleLeaseHeartbeat(w http.ResponseWriter, r *http.Request) {
    u, _ := currentUser(r)
    var body struct{ ClientID string `json:"client_id"` }
    if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.ClientID == "" {
        http.Error(w, "bad json", http.StatusBadRequest); return
    }
    leaseMu.Lock()
    l := leases[u]
    if l != nil && l.ClientID == body.ClientID {
        l.Expires = time.Now().Add(90 * time.Second)
    }
    leaseMu.Unlock()
    // Respond with current holder and whether caller owns it
    cur := leaseFor(u)
    owner := cur != nil && cur.ClientID == body.ClientID
    w.Header().Set("Content-Type", "application/json")
    if cur != nil {
        io.WriteString(w, fmt.Sprintf(`{"client_id":"%s","expires":%d,"owner":%t}`, cur.ClientID, cur.Expires.Unix(), owner))
    } else {
        io.WriteString(w, fmt.Sprintf(`{"client_id":"","owner":%t}`, owner))
    }
}

func handleLeaseRelease(w http.ResponseWriter, r *http.Request) {
    u, _ := currentUser(r)
    var body struct{ ClientID string `json:"client_id"` }
    if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.ClientID == "" {
        http.Error(w, "bad json", http.StatusBadRequest); return
    }
    leaseMu.Lock()
    if l := leases[u]; l != nil && l.ClientID == body.ClientID {
        leases[u] = nil
    }
    leaseMu.Unlock()
    broadcast(u, `{"client_id":""}`)
    w.WriteHeader(http.StatusOK)
}

func handleLeaseStream(w http.ResponseWriter, r *http.Request) {
    u, _ := currentUser(r)
    flusher, ok := w.(http.Flusher)
    if !ok { http.Error(w, "stream unsupported", http.StatusInternalServerError); return }
    w.Header().Set("Content-Type", "text/event-stream")
    w.Header().Set("Cache-Control", "no-cache")
    w.Header().Set("Connection", "keep-alive")
    ch := make(chan string, 8)
    leaseMu.Lock()
    if subscribers[u] == nil { subscribers[u] = map[chan string]struct{}{} }
    subscribers[u][ch] = struct{}{}
    // send initial state
    if l := leases[u]; l != nil && time.Now().Before(l.Expires) {
        b, _ := json.Marshal(l)
        fmt.Fprintf(w, "event: lease\n")
        fmt.Fprintf(w, "data: %s\n\n", string(b))
    } else {
        fmt.Fprintf(w, "event: lease\n")
        fmt.Fprintf(w, "data: {\"client_id\":\"\"}\n\n")
    }
    flusher.Flush()
    leaseMu.Unlock()

    // writer loop
    notify := r.Context().Done()
    for {
        select {
        case <-notify:
            leaseMu.Lock()
            delete(subscribers[u], ch)
            close(ch)
            leaseMu.Unlock()
            return
        case msg := <-ch:
            fmt.Fprintf(w, "event: lease\n")
            fmt.Fprintf(w, "data: %s\n\n", msg)
            flusher.Flush()
        }
    }
}

func handleLeaseCurrent(w http.ResponseWriter, r *http.Request) {
    u, _ := currentUser(r)
    w.Header().Set("Content-Type", "application/json")
    if l := leaseFor(u); l != nil {
        io.WriteString(w, fmt.Sprintf(`{"client_id":"%s","expires":%d}`, l.ClientID, l.Expires.Unix()))
        return
    }
    io.WriteString(w, `{"client_id":""}`)
}

func handleAudiobooksJSON(w http.ResponseWriter, r *http.Request) {
    // Never serve the on-disk file directly; return in-memory cache only.
    cacheMu.RLock()
    t := cachedTree
    cacheMu.RUnlock()
    if t == nil {
        // Try to build once
        if err := refreshIndex(); err != nil {
            // Graceful empty tree fallback
            w.Header().Set("Content-Type", "application/json")
            io.WriteString(w, `{"name":"Audiobooks","type":"directory","children":[]}`)
            return
        }
        cacheMu.RLock()
        t = cachedTree
        cacheMu.RUnlock()
        if t == nil {
            w.Header().Set("Content-Type", "application/json")
            io.WriteString(w, `{"name":"Audiobooks","type":"directory","children":[]}`)
            return
        }
    }
    w.Header().Set("Content-Type", "application/json")
    _ = json.NewEncoder(w).Encode(t)
}

func safeJoin(base, rel string) (string, error) {
    clean := filepath.Clean("/" + rel)
    // strip leading slash after cleaning
    if strings.HasPrefix(clean, "/") {
        clean = clean[1:]
    }
    p := filepath.Join(base, clean)
    // ensure p is within base
    absBase, _ := filepath.Abs(base)
    absP, _ := filepath.Abs(p)
    if !strings.HasPrefix(absP, absBase) {
        return "", errors.New("path traversal")
    }
    return p, nil
}

func handleMedia(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet && r.Method != http.MethodHead { http.Error(w, "method not allowed", http.StatusMethodNotAllowed); return }
    enc := strings.TrimPrefix(r.URL.Path, "/media/")
    rel, err := neturl.PathUnescape(enc)
    if err != nil { http.Error(w, "bad path", http.StatusBadRequest); return }
    fp, err := safeJoin(*dataDir, rel)
    if err != nil { http.Error(w, "bad path", http.StatusBadRequest); return }
    if verbose { log.Printf("media request: enc=%q rel=%q fp=%q", enc, rel, fp) }
    http.ServeFile(w, r, fp)
}

func handleRootOrData(w http.ResponseWriter, r *http.Request) {
    p := r.URL.Path
    // Serve SPA index for any subpath root like '/mybooks/'
    if strings.HasSuffix(p, "/") && !(strings.HasPrefix(p, "/api/") || strings.HasPrefix(p, "/login") || strings.HasPrefix(p, "/logout") || strings.HasPrefix(p, "/static/") || strings.HasPrefix(p, "/media/")) {
        serveStaticIndex(w, r)
        return
    }
    // Prevent direct index.html
    if strings.HasSuffix(p, "/index.html") {
        http.NotFound(w, r)
        return
    }
    // Rewrite prefixed resource paths: /<prefix>/audiobooks.json|media|static
    if i := strings.Index(p, "/audiobooks.json"); i >= 0 {
        r2 := r.Clone(r.Context())
        r2.URL.Path = p[i:]
        handleAudiobooksJSON(w, r2)
        return
    }
    if i := strings.Index(p, "/media/"); i >= 0 {
        r2 := r.Clone(r.Context())
        r2.URL.Path = p[i:]
        handleMedia(w, r2)
        return
    }
    if strings.HasSuffix(p, "/static/favicon.ico") {
        serveStaticFavicon(w, r)
        return
    }
    // Support direct audio file paths like '/mybooks/Folder/file.mp3'
    if isAudioPath(p) {
        if fp, ok := resolveDataPathFromPrefixed(p); ok {
            if verbose { log.Printf("media direct: %q -> %q", p, fp) }
            http.ServeFile(w, r, fp)
            return
        }
    }
    if strings.HasSuffix(p, "/static/mirror.js") {
        serveMirrorJS(w, r)
        return
    }
    if strings.HasSuffix(p, "/static/solo.js") {
        serveSoloJS(w, r)
        return
    }
    http.NotFound(w, r)
}

func isAudioPath(p string) bool {
    ext := strings.ToLower(filepath.Ext(p))
    return audioExt[ext]
}

func resolveDataPathFromPrefixed(p string) (string, bool) {
    // Remove leading '/'
    raw := strings.TrimPrefix(p, "/")
    dec, err := neturl.PathUnescape(raw)
    if err != nil { dec = raw }
    // Try direct join
    fp := filepath.Join(*dataDir, dec)
    if st, err := os.Stat(fp); err == nil && !st.IsDir() { return fp, true }
    // Try skipping first segment (e.g., '/mybooks/...')
    if i := strings.Index(dec, "/"); i > 0 {
        fp2 := filepath.Join(*dataDir, dec[i+1:])
        if st, err := os.Stat(fp2); err == nil && !st.IsDir() { return fp2, true }
    }
    return "", false
}

// ---------------- State persistence ----------------

func stateFileForUser(u string) string {
    dir := filepath.Join(*dataDir, "state")
    _ = os.MkdirAll(dir, 0o755)
    return filepath.Join(dir, u+".json")
}

func handleState(w http.ResponseWriter, r *http.Request) {
    u, ok := currentUser(r)
    if !ok { http.Error(w, "unauthorized", http.StatusUnauthorized); return }
    path := stateFileForUser(u)
    switch r.Method {
    case http.MethodGet:
        b, err := os.ReadFile(path)
        if err != nil {
            if os.IsNotExist(err) { w.Header().Set("Content-Type", "application/json"); io.WriteString(w, "{}"); return }
            http.Error(w, "server error", http.StatusInternalServerError); return
        }
        w.Header().Set("Content-Type", "application/json")
        w.Write(b)
    case http.MethodPost:
        // Accept arbitrary JSON and store as-is
        var v any
        if err := json.NewDecoder(r.Body).Decode(&v); err != nil { http.Error(w, "bad json", http.StatusBadRequest); return }
        stateMu.Lock()
        defer stateMu.Unlock()
        b, _ := json.MarshalIndent(v, "", "  ")
        if err := os.WriteFile(path, b, 0o644); err != nil { http.Error(w, "server error", http.StatusInternalServerError); return }
        w.Header().Set("Content-Type", "application/json")
        io.WriteString(w, `{"ok":true}`)
    default:
        http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
    }
}

// ---------------- Indexing ----------------

var audioExt = map[string]bool{
    ".mp3": true, ".m4a": true, ".m4b": true, ".ogg": true, ".wav": true, ".aac": true, ".flac": true,
}

func loadOrInitIndex() error {
    // Always rebuild on startup to avoid using on-disk audiobooks.json.
    if err := refreshIndex(); err != nil {
        return err
    }
    if sig, serr := computeSignature(*dataDir); serr == nil {
        sigMu.Lock()
        lastSig = sig
        sigMu.Unlock()
    }
    return nil
}

func refreshIndex() error {
    t := TreeNode{Name: "Audiobooks", Type: "directory"}
    entries, err := os.ReadDir(*dataDir)
    if err != nil { return err }
    for _, e := range entries {
        name := e.Name()
        if strings.HasPrefix(name, ".") || name == "audiobooks.json" || name == "session_secret" || name == "state" { continue }
        full := filepath.Join(*dataDir, name)
        node, err := buildNode(full, name)
        if err != nil { log.Printf("indexing %s: %v", name, err); continue }
        if node != nil { t.Children = append(t.Children, *node) }
    }
    // sort children by name (dirs first inside buildNode)
    sort.Slice(t.Children, func(i, j int) bool { return t.Children[i].Name < t.Children[j].Name })
    // save to disk and memory
    b, _ := json.MarshalIndent(t, "", "  ")
    if err := os.WriteFile(filepath.Join(*dataDir, "audiobooks.json"), b, 0o644); err != nil { return err }
    cacheMu.Lock()
    cachedTree = &t
    cacheModTime = time.Now()
    cacheMu.Unlock()
    return nil
}

func buildNode(fullPath, relPath string) (*TreeNode, error) {
    fi, err := os.Stat(fullPath)
    if err != nil { return nil, err }
    if fi.IsDir() {
        entries, err := os.ReadDir(fullPath)
        if err != nil { return nil, err }
        node := &TreeNode{Name: filepath.Base(relPath), Type: "directory"}
        for _, e := range entries {
            name := e.Name()
            if strings.HasPrefix(name, ".") { continue }
            if name == "audiobooks.json" || name == "session_secret" || name == "state" { continue }
            childFull := filepath.Join(fullPath, name)
            childRel := filepath.Join(relPath, name)
            ch, err := buildNode(childFull, childRel)
            if err != nil { log.Printf("index child %s: %v", childRel, err); continue }
            if ch != nil { node.Children = append(node.Children, *ch) }
        }
        // dirs first then files by name
        sort.Slice(node.Children, func(i, j int) bool {
            if node.Children[i].Type == node.Children[j].Type {
                return strings.ToLower(node.Children[i].Name) < strings.ToLower(node.Children[j].Name)
            }
            return node.Children[i].Type == "directory"
        })
        return node, nil
    }
    // file
    ext := strings.ToLower(filepath.Ext(fi.Name()))
    if !audioExt[ext] {
        return nil, nil // skip non-audio
    }
    // URLs in cache stay as relative paths; client will request via /media or direct
    rel := filepath.ToSlash(relPath)
    return &TreeNode{Name: fi.Name(), Type: "file", URL: rel}, nil
}

// ---------------- Efficient periodic reindexing ----------------

// computeSignature walks /data and creates a fast fingerprint of audio files
// based on relative path, size, and modtime. No file contents are read.
func computeSignature(root string) (string, error) {
    const (
        offset64 = 1469598103934665603
        prime64  = 1099511628211
    )
    h := uint64(offset64)
    add := func(s string) {
        for i := 0; i < len(s); i++ {
            h ^= uint64(s[i])
            h *= prime64
        }
    }
    var count int
    err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
        if err != nil { return err }
        name := d.Name()
        // skip special dirs/files
        if name == "state" || name == "audiobooks.json" || name == "session_secret" || strings.HasPrefix(name, ".") {
            if d.IsDir() && (name == "state" || strings.HasPrefix(name, ".")) {
                return filepath.SkipDir
            }
            if !d.IsDir() { return nil }
        }
        if d.IsDir() { return nil }
        ext := strings.ToLower(filepath.Ext(name))
        if !audioExt[ext] { return nil }
        rel, _ := filepath.Rel(root, p)
        info, ierr := d.Info(); if ierr != nil { return ierr }
        add(strings.ReplaceAll(rel, "\\", "/"))
        add("|")
        add(strconv.FormatInt(info.Size(), 10))
        add("|")
        add(strconv.FormatInt(info.ModTime().UnixNano(), 10))
        count++
        return nil
    })
    if err != nil { return "", err }
    return fmt.Sprintf("%d:%x", count, h), nil
}

func startIndexScheduler() {
    // small initial delay then hourly checks
    time.Sleep(5 * time.Second)
    doIndexCheck()
    ticker := time.NewTicker(1 * time.Hour)
    defer ticker.Stop()
    for range ticker.C {
        doIndexCheck()
    }
}

func doIndexCheck() {
    sig, err := computeSignature(*dataDir)
    if err != nil { log.Printf("signature compute error: %v", err); return }
    sigMu.RLock(); prev := lastSig; sigMu.RUnlock()
    if sig == prev && prev != "" { return }
    if err := refreshIndex(); err != nil {
        log.Printf("reindex error: %v", err)
        return
    }
    sigMu.Lock(); lastSig = sig; sigMu.Unlock()
    log.Printf("library changed; index refreshed")
}

// ---------------- Static pages ----------------

func serveStaticIndex(w http.ResponseWriter, r *http.Request) {
    // Always serve the bundled UI to ensure consistent behavior.
    content, err := os.ReadFile(filepath.Join("./web", "index.html"))
    if err != nil {
        http.Error(w, "index not found", http.StatusNotFound)
        return
    }
    // Build boot script with per-user state
    boot := ""
    if u, ok := currentUser(r); ok {
        sf := stateFileForUser(u)
        jb, err := os.ReadFile(sf)
        if err != nil {
            jb = []byte("{}")
        }
        // Avoid closing the script early
        js := strings.ReplaceAll(string(jb), "</", "<\\/")
        // Include __AB_PREFIX for subpath deployments
        prefix := forwardedPrefix(r)
        boot = "<script>(function(){try{window.__AB_PREFIX='" + prefix + "';var S=" + js + ";localStorage.setItem('audiobookPlayerState', JSON.stringify(S));if(S&&Array.isArray(S.listened)){localStorage.setItem('audiobookListened', JSON.stringify(S.listened));}}catch(e){}})();</script>"
    }

    // Tiny logout link (top-right) injector
    logout := "" +
        "<style>#ab-logout{position:fixed;top:calc(8px + env(safe-area-inset-top,0px));right:calc(8px + env(safe-area-inset-right,0px));z-index:2147483647;font-size:12px;color:#9ecbff;text-decoration:none;padding:6px 8px;border-radius:8px;background:rgba(0,0,0,.35);-webkit-backdrop-filter:saturate(180%) blur(8px);backdrop-filter:saturate(180%) blur(8px);}#ab-logout:hover{text-decoration:underline}</style>" +
        "<script>(function(){var p=window.__AB_PREFIX||(function(){var b=document.querySelector('base');try{return b?new URL(b.href).pathname.replace(/\\/$/,''):'';}catch(e){return''}})();function add(){if(document.getElementById('ab-logout'))return;var a=document.createElement('a');a.id='ab-logout';a.href='#';a.textContent='Logout';a.addEventListener('click',function(e){e.preventDefault();fetch(p+'/logout',{method:'POST'}).finally(function(){location.href=p+'/login';});});document.body.appendChild(a);}if(document.readyState==='loading'){document.addEventListener('DOMContentLoaded',add);}else{add();}})();</script>"

    // Simple injection: add scripts right after <head>
    html := string(content)
    const tag = "<head>"
    if idx := strings.Index(strings.ToLower(html), "<head>"); idx != -1 {
        // preserve original case by searching again for exact
        if i := strings.Index(html, tag); i != -1 {
            i += len(tag)
            base := ""
            if p := forwardedPrefix(r); p != "" { base = "\n    <base href=\"" + p + "/\">" }
            html = html[:i] + base + "\n    " + boot + "\n    <script src=\"static/mirror.js\"></script>\n    <script src=\"static/solo.js\"></script>\n    " + logout + html[i:]
        } else {
            // fallback: lower-cased index
            i2 := idx + len(tag)
            base := ""
            if p := forwardedPrefix(r); p != "" { base = "\n    <base href=\"" + p + "/\">" }
            html = html[:i2] + base + "\n    " + boot + "\n    <script src=\"static/mirror.js\"></script>\n    <script src=\"static/solo.js\"></script>\n    " + logout + html[i2:]
        }
    } else {
        // Fallback: prepend scripts
        html = boot + "\n<script src=\"static/mirror.js\"></script>\n<script src=\"static/solo.js\"></script>\n" + logout + html
    }
    w.Header().Set("Content-Type", "text/html; charset=utf-8")
    io.WriteString(w, html)
}

func serveStaticLogin(w http.ResponseWriter, r *http.Request) {
    b, err := os.ReadFile(filepath.Join("./web", "login.html"))
    if err != nil { http.Error(w, "not found", http.StatusNotFound); return }
    html := string(b)
    // Inject base and __AB_PREFIX so login fetch uses subpath
    prefix := forwardedPrefix(r)
    inject := "<script>window.__AB_PREFIX='" + prefix + "';</script>"
    const tag = "<head>"
    if idx := strings.Index(strings.ToLower(html), "<head>"); idx != -1 {
        if i := strings.Index(html, tag); i != -1 { i += len(tag); html = html[:i] + "\n    <base href=\"" + prefix + "/\">\n    " + inject + html[i:] } else { i2 := idx + len(tag); html = html[:i2] + "\n    <base href=\"" + prefix + "/\">\n    " + inject + html[i2:] }
    } else {
        html = inject + html
    }
    w.Header().Set("Content-Type", "text/html; charset=utf-8")
    io.WriteString(w, html)
}

// Serve injected helper script that mirrors localStorage <-> server state.
func serveMirrorJS(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
    http.ServeFile(w, r, filepath.Join("./web", "static", "mirror.js"))
}

// Serve solo-play coordinator
// URL: /static/solo.js
func serveSoloJS(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
    http.ServeFile(w, r, filepath.Join("./web", "static", "solo.js"))
}

// Serve static favicon from web/static/favicon.ico
func serveStaticFavicon(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "image/x-icon")
    http.ServeFile(w, r, filepath.Join("./web", "static", "favicon.ico"))
}
