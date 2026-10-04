package server

import (
	"context"
	"errors"
	"fmt"
	"math"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"

	"rsc.io/qr"

	"github.com/vburenin/bookbeam/server/internal/auth"
)

// cookieMaxAge matches the ten-year token lifetime. Browsers cap it (Chrome:
// 400 days), so api/me renews the cookies of devices in use.
const cookieMaxAge = 10 * 365 * 24 * 60 * 60

// authedHandler is a handler that runs only for authenticated requests.
type authedHandler func(w http.ResponseWriter, r *http.Request, sess auth.Session)

// requireAuth authenticates the session cookie or answers 401. When several
// ab_session cookies are present (e.g. a v1 cookie on "/" next to one on a
// sub-path), any valid one is accepted.
func (s *Server) requireAuth(h authedHandler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ua, ip := r.UserAgent(), s.clientIP(r)
		for _, c := range r.CookiesNamed(auth.CookieName) {
			if sess, err := s.auth.Authenticate(c.Value, ua, ip); err == nil {
				setLogUser(r, sess.User)
				h(w, r.WithContext(context.WithValue(r.Context(), ctxSessionToken, c.Value)), sess)
				return
			}
		}
		writeError(w, http.StatusUnauthorized, "unauthorized")
	})
}

func (s *Server) setSessionCookie(w http.ResponseWriter, r *http.Request, token string) {
	s.setCookie(w, r, auth.CookieName, token)
}

// setCookie sets a long-lived app cookie scoped to the app's path.
func (s *Server) setCookie(w http.ResponseWriter, r *http.Request, name, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     prefixOf(r) + "/",
		MaxAge:   cookieMaxAge,
		Expires:  time.Now().Add(cookieMaxAge * time.Second),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   s.cookieSecure || s.isHTTPS(r),
	})
}

// requestDevice returns the browser's device id (ab_device cookie), or ""
// when it has none (or a malformed one).
func requestDevice(r *http.Request) string {
	for _, c := range r.CookiesNamed(auth.DeviceCookieName) {
		if auth.ValidDeviceID(c.Value) {
			return c.Value
		}
	}
	return ""
}

// signInDevice returns the device id a sign-in on r is recorded under: the
// browser's own, or a new one (set as a cookie once the sign-in succeeds).
func signInDevice(r *http.Request) (string, error) {
	if d := requestDevice(r); d != "" {
		return d, nil
	}
	return auth.NewDeviceID()
}

// sessionDevice returns the device sess lives in and (re)sets the browser's
// ab_device cookie to it. Sessions from before devices were tracked are
// linked to the browser's device (a new one if it has none) on the way.
func (s *Server) sessionDevice(w http.ResponseWriter, r *http.Request, sess auth.Session) string {
	dev := sess.Device
	if dev == "" {
		var err error
		if dev, err = signInDevice(r); err != nil {
			s.log.Error("creating device id", "err", err)
			return ""
		}
		if err := s.auth.LinkDevice(sess.ID, dev); err != nil {
			s.log.Error("linking session to device", "user", sess.User, "err", err)
			return ""
		}
	}
	s.setCookie(w, r, auth.DeviceCookieName, dev)
	return dev
}

// clearSessionCookies expires the cookie on the app path and on "/" (where
// v1 may have set it).
func (s *Server) clearSessionCookies(w http.ResponseWriter, r *http.Request) {
	paths := []string{prefixOf(r) + "/"}
	if paths[0] != "/" {
		paths = append(paths, "/")
	}
	for _, p := range paths {
		http.SetCookie(w, &http.Cookie{
			Name: auth.CookieName, Value: "", Path: p, MaxAge: -1, Expires: time.Unix(0, 0),
			HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: s.cookieSecure || s.isHTTPS(r),
		})
	}
}

// handleLogin accepts a native form POST (redirecting back to the app) or a
// JSON body (answering JSON).
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	isJSON := mt == "application/json"
	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if isJSON {
		if !readJSON(w, r, &creds) {
			return
		}
	} else {
		r.Body = http.MaxBytesReader(w, r.Body, maxJSONBody)
		if err := r.ParseForm(); err != nil {
			redirectRelative(w, "./?login=failed")
			return
		}
		creds.Username, creds.Password = r.PostFormValue("username"), r.PostFormValue("password")
	}
	creds.Username = strings.TrimSpace(creds.Username)

	// Signing in on a device that already has someone signed in adds a
	// listener; the others stay available for switching.
	device, err := signInDevice(r)
	if err != nil {
		s.log.Error("creating device id", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	token, sess, err := s.auth.Login(creds.Username, creds.Password, r.UserAgent(), s.clientIP(r), device)
	var limited *auth.RateLimitedError
	switch {
	case err == nil:
		setLogUser(r, sess.User)
		s.setSessionCookie(w, r, token)
		s.setCookie(w, r, auth.DeviceCookieName, device)
		if isJSON {
			writeJSON(w, http.StatusOK, map[string]any{"ok": true, "username": sess.User})
		} else {
			redirectRelative(w, "./")
		}
	case errors.As(err, &limited):
		secs := int(math.Ceil(limited.RetryAfter.Seconds()))
		w.Header().Set("Retry-After", strconv.Itoa(secs))
		if isJSON {
			writeJSON(w, http.StatusTooManyRequests, map[string]any{
				"error": "too many failed attempts; try again later", "retryAfter": secs})
		} else {
			redirectRelative(w, "./?login=ratelimited")
		}
	case errors.Is(err, auth.ErrInvalidCredentials):
		if isJSON {
			writeError(w, http.StatusUnauthorized, "invalid username or password")
		} else {
			redirectRelative(w, "./?login=failed")
		}
	default:
		s.log.Error("login", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
	}
}

// handleLogout signs out the current session only. If someone else is
// signed in on the same device (the family car), the device switches to
// them, so it stays usable; "next" names them ("" = signed out).
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	device := sess.Device
	if device == "" {
		device = requestDevice(r)
	}
	next, token, ok, err := s.auth.SignOut(sess, device)
	if err != nil {
		s.log.Error("logout", "user", sess.User, "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	s.hub.closeSession(sess.ID)
	if !ok {
		s.clearSessionCookies(w, r)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "next": ""})
		return
	}
	s.setSessionCookie(w, r, token)
	s.log.Info("signed out; device switched to another listener", "user", sess.User, "next", next.User)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "next": next.User})
}

// handleMe identifies the signed-in user. Every app start calls it, so it
// also renews the cookies (browsers cap their lifetime, and the family car
// must never silently sign out) and links pre-existing sessions to their
// device.
func (s *Server) handleMe(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	if tok := sessionToken(r); tok != "" {
		s.setSessionCookie(w, r, tok)
	}
	s.sessionDevice(w, r, sess)
	writeJSON(w, http.StatusOK, map[string]string{
		"username":   sess.User,
		"sessionId":  sess.ID,
		"deviceName": sess.Name,
		"version":    s.version,
	})
}

// deviceAccountDTO is one listener in GET api/device/accounts.
type deviceAccountDTO struct {
	Username  string `json:"username"`
	SessionID string `json:"sessionId"`
	Current   bool   `json:"current"`
	LastSeen  int64  `json:"lastSeen"`
}

// handleDeviceAccounts lists who is signed in on this device ("Who's
// listening?"), one entry per user: the current listener first, then the
// others, most recently used first.
func (s *Server) handleDeviceAccounts(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	out := []deviceAccountDTO{{Username: sess.User, SessionID: sess.ID, Current: true, LastSeen: sess.LastSeen}}
	if dev := s.sessionDevice(w, r, sess); dev != "" {
		for _, x := range s.auth.DeviceAccounts(dev) {
			if x.User != sess.User {
				out = append(out, deviceAccountDTO{Username: x.User, SessionID: x.ID, LastSeen: x.LastSeen})
			}
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// handleDeviceSwitch makes another listener signed in on this device the
// current one.
func (s *Server) handleDeviceSwitch(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	var body struct {
		Username string `json:"username"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	dev := s.sessionDevice(w, r, sess)
	if dev == "" {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	token, target, err := s.auth.SwitchAccount(dev, strings.TrimSpace(body.Username))
	if errors.Is(err, auth.ErrSessionNotFound) {
		writeError(w, http.StatusNotFound, "that listener is not signed in on this device")
		return
	}
	if err != nil {
		s.log.Error("switching listener", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	s.setSessionCookie(w, r, token)
	s.log.Info("switched listener", "from", sess.User, "to", target.User)
	writeJSON(w, http.StatusOK, map[string]string{"username": target.User})
}

// sessionDTO is a device in the Settings → Devices list.
type sessionDTO struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	UA        string `json:"ua"`
	IP        string `json:"ip"`
	CreatedAt int64  `json:"createdAt"`
	LastSeen  int64  `json:"lastSeen"`
	Current   bool   `json:"current"`
}

func toSessionDTO(x auth.Session, current string) sessionDTO {
	return sessionDTO{ID: x.ID, Name: x.Name, UA: x.UA, IP: x.IP, CreatedAt: x.CreatedAt, LastSeen: x.LastSeen, Current: x.ID == current}
}

func (s *Server) handleSessions(w http.ResponseWriter, _ *http.Request, sess auth.Session) {
	list := s.auth.Sessions().List(sess.User)
	out := make([]sessionDTO, 0, len(list))
	for _, x := range list {
		out = append(out, toSessionDTO(x, sess.ID))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleSessionRename(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	var body struct {
		Name string `json:"name"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	name := auth.CleanName(body.Name)
	if name == "" {
		writeError(w, http.StatusBadRequest, "name must not be empty")
		return
	}
	x, err := s.auth.Sessions().Rename(sess.User, r.PathValue("id"), name)
	if err != nil {
		s.sessionError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toSessionDTO(x, sess.ID))
}

func (s *Server) handleSessionRevoke(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	id := r.PathValue("id")
	if err := s.auth.Revoke(sess.User, id); err != nil {
		s.sessionError(w, err)
		return
	}
	s.hub.closeSession(id)
	if id == sess.ID {
		s.clearSessionCookies(w, r)
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleRevokeOthers(w http.ResponseWriter, _ *http.Request, sess auth.Session) {
	ids, err := s.auth.RevokeOthers(sess.User, sess.ID)
	if err != nil {
		s.sessionError(w, err)
		return
	}
	for _, id := range ids {
		s.hub.closeSession(id)
	}
	writeJSON(w, http.StatusOK, map[string]int{"revoked": len(ids)})
}

func (s *Server) sessionError(w http.ResponseWriter, err error) {
	if errors.Is(err, auth.ErrSessionNotFound) {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	s.log.Error("updating sessions", "err", err)
	writeError(w, http.StatusInternalServerError, "internal error")
}

// --- Device pairing ---

func (s *Server) handlePairStart(w http.ResponseWriter, r *http.Request) {
	// The body may carry {deviceName}; it is ignored (see StartPairing).
	var body struct{}
	if err := decodeJSON(w, r, &body); err != nil && !errors.Is(err, errEmptyBody) {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	req, pollToken, err := s.auth.StartPairing(r.UserAgent(), s.clientIP(r))
	switch {
	case errors.Is(err, auth.ErrTooManyPairings):
		writeError(w, http.StatusTooManyRequests, err.Error())
	case err != nil:
		s.log.Error("starting pairing", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
	default:
		writeJSON(w, http.StatusOK, map[string]any{"code": req.Code, "pollToken": pollToken, "expiresAt": req.ExpiresAt})
	}
}

func (s *Server) handlePairPoll(w http.ResponseWriter, r *http.Request) {
	var body struct {
		PollToken string `json:"pollToken"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	if body.PollToken == "" {
		writeError(w, http.StatusBadRequest, "pollToken is required")
		return
	}
	device, err := signInDevice(r)
	if err != nil {
		s.log.Error("creating device id", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	status, token, sess, err := s.auth.PollPairing(body.PollToken, r.UserAgent(), s.clientIP(r), device)
	if err != nil {
		s.log.Error("redeeming pairing", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if status != auth.PairApproved {
		writeJSON(w, http.StatusOK, map[string]string{"status": status})
		return
	}
	setLogUser(r, sess.User)
	s.setSessionCookie(w, r, token)
	s.setCookie(w, r, auth.DeviceCookieName, device)
	writeJSON(w, http.StatusOK, map[string]string{"status": status, "username": sess.User})
}

func (s *Server) handlePairInfo(w http.ResponseWriter, r *http.Request, _ auth.Session) {
	req, err := s.auth.LookupPairing(r.PathValue("code"))
	if err != nil {
		s.pairError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, req)
}

func (s *Server) handlePairApprove(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	var body struct {
		Name string `json:"name"`
	}
	if err := decodeJSON(w, r, &body); err != nil && !errors.Is(err, errEmptyBody) {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if err := s.auth.ApprovePairing(r.PathValue("code"), sess.User, body.Name); err != nil {
		s.pairError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handlePairDeny(w http.ResponseWriter, r *http.Request, _ auth.Session) {
	if err := s.auth.DenyPairing(r.PathValue("code")); err != nil {
		s.pairError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) pairError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, auth.ErrPairingNotFound):
		writeError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, auth.ErrPairingUsed):
		writeError(w, http.StatusConflict, err.Error())
	default:
		s.log.Error("pairing", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
	}
}

// maxQRData bounds the URL encoded into a pairing QR code.
const maxQRData = 400

// handlePairQR renders an SVG QR code for a pairing URL.
func (s *Server) handlePairQR(w http.ResponseWriter, r *http.Request) {
	data := r.URL.Query().Get("data")
	if len(data) > maxQRData || !(strings.HasPrefix(data, "http://") || strings.HasPrefix(data, "https://")) {
		writeError(w, http.StatusBadRequest, "data must be an http(s) URL of at most 400 characters")
		return
	}
	code, err := qr.Encode(data, qr.M)
	if err != nil {
		writeError(w, http.StatusBadRequest, "cannot encode QR code")
		return
	}
	w.Header().Set("Content-Type", "image/svg+xml")
	w.Header().Set("Cache-Control", "private, max-age=600")
	_, _ = w.Write([]byte(qrSVG(code)))
}

// qrSVG draws the code as one path of horizontal runs with a 4-module
// quiet zone.
func qrSVG(code *qr.Code) string {
	const quiet = 4
	n := code.Size + 2*quiet
	var b strings.Builder
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" shape-rendering="crispEdges">`, n, n)
	fmt.Fprintf(&b, `<rect width="%d" height="%d" fill="#fff"/><path fill="#000" d="`, n, n)
	for y := range code.Size {
		for x := 0; x < code.Size; {
			if !code.Black(x, y) {
				x++
				continue
			}
			run := 1
			for x+run < code.Size && code.Black(x+run, y) {
				run++
			}
			fmt.Fprintf(&b, "M%d %dh%dv1h-%dz", x+quiet, y+quiet, run, run)
			x += run
		}
	}
	b.WriteString(`"/></svg>`)
	return b.String()
}
