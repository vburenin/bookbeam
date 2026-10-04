package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/vburenin/bookbeam/server/internal/fsutil"
)

// CookieName is the session cookie. The name and token format are shared
// with BookBeam 1.x so cookies issued by v1 (e.g. the family car's, valid
// for ten years) keep working.
const CookieName = "ab_session"

// tokenYears is how long a session token stays valid.
const tokenYears = 10

const minSecretLen = 32

// signer creates and verifies v1-compatible session tokens:
//
//	username|expUnix|nonceHex|sigHex
//	sigHex = hex(HMAC-SHA256(secret, "|"+username+"|"+expUnix+"|"+nonceHex))
type signer struct {
	secret []byte
}

func (s signer) sign(parts ...string) string {
	mac := hmac.New(sha256.New, s.secret)
	for _, p := range parts {
		mac.Write([]byte("|"))
		mac.Write([]byte(p))
	}
	return hex.EncodeToString(mac.Sum(nil))
}

// issue mints a new token for user with a fresh random nonce, which doubles
// as the session id.
func (s signer) issue(user string, now time.Time) (token, nonce string, exp time.Time, err error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", "", time.Time{}, err
	}
	nonce = hex.EncodeToString(raw[:])
	exp = time.Unix(now.AddDate(tokenYears, 0, 0).Unix(), 0)
	return s.mint(user, exp.Unix(), nonce), nonce, exp, nil
}

// mint builds the token for a session. Tokens are deterministic, so minting
// an existing session's token again reproduces the cookie it was issued.
func (s signer) mint(user string, expUnix int64, nonce string) string {
	exp := strconv.FormatInt(expUnix, 10)
	return strings.Join([]string{user, exp, nonce, s.sign(user, exp, nonce)}, "|")
}

var errBadToken = errors.New("invalid session token")

// verify checks the signature and expiry and returns the token's user,
// nonce and expiry time.
func (s signer) verify(token string, now time.Time) (user, nonce string, exp time.Time, err error) {
	parts := strings.Split(token, "|")
	if len(parts) != 4 {
		return "", "", time.Time{}, errBadToken
	}
	user, expUnix, nonce, sig := parts[0], parts[1], parts[2], parts[3]
	want := s.sign(user, expUnix, nonce)
	if !hmac.Equal([]byte(sig), []byte(want)) {
		return "", "", time.Time{}, errBadToken
	}
	expSec, err := strconv.ParseInt(expUnix, 10, 64)
	if err != nil {
		return "", "", time.Time{}, errBadToken
	}
	exp = time.Unix(expSec, 0).UTC()
	if now.After(exp) || nonce == "" {
		return "", "", time.Time{}, errBadToken
	}
	return user, nonce, exp, nil
}

// loadSecret returns the HMAC key stored at path, creating it when missing.
// When allowLegacy is set and legacyPath holds a usable v1 key, that key is
// copied so existing v1 cookies stay valid; it reports whether it did so.
func loadSecret(path, legacyPath string, allowLegacy bool) (secret []byte, migrated bool, err error) {
	b, err := os.ReadFile(path)
	switch {
	case err == nil && len(b) >= minSecretLen:
		return b, false, nil
	case err == nil:
		return nil, false, fmt.Errorf("%s is shorter than %d bytes; delete it to generate a new key (signs everyone out)", path, minSecretLen)
	case !errors.Is(err, fs.ErrNotExist):
		return nil, false, err
	}

	if allowLegacy && legacyPath != "" {
		if lb, lerr := os.ReadFile(legacyPath); lerr == nil && len(lb) >= minSecretLen {
			if err := fsutil.WriteFileAtomic(path, lb, 0o600); err != nil {
				return nil, false, err
			}
			return lb, true, nil
		}
	}

	b = make([]byte, minSecretLen)
	if _, err := rand.Read(b); err != nil {
		return nil, false, err
	}
	if err := fsutil.WriteFileAtomic(path, b, 0o600); err != nil {
		return nil, false, err
	}
	return b, false, nil
}
