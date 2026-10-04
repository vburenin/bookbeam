package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// usernameRE restricts usernames to characters that are safe in file names
// (users/<name>.json) and in the "|"-separated session token.
var usernameRE = regexp.MustCompile(`^[A-Za-z0-9._@-]{1,64}$`)

// ValidUsername reports whether name is acceptable as a BookBeam username.
func ValidUsername(name string) bool { return usernameRE.MatchString(name) }

// Users is the immutable set of configured logins. Passwords are kept only
// as SHA-256 digests so plain-text and pre-hashed entries are verified the
// same way, in constant time.
type Users struct {
	digests map[string][sha256.Size]byte
}

// ParseUsers parses "user:password" or "user:sha256:<64 hex>" entries (the
// "sha256:" prefix is case-insensitive). Later entries override earlier ones
// for the same username, so callers should pass the lowest-precedence source
// first. Errors name the entry by position and never echo a password.
func ParseUsers(specs []string) (*Users, error) {
	u := &Users{digests: make(map[string][sha256.Size]byte, len(specs))}
	for i, spec := range specs {
		name, digest, err := parseUserSpec(spec)
		if err != nil {
			return nil, fmt.Errorf("user entry #%d: %w", i+1, err)
		}
		u.digests[name] = digest
	}
	return u, nil
}

// Merge returns the users of u and o; o wins for names in both.
func (u *Users) Merge(o *Users) *Users {
	out := &Users{digests: make(map[string][sha256.Size]byte, len(u.digests)+len(o.digests))}
	for n, d := range u.digests {
		out.digests[n] = d
	}
	for n, d := range o.digests {
		out.digests[n] = d
	}
	return out
}

const hashPrefix = "sha256:"

func parseUserSpec(spec string) (string, [sha256.Size]byte, error) {
	var zero [sha256.Size]byte
	name, secret, ok := strings.Cut(spec, ":")
	switch {
	case !ok:
		// Without a ':' there is no telling which part is a password (an
		// entry split off a password containing a separator), so nothing
		// of it is echoed.
		return "", zero, errors.New("no ':' in it; want user:password or user:sha256:<hex>")
	case name == "":
		return "", zero, errors.New("missing username; want user:password or user:sha256:<hex>")
	case secret == "":
		return "", zero, fmt.Errorf("user %q has an empty password", name)
	case !ValidUsername(name):
		return "", zero, errors.New("invalid username: only letters, digits and . _ @ - are allowed (max 64)")
	}
	if len(secret) >= len(hashPrefix) && strings.EqualFold(secret[:len(hashPrefix)], hashPrefix) {
		b, err := hex.DecodeString(secret[len(hashPrefix):])
		if err != nil || len(b) != sha256.Size {
			return "", zero, fmt.Errorf("user %q: sha256: must be followed by 64 hex digits", name)
		}
		var d [sha256.Size]byte
		copy(d[:], b)
		return name, d, nil
	}
	return name, sha256.Sum256([]byte(secret)), nil
}

// Verify checks a username/password pair in constant time with respect to
// the password, and does the same amount of work for unknown usernames.
func (u *Users) Verify(name, password string) bool {
	want, known := u.digests[name]
	got := sha256.Sum256([]byte(password))
	match := subtle.ConstantTimeCompare(got[:], want[:]) == 1
	return known && match
}

// Exists reports whether name is a configured user.
func (u *Users) Exists(name string) bool {
	_, ok := u.digests[name]
	return ok
}

// Names returns the configured usernames, sorted.
func (u *Users) Names() []string {
	names := make([]string, 0, len(u.digests))
	for n := range u.digests {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}
