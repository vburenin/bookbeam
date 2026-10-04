package auth

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
)

// DeviceCookieName identifies a browser across the sessions signed in on it,
// so a family sharing one device (the car) can switch between listeners.
const DeviceCookieName = "ab_device"

const deviceIDLen = 32 // hex characters

// NewDeviceID returns a random device id (32 lowercase hex characters).
func NewDeviceID() (string, error) {
	var raw [deviceIDLen / 2]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}

// ValidDeviceID reports whether id has the shape NewDeviceID produces.
func ValidDeviceID(id string) bool {
	if len(id) != deviceIDLen {
		return false
	}
	for _, c := range []byte(id) {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// DeviceName derives a friendly device label from a User-Agent, e.g.
// "Tesla", "iPhone · Safari" or "Windows · Edge".
func DeviceName(ua string) string {
	if strings.Contains(ua, "Tesla/") || strings.Contains(ua, "QtCarBrowser") {
		return "Tesla"
	}
	platform := firstMatch(ua, []nameRule{
		// Order matters: iOS UAs say "like Mac OS X", Android UAs say "Linux".
		{"iPhone", "iPhone"},
		{"iPad", "iPad"},
		{"Android", "Android"},
		{"Macintosh", "Mac"},
		{"Mac OS X", "Mac"},
		{"Windows", "Windows"},
		{"Linux", "Linux"},
		{"X11", "Linux"},
	})
	browser := firstMatch(ua, []nameRule{
		// Order matters: Edge and Chrome UAs also contain "Safari/".
		{"Edg/", "Edge"},
		{"EdgA/", "Edge"},
		{"EdgiOS/", "Edge"},
		{"Firefox/", "Firefox"},
		{"FxiOS/", "Firefox"},
		{"CriOS/", "Chrome"},
		{"Chrome/", "Chrome"},
		{"Chromium/", "Chrome"},
		{"Safari/", "Safari"},
	})
	switch {
	case platform != "" && browser != "":
		return platform + " · " + browser
	case platform != "":
		return platform
	case browser != "":
		return browser
	default:
		return "Unknown device"
	}
}

type nameRule struct{ needle, name string }

func firstMatch(ua string, rules []nameRule) string {
	for _, r := range rules {
		if strings.Contains(ua, r.needle) {
			return r.name
		}
	}
	return ""
}
