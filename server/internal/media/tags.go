package media

import (
	"slices"
	"strings"
	"unicode/utf16"
)

// maxTagValues caps how many distinct values one key may collect, which keeps
// a hostile file with millions of repeated comments from going quadratic.
const maxTagValues = 64

// tagMap gathers raw tag values under normalised keys before they are mapped
// onto Info fields. Every container funnels its native tag names into this
// one vocabulary, so field priorities (e.g. NARRATOR before PERFORMER) are
// defined once in apply instead of once per format.
type tagMap map[string][]string

// normKey upper-cases a tag name and drops everything but ASCII letters and
// digits, so "Album Artist", "album_artist" and "ALBUMARTIST" all match.
func normKey(k string) string {
	b := make([]byte, 0, len(k))
	for i := 0; i < len(k); i++ {
		switch c := k[i]; {
		case c >= 'a' && c <= 'z':
			b = append(b, c-'a'+'A')
		case c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
			b = append(b, c)
		}
	}
	return string(b)
}

// add records values under key, skipping blanks and duplicates.
func (t tagMap) add(key string, values ...string) {
	k := normKey(key)
	if k == "" {
		return
	}
	for _, v := range values {
		v = cleanText(v)
		if v == "" || len(t[k]) >= maxTagValues || slices.Contains(t[k], v) {
			continue
		}
		t[k] = append(t[k], v)
	}
}

// get returns the values of the first key that has any, joined with ", ".
func (t tagMap) get(keys ...string) string {
	for _, k := range keys {
		if vs := t[k]; len(vs) > 0 {
			return strings.Join(vs, ", ")
		}
	}
	return ""
}

// apply copies the tags onto info, filling only fields that are still empty
// so that tag sets applied earlier take precedence.
func (t tagMap) apply(info *Info) {
	set := func(dst *string, keys ...string) {
		if *dst == "" {
			*dst = t.get(keys...)
		}
	}
	set(&info.Title, "TITLE")
	set(&info.Album, "ALBUM")
	set(&info.Artist, "ARTIST")
	set(&info.AlbumArtist, "ALBUMARTIST")
	set(&info.Composer, "COMPOSER")
	set(&info.Narrator, "NARRATOR", "PERFORMER")
	set(&info.Genre, "GENRE")
	if info.Year == "" {
		info.Year = yearOf(t.get("DATE", "YEAR"))
	}
	set(&info.Comment, "COMMENT")
	set(&info.Description, "LONGDESCRIPTION", "DESCRIPTION", "SYNOPSIS")
	set(&info.Series, "SERIES", "MVNM")
	set(&info.SeriesPart, "SERIESPART", "MVIN")

	// Numbers come as "3/12" or as separate number and total tags.
	setPair := func(num, total *int, numKeys, totalKeys []string) {
		n, tot := parsePair(t.get(numKeys...))
		if tot == 0 {
			tot = leadingInt(t.get(totalKeys...))
		}
		fill(num, n)
		fill(total, tot)
	}
	setPair(&info.Track, &info.TrackTotal, []string{"TRACKNUMBER", "TRACK"}, []string{"TRACKTOTAL", "TOTALTRACKS"})
	setPair(&info.Disc, &info.DiscTotal, []string{"DISCNUMBER", "DISC"}, []string{"DISCTOTAL", "TOTALDISCS"})
}

// fill sets *dst to v when *dst still holds the zero value.
func fill[T comparable](dst *T, v T) {
	var zero T
	if *dst == zero {
		*dst = v
	}
}

// parsePair parses "3", "3/12" or " 03 / 12 " into (3, 12).
func parsePair(s string) (n, total int) {
	a, b, _ := strings.Cut(s, "/")
	return leadingInt(a), leadingInt(b)
}

// leadingInt parses the decimal digits at the start of s (after spaces).
func leadingInt(s string) int {
	s = strings.TrimSpace(s)
	n := 0
	for i := 0; i < len(s) && i < 9 && s[i] >= '0' && s[i] <= '9'; i++ {
		n = n*10 + int(s[i]-'0')
	}
	return n
}

// yearOf reduces a date such as "2011-05-03T00:00:00Z" to "2011"; anything
// that does not start with a 4-digit year is returned unchanged.
func yearOf(s string) string {
	if len(s) >= 4 && isDigits(s[:4]) && (len(s) == 4 || !isDigits(s[4:5])) {
		return s[:4]
	}
	return s
}

func isDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != ""
}

// cleanText makes a tag value safe to display: valid UTF-8, no control
// characters other than tab/newline, no stray byte-order marks, trimmed.
func cleanText(s string) string {
	s = strings.ToValidUTF8(s, "�")
	s = strings.Map(func(r rune) rune {
		if (r < 0x20 && r != '\t' && r != '\n' && r != '\r') || r == 0x7F || r == 0xFEFF {
			return -1
		}
		return r
	}, s)
	return strings.TrimSpace(s)
}

// utf16String decodes UTF-16 (a trailing odd byte is ignored).
func utf16String(b []byte, bigEndian bool) string {
	u := make([]uint16, len(b)/2)
	for i := range u {
		if bigEndian {
			u[i] = uint16(b[2*i])<<8 | uint16(b[2*i+1])
		} else {
			u[i] = uint16(b[2*i+1])<<8 | uint16(b[2*i])
		}
	}
	return string(utf16.Decode(u))
}

// bomText decodes text that is UTF-16 when it starts with a byte-order mark
// and UTF-8 (or, failing that, a legacy code page; see legacyText) otherwise.
func bomText(b []byte) string {
	switch {
	case len(b) >= 2 && b[0] == 0xFE && b[1] == 0xFF:
		return utf16String(b[2:], true)
	case len(b) >= 2 && b[0] == 0xFF && b[1] == 0xFE:
		return utf16String(b[2:], false)
	}
	return legacyText(b)
}
