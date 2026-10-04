package library

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// NaturalCompare orders strings the way people expect file names to sort:
// case-insensitively, with runs of digits compared by numeric value
// ("Chapter 2" < "Chapter 10"). Strings that compare equal under those rules
// ("01" vs "1", "a" vs "A") fall back to a byte-wise comparison so the order
// is total and deterministic.
func NaturalCompare(a, b string) int {
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		if isDigit(a[i]) && isDigit(b[j]) {
			si := i
			for i < len(a) && isDigit(a[i]) {
				i++
			}
			sj := j
			for j < len(b) && isDigit(b[j]) {
				j++
			}
			na := strings.TrimLeft(a[si:i], "0")
			nb := strings.TrimLeft(b[sj:j], "0")
			if len(na) != len(nb) {
				return cmpInt(len(na), len(nb))
			}
			if c := strings.Compare(na, nb); c != 0 {
				return c
			}
			continue
		}
		ra, wa := utf8.DecodeRuneInString(a[i:])
		rb, wb := utf8.DecodeRuneInString(b[j:])
		if la, lb := unicode.ToLower(ra), unicode.ToLower(rb); la != lb {
			return cmpInt(int(la), int(lb))
		}
		i += wa
		j += wb
	}
	switch {
	case i < len(a):
		return 1
	case j < len(b):
		return -1
	}
	return strings.Compare(a, b)
}

// NaturalLess reports whether a sorts before b in natural order.
func NaturalLess(a, b string) bool { return NaturalCompare(a, b) < 0 }

func isDigit(c byte) bool { return '0' <= c && c <= '9' }

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}
