package library

import (
	"regexp"
	"sort"
	"strings"
	"unicode"
)

// Anthologies: folders that hold many separate works rather than the
// chapters of one book, such as the archive of a radio drama show where each
// file is a story by a different author ("1998/Pelevin Viktor - Zhjoltaja
// Strela.mp3", "Season 2/Аверин Никита - Часть 1. Цена победы.mp3"). Every
// work becomes a book of its own, so each story has its own place, progress
// and "finished" mark, while the folder keeps them together for browsing.

// partMarkerRE matches the part numbering of a multi-part work, wherever it
// stands in a title: "Принц Госплана (часть 2)", "Часть 1. Цена победы",
// "Story, Part 3", "Episode 2 - The End".
var partMarkerRE = regexp.MustCompile(`(?i)[\s,.:;–—-]*[(\[]?\s*(часть|частина|серия|эпизод|part|pt\.?|episode|ep\.?)\s*\d+\s*[)\]]?[\s,.:;–—-]*`)

// authorPrefixRE splits "Author - Title" file names.
var authorPrefixRE = regexp.MustCompile(`^(.+?)\s+[-–—]\s+(.+)$`)

// work is one work found in an anthology folder: its files in play order
// and, for multi-part works, the title the parts share.
type work struct {
	title string
	files []fileEntry
}

// anthologyWorks returns the works of an anthology folder, or nil when the
// files are the tracks of one book. A folder is an anthology when its files
// name several authors and no one author accounts for most of them: the
// chapters of a book share their author (a guest foreword or a mistagged
// chapter still leaves the author well above 60%), while a year of a radio
// show mixes dozens, its most frequent author rarely reaching a third. Consecutive
// files by the same author whose titles match once part numbers are removed
// are the parts of one work.
func anthologyWorks(files []fileEntry, info infoFunc) []work {
	if len(files) < 2 {
		return nil
	}
	authors := make([]string, len(files))
	known := 0
	counts := map[string]int{}
	for i, f := range files {
		authors[i] = personKey(fileAuthor(f, info))
		if authors[i] != "" {
			known++
			counts[authors[i]]++
		}
	}
	top := 0
	for _, n := range counts {
		top = max(top, n)
	}
	// Most files must name an author, at least two authors must appear, and
	// the most frequent one must own less than 60% of the files.
	if len(counts) < 2 || known*3 < len(files)*2 || top*5 >= known*3 {
		return nil
	}

	var works []work
	lastKey := ""
	for i, f := range files {
		stem := workStem(f, info)
		key := authors[i] + "\x00" + nameKey(stem)
		if n := len(works); n > 0 && stem != "" && key == lastKey {
			works[n-1].files = append(works[n-1].files, f)
			works[n-1].title = stem
			continue
		}
		works = append(works, work{files: []fileEntry{f}})
		lastKey = key
	}
	return works
}

// fileAuthor is the author of one file in an anthology: its artist tag, or
// the "Author - " prefix of its name.
func fileAuthor(f fileEntry, info infoFunc) string {
	if in := info(f.Rel); in != nil {
		if a := usablePerson(in.Artist); a != "" {
			return a
		}
	}
	return nameAuthor(f.Name)
}

// nameAuthor is the "Author - " prefix of an "Author - Title" file name, or
// "" when the name has none (or the prefix is just a number).
func nameAuthor(name string) string {
	if m := authorPrefixRE.FindStringSubmatch(fileTitle(name)); m != nil && !isNumberish(m[1]) {
		return m[1]
	}
	return ""
}

// workStem is a file's title with part numbering removed, used to tell
// whether neighbouring files are parts of one work. It prefers the title
// tag, else the file name without its "Author - " prefix.
func workStem(f fileEntry, info infoFunc) string {
	title := ""
	if in := info(f.Rel); in != nil {
		title = usableTitle(in.Title)
	}
	if title == "" {
		title = fileTitle(f.Name)
		if m := authorPrefixRE.FindStringSubmatch(title); m != nil && !isNumberish(m[1]) {
			title = m[2]
		}
	}
	return strings.TrimSpace(partMarkerRE.ReplaceAllString(title, " "))
}

// personKey normalises a person's name so that word order, case and
// punctuation do not matter: "Кори Джеймс" and "Джеймс Кори" are one author.
func personKey(s string) string {
	words := strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	})
	sort.Strings(words)
	return strings.Join(words, " ")
}

// leadingNumRE matches the running number some archives put before
// "Author - Title" ("273  Каттнер Генри - День не в счет").
var leadingNumRE = regexp.MustCompile(`^\d{1,4}[\s.)_-]+`)

// splitAuthorTitle splits an anthology work's "[NN] Author - Title" name or
// title tag into author and title. Underscored names ("Kim_Njuman_-_Egipetskaya_Alleya")
// count as spaced. It returns "" for the author when s has no such shape, so
// titles like "31 июня" or "3-D Action" are left alone.
func splitAuthorTitle(s string) (author, title string) {
	if strings.Contains(s, "_-_") || !strings.Contains(s, " ") {
		s = strings.Join(strings.Fields(strings.ReplaceAll(s, "_", " ")), " ")
	}
	rest := s
	if loc := leadingNumRE.FindStringIndex(s); loc != nil {
		rest = s[loc[1]:]
	}
	if m := authorPrefixRE.FindStringSubmatch(rest); m != nil && !isNumberish(m[1]) {
		return strings.TrimSpace(m[1]), strings.TrimSpace(m[2])
	}
	return "", s
}

// isNumberish reports whether s is only digits and punctuation ("01", "1.2").
func isNumberish(s string) bool {
	for _, r := range s {
		if unicode.IsLetter(r) {
			return false
		}
	}
	return true
}
