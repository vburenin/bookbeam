package library

import (
	"bytes"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/vburenin/bookbeam/server/internal/media"
)

var (
	// junkTitleRE matches placeholder album/title tags, including Windows
	// Media Player's "Unknown Album (3/4/2009 9:23:15 PM)".
	junkTitleRE = regexp.MustCompile(`(?i)^(unknown|unknown album( \(.*\))?|<unknown>|untitled|track\s*\d+|audio\s?books?|неизвестн\S*( альбом)?|без названия|трек\s*\d+|аудиокниг[аи])$`)
	// junkPersonRE matches placeholder artist tags.
	junkPersonRE = regexp.MustCompile(`(?i)^(unknown|unknown artist|<unknown>|various|various artists|va|неизвестн\S*( исполнитель)?|разные исполнители|сборник)$`)
	// genericTrackTitleRE matches "Track 01"-style track titles.
	genericTrackTitleRE = regexp.MustCompile(`(?i)^(track|trk|tr|трек)?[\s._-]*\d+$`)
	// trailingYearRE captures a trailing " (YYYY)" in a folder/file name.
	trailingYearRE = regexp.MustCompile(`^(.*\S)\s*\((\d{4})\)$`)
	// leadingBookNumRE matches "01 - " / "1. " numbering in book names. At
	// most three digits: "1984 - George Orwell" is a title, not a number.
	leadingBookNumRE = regexp.MustCompile(`^\d{1,3}\s*[-.]\s+`)
	// leadingTrackNumRE matches track numbering in file names: "01 - ",
	// "01. ", "01_", "01) " or a short number followed by a space ("01 ").
	// Long bare numbers ("2001 A Space Odyssey") are left alone.
	leadingTrackNumRE = regexp.MustCompile(`^(?:\d+\s*[-–—._)]\s*|\d{1,3}\s+)`)
	// tagYearRE extracts the year from date tags such as "2011-05-03".
	tagYearRE = regexp.MustCompile(`^(\d{4})(\D|$)`)
	// editionRE matches an edition marker ending a title: "[Unabridged]",
	// "(Abridged Edition)", " - Unabridged".
	editionRE = regexp.MustCompile(`(?i)(\s*[\[(]\s*(un)?abridged(\s+(edition|version|audiobook))?\s*[\])]|(\s+[-–:,]\s*|[-–:,]\s+)(un)?abridged(\s+(edition|version|audiobook))?)\s*$`)
	// discMarkerRE matches a disc marker ending an album tag: "It (Disc 1)",
	// "Misery CD1", "Book, Part 2 of 3".
	discMarkerRE = regexp.MustCompile(`(?i)[\s,:–-]*[(\[]?(\b(cd|disc|disk|part)|(^|[\s,:(\[])(диск|часть|частина))\s*\d+(\s*(of|из|з)\s*\d+)?[)\]]?$`)
	// discLabelRE finds the disc marker in a disc folder's name.
	discLabelRE = regexp.MustCompile(`(?i)(?:\b(cd|disc|disk|part)|(диск|часть|частина))[\s._-]*0*(\d+)`)
)

// maxDescriptionBytes bounds descriptions read from text files.
const maxDescriptionBytes = 8 << 10

// clean trims a tag value and drops invalid UTF-8.
func clean(s string) string {
	return strings.TrimSpace(strings.ToValidUTF8(s, ""))
}

// usableTitle returns the cleaned tag unless it is empty or a placeholder.
func usableTitle(s string) string {
	s = clean(s)
	if junkTitleRE.MatchString(s) {
		return ""
	}
	return s
}

// bookTitleTag is a title or album tag fit to be a book title: usable and
// without an edition marker.
func bookTitleTag(s string) string {
	return usableTitle(stripEdition(clean(s)))
}

func usablePerson(s string) string {
	s = clean(s)
	if junkPersonRE.MatchString(s) {
		return ""
	}
	return s
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func stripExt(name string) string { return strings.TrimSuffix(name, filepath.Ext(name)) }

// stripEdition removes a trailing edition marker ("Hatchet [Unabridged]" ->
// "Hatchet") unless nothing would remain.
func stripEdition(s string) string {
	if t := strings.TrimSpace(editionRE.ReplaceAllString(s, "")); t != "" {
		return t
	}
	return s
}

// stripDiscMarker removes a trailing disc marker ("It (Disc 1)" -> "It")
// unless nothing would remain.
func stripDiscMarker(s string) string {
	if t := strings.TrimSpace(discMarkerRE.ReplaceAllString(s, "")); t != "" {
		return t
	}
	return s
}

// nameKey reduces a title to lower-case letters and digits, without an
// edition marker, for loose comparisons.
func nameKey(s string) string {
	s = stripEdition(s)
	var b strings.Builder
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(unicode.ToLower(r))
		}
	}
	return b.String()
}

// sameName reports whether two titles name the same thing, loosely: equal
// keys, or one containing the other ("Matilda" and "Roald Dahl - Matilda").
func sameName(a, b string) bool {
	ka, kb := nameKey(a), nameKey(b)
	if len(ka) > len(kb) {
		ka, kb = kb, ka
	}
	return ka != "" && (ka == kb || (utf8.RuneCountInString(ka) >= 4 && strings.Contains(kb, ka)))
}

// cleanName derives a title (and maybe a year) from a folder or file name:
// "Pride & Prejudice (1813)" -> ("Pride & Prejudice", "1813"),
// "03 - Caliban's War" -> ("Caliban's War", ""),
// "Hatchet [Unabridged]" -> ("Hatchet", "").
func cleanName(name string) (title, year string) {
	title = stripEdition(strings.TrimSpace(media.DecodeName(name)))
	if m := trailingYearRE.FindStringSubmatch(title); m != nil {
		title, year = stripEdition(strings.TrimSpace(m[1])), m[2]
	}
	if loc := leadingBookNumRE.FindStringIndex(title); loc != nil {
		if rest := strings.TrimSpace(title[loc[1]:]); rest != "" {
			title = rest
		}
	}
	return title, year
}

// stripAuthor removes the author from a name-derived title: "George Orwell
// - 1984" and "1984 - George Orwell" become "1984" when the tags say the
// author is George Orwell.
func stripAuthor(title, author string) string {
	if author == "" {
		return title
	}
	for _, sep := range []string{" - ", " – ", " — "} {
		if p := author + sep; len(title) > len(p) && strings.EqualFold(title[:len(p)], p) {
			return strings.TrimSpace(title[len(p):])
		}
		if s := sep + author; len(title) > len(s) && strings.EqualFold(title[len(title)-len(s):], s) {
			return strings.TrimSpace(title[:len(title)-len(s)])
		}
	}
	return title
}

// normYear reduces date tags to a year when they start with one.
func normYear(s string) string {
	s = clean(s)
	if m := tagYearRE.FindStringSubmatch(s); m != nil {
		return m[1]
	}
	return s
}

// fileTitle is a track title derived from its file name.
func fileTitle(name string) string {
	base := strings.TrimSpace(stripExt(media.DecodeName(name)))
	if loc := leadingTrackNumRE.FindStringIndex(base); loc != nil {
		if rest := strings.TrimSpace(base[loc[1]:]); rest != "" {
			return rest
		}
	}
	return base
}

// trackTitles picks a title per track: the title tag when it is meaningful
// (not "Track 01"-style, not the same for every track), else the file name
// without its numbering, unless that leaves several tracks with the same
// title ("01 Track.mp3", "02 Track.mp3").
func trackTitles(files []fileEntry, infos []*media.Info) []string {
	tag := func(i int) string {
		if infos[i] == nil {
			return ""
		}
		t := usableTitle(infos[i].Title)
		if genericTrackTitleRE.MatchString(t) {
			return ""
		}
		return t
	}
	useTags := true
	if len(files) >= 2 {
		first := tag(0)
		same := first != ""
		for i := 1; i < len(files) && same; i++ {
			same = strings.EqualFold(tag(i), first)
		}
		useTags = !same
	}
	titles := make([]string, len(files))
	fromName := make([]bool, len(files))
	named := map[string]int{}
	for i, f := range files {
		if t := tag(i); useTags && t != "" {
			titles[i] = t
		} else {
			titles[i], fromName[i] = fileTitle(f.Name), true
			named[strings.ToLower(titles[i])]++
		}
	}
	for i, f := range files {
		if fromName[i] && named[strings.ToLower(titles[i])] > 1 {
			titles[i] = strings.TrimSpace(stripExt(f.Name))
		}
	}
	return titles
}

// labelDiscTracks prefixes the track titles of a multi-disc book with their
// disc ("Disc 2 · Track 01") when titles repeat across discs, which would
// leave a chapter list of identical names.
func labelDiscTracks(spec bookSpec, titles []string) {
	if spec.Discs == nil {
		return
	}
	seen := map[string]bool{}
	repeats := false
	for _, t := range titles {
		k := strings.ToLower(t)
		repeats = repeats || seen[k]
		seen[k] = true
	}
	if !repeats {
		return
	}
	for i, f := range spec.Files {
		sub := strings.TrimPrefix(path.Dir(f.Rel), spec.Rel+"/")
		var parts []string
		for _, name := range strings.Split(sub, "/") {
			parts = append(parts, discLabel(name))
		}
		titles[i] = strings.Join(append(parts, titles[i]), " · ")
	}
}

// discLabel names a disc folder briefly: "It (Disc 02)" -> "Disc 2",
// "Dune [CD1]" -> "CD 1", "3" -> "Disc 3".
func discLabel(name string) string {
	m := discLabelRE.FindStringSubmatch(name)
	if m == nil {
		if bareDiscRE.MatchString(name) {
			return "Disc " + strings.TrimLeft(name, "0")
		}
		return name
	}
	if m[2] != "" { // Cyrillic: keep the word, capitalised ("ДИСК" -> "Диск")
		r := []rune(strings.ToLower(m[2]))
		return strings.ToUpper(string(r[0])) + string(r[1:]) + " " + m[3]
	}
	word := map[string]string{"cd": "CD", "disc": "Disc", "disk": "Disc", "part": "Part"}[strings.ToLower(m[1])]
	return word + " " + m[3]
}

// tally returns the value most of vals agree on (compared case-insensitively;
// the first spelling wins), ignoring empty ones, with its count and the
// number of non-empty values. Ties go to the value seen first.
func tally(vals []string) (best string, votes, total int) {
	counts := map[string]int{}
	var firsts []string // distinct values in order of first appearance
	for _, v := range vals {
		if v == "" {
			continue
		}
		total++
		k := strings.ToLower(v)
		if counts[k] == 0 {
			firsts = append(firsts, v)
		}
		counts[k]++
	}
	for _, v := range firsts {
		if c := counts[strings.ToLower(v)]; c > votes {
			best, votes = v, c
		}
	}
	return best, votes, total
}

// consensus is the most common non-empty value of get across the tracks.
func consensus(infos []*media.Info, get func(*media.Info) string) string {
	vals := make([]string, 0, len(infos))
	for _, in := range infos {
		if in != nil {
			vals = append(vals, get(in))
		}
	}
	best, _, _ := tally(vals)
	return best
}

// bookMeta records how a book's title was chosen, for disambiguateTitles.
type bookMeta struct {
	fromTags  bool   // the title came from tags
	nameTitle string // the title the folder or file name gives
	anthology bool   // a work of an anthology folder
}

// applyMetadata fills a book's descriptive fields from its tracks' tags
// (each field from the value most tracks agree on, so an untagged intro or
// an odd track cannot decide), falling back to folder/file names and text
// files.
func applyMetadata(b *Book, spec bookSpec, infos []*media.Info, root string) bookMeta {
	name := spec.Dir.Name
	if spec.Single {
		name = stripExt(spec.Files[0].Name)
	}
	nameTitle, nameYear := cleanName(name)

	title := tagTitle(spec, infos)
	if spec.Work != "" {
		title = spec.Work
	}
	b.Year = firstNonEmpty(consensus(infos, func(in *media.Info) string { return normYear(in.Year) }), nameYear)

	// The track artist is the author far more often than the album artist,
	// which audiobook rips use for the narrator ("Кирилл Головин") or the
	// series or show a work belongs to ("Модель Для Сборки").
	artist := consensus(infos, func(in *media.Info) string { return usablePerson(in.Artist) })
	albumArtist := consensus(infos, func(in *media.Info) string { return usablePerson(in.AlbumArtist) })
	if !strings.EqualFold(artist, firstNonEmpty(title, nameTitle)) {
		b.Author = artist
	}
	if b.Author == "" && !spec.Anthology {
		b.Author = albumArtist // an anthology's album artist is the show, not the author
	}
	if b.Author == "" && spec.Anthology {
		b.Author = nameAuthor(spec.Files[0].Name) // "Author - Title.mp3"
	}
	nameTitle = stripAuthor(nameTitle, b.Author)
	b.Title = firstNonEmpty(title, nameTitle, b.Path)
	if spec.Anthology {
		// A story's own "Author - Title" beats the artist tag, which some
		// archives fill with the show or its host ("Podcast Records").
		if a, t := splitAuthorTitle(b.Title); a != "" && t != "" {
			b.Author, b.Title = a, t
		}
	}

	b.Narrator = firstNonEmpty(
		consensus(infos, func(in *media.Info) string { return usablePerson(in.Narrator) }),
		consensus(infos, func(in *media.Info) string { return usablePerson(in.Composer) }))
	if b.Narrator == "" && !spec.Single && albumArtist != "" && !strings.EqualFold(albumArtist, b.Author) {
		b.Narrator = albumArtist // a book's second credited person is its reader
	}
	b.Series = consensus(infos, func(in *media.Info) string { return clean(in.Series) })
	b.SeriesPart = consensus(infos, func(in *media.Info) string { return clean(in.SeriesPart) })
	b.Genre = consensus(infos, func(in *media.Info) string { return clean(in.Genre) })
	b.Description = consensus(infos, func(in *media.Info) string { return clean(in.Description) })
	if b.Description == "" {
		b.Description = consensus(infos, func(in *media.Info) string {
			if c := clean(in.Comment); utf8.RuneCountInString(c) > 40 {
				return c
			}
			return ""
		})
	}

	meta := bookMeta{fromTags: title != "", nameTitle: nameTitle, anthology: spec.Anthology}
	// Text files describe the folder, so they only apply to directory books
	// (a desc.txt next to several single-file books would be ambiguous).
	if spec.Single {
		return meta
	}
	if b.Description == "" {
		for _, name := range []string{"desc.txt", "description.txt", "summary.txt"} {
			if rel, ok := spec.Dir.Texts[name]; ok {
				if d := readText(filepath.Join(root, filepath.FromSlash(rel))); d != "" {
					b.Description = d
					break
				}
			}
		}
	}
	if rel, ok := spec.Dir.Texts["reader.txt"]; ok {
		if r := readText(filepath.Join(root, filepath.FromSlash(rel))); r != "" {
			b.Narrator = firstLine(r)
		}
	}
	return meta
}

// tagTitle is the book title the tags give, or "":
//   - single-file books: the title tag, else the album;
//   - a folder holding one file: the same when the file is a whole book (an
//     .m4b, or embedded chapters); else the album first, since the title of
//     a lone mp3 may name a chapter;
//   - other folders: the album most tracks agree on. Disc rips often put the
//     disc into the album ("It (Disc 1)", "Misery CD1"); such markers are
//     dropped for multi-disc books and whenever the albums differ.
func tagTitle(spec bookSpec, infos []*media.Info) string {
	if len(spec.Files) == 1 {
		in := infos[0]
		if in == nil {
			return ""
		}
		title, album := bookTitleTag(in.Title), bookTitleTag(in.Album)
		whole := spec.Single || len(in.Chapters) >= 2 || strings.EqualFold(filepath.Ext(spec.Files[0].Name), ".m4b")
		if whole {
			return firstNonEmpty(title, album)
		}
		return firstNonEmpty(album, title)
	}

	albums := make([]string, 0, len(infos))
	for _, in := range infos {
		if in != nil {
			albums = append(albums, bookTitleTag(in.Album))
		}
	}
	best, votes, total := tally(albums)
	if spec.Discs != nil || votes < total {
		for i, a := range albums {
			if a != "" {
				albums[i] = stripDiscMarker(a)
			}
		}
		best, votes, total = tally(albums)
	}
	if votes*2 > total {
		return best
	}
	return "" // no album most tracks agree on: the folder name is a better title
}

// disambiguateTitles gives books in one folder that ended up with the same
// tag title (a series-level album such as "Harry Potter" on every volume)
// the titles their own folder or file names give, when those differ.
func disambiguateTitles(books []*Book, metas []bookMeta) {
	type key struct{ folder, title string }
	groups := map[key][]int{}
	for i, b := range books {
		k := key{b.Folder, strings.ToLower(b.Title)}
		groups[k] = append(groups[k], i)
	}
	for _, idx := range groups {
		if len(idx) < 2 {
			continue
		}
		names := map[string]bool{}
		usable := true
		for _, i := range idx {
			n := strings.ToLower(metas[i].nameTitle)
			usable = usable && metas[i].fromTags && n != "" && !names[n]
			names[n] = true
		}
		if !usable {
			continue
		}
		for _, i := range idx {
			books[i].Title = metas[i].nameTitle
			if metas[i].anthology {
				if a, t := splitAuthorTitle(metas[i].nameTitle); a != "" && t != "" {
					books[i].Author, books[i].Title = a, t
				}
			}
		}
	}
}

// readText reads at most maxDescriptionBytes of a text file, trimmed.
// Unreadable files yield "".
func readText(abs string) string {
	f, err := os.Open(abs)
	if err != nil {
		return ""
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxDescriptionBytes))
	if err != nil {
		return ""
	}
	b = bytes.TrimPrefix(b, []byte("\xef\xbb\xbf")) // UTF-8 BOM
	return clean(strings.ReplaceAll(string(b), "\r\n", "\n"))
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(s, "\n")
	return strings.TrimSpace(line)
}
