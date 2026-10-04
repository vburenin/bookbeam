package library

import (
	"cmp"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/vburenin/bookbeam/server/internal/media"
)

var (
	// discDirRE matches disc folders: "CD 1", "Disc 02", "part3",
	// "Disk 1 of 2", "It (Disc 1)", "Dune [CD2]", "CD 01 - Chapters 1-4",
	// and the Russian/Ukrainian "Диск 1", "Часть 2 из 3", "Частина 1".
	discDirRE = regexp.MustCompile(`(?i)(^|[\s._(\[-])(cd|disc|disk|part|диск|часть|частина)[\s._-]*\d+([\s._-]*(of|из|з)[\s._-]*\d+)?[)\]]?(\s*[-–:]\s.*)?$`)
	// bareDiscRE matches folders named by a number alone ("1", "02"). They
	// are discs only when their tags say they belong to one album: such
	// names are just as often the volumes of a series.
	bareDiscRE = regexp.MustCompile(`^\d{1,3}$`)
)

// bookSpec is a grouping decision: which files form one book.
type bookSpec struct {
	Rel    string   // book path (directory, or the first file for single-file books and works)
	Dir    *dirNode // directory holding the files (the parent for single-file books)
	Single bool     // one of several books sharing Dir: a self-contained file, or a work of an anthology
	// Anthology marks a work of an anthology folder (see anthologyWorks);
	// Work is the title a multi-part work's parts share.
	Anthology bool
	Work      string
	Files     []fileEntry // tracks in play order
	Discs     []*dirNode  // merged disc folders holding the audio, in order (nil if none)
	Dirs      []*dirNode  // every folder the book spans: Dir, then part and disc folders
}

// infoFunc returns a file's probed metadata, or nil when unknown.
type infoFunc func(rel string) *media.Info

// groupBooks applies the grouping rules to the walked tree:
//
//  1. A directory with direct audio files is a book of those files.
//  2. Unless it has ≥2 audio files and they look like separate books: ≥2
//     .m4b files, every file carrying ≥2 embedded chapters, or every file
//     tagged with its own album (see separateAlbums). Then each file is its
//     own book. Loose files in the library root are always books of their own.
//  3. Otherwise, a folder of works by different authors (an anthology, see
//     anthologyWorks) yields a book per work: a file, or a run of its parts.
//  4. A directory without direct audio whose audio-bearing sub-directories
//     are all disc folders (see discFolders) is one book spanning them.
//
// Tracks play in natural file-name order unless track tags give a better
// one (see tagOrder).
func groupBooks(root *dirNode, info infoFunc) []bookSpec {
	var out []bookSpec
	var visit func(d *dirNode, isRoot bool)
	visit = func(d *dirNode, isRoot bool) {
		if len(d.Audio) > 0 {
			if isRoot || splitIntoSingles(d.Audio, info) {
				for _, f := range d.Audio {
					out = append(out, bookSpec{Rel: f.Rel, Dir: d, Single: true, Files: []fileEntry{f}, Dirs: []*dirNode{d}})
				}
			} else if works := anthologyWorks(d.Audio, info); works != nil {
				for _, w := range works {
					out = append(out, bookSpec{Rel: w.files[0].Rel, Dir: d, Single: true, Anthology: true, Work: w.title, Files: w.files, Dirs: []*dirNode{d}})
				}
			} else {
				out = append(out, bookSpec{Rel: d.Rel, Dir: d, Files: tagOrder(d.Audio, info), Dirs: []*dirNode{d}})
			}
		} else if !isRoot {
			if discs, all := discFolders(d, info, false); discs != nil {
				var files []fileEntry
				for _, disc := range discs {
					files = append(files, tagOrder(disc.Audio, info)...)
				}
				out = append(out, bookSpec{Rel: d.Rel, Dir: d, Files: files, Discs: discs, Dirs: append([]*dirNode{d}, all...)})
				return
			}
		}
		for _, sub := range d.Dirs {
			if sub.AudioBelow {
				visit(sub, false)
			}
		}
	}
	visit(root, true)
	return out
}

func splitIntoSingles(files []fileEntry, info infoFunc) bool {
	if len(files) < 2 {
		return false
	}
	m4b := 0
	allChaptered := true
	for _, f := range files {
		if strings.EqualFold(filepath.Ext(f.Name), ".m4b") {
			m4b++
		}
		if in := info(f.Rel); in == nil || len(in.Chapters) < 2 {
			allChaptered = false
		}
	}
	return m4b >= 2 || allChaptered || separateAlbums(files, info)
}

// separateAlbums reports whether files sharing a folder are separate books
// by their tags: none has embedded chapters, and each carries an album tag
// of its own (distinct once disc/part markers are removed, so "Book CD1" and
// "Book CD2" stay together) that names the file itself, matching its title
// tag or file name. A folder of Roald Dahl stories qualifies; the chapters
// of one book, sharing an album, do not.
func separateAlbums(files []fileEntry, info infoFunc) bool {
	seen := map[string]bool{}
	for _, f := range files {
		in := info(f.Rel)
		if in == nil || len(in.Chapters) >= 2 {
			return false
		}
		album := usableTitle(in.Album)
		key := nameKey(stripDiscMarker(album))
		if key == "" || seen[key] {
			return false
		}
		seen[key] = true
		if !sameName(album, in.Title) && !sameName(album, fileTitle(f.Name)) {
			return false
		}
	}
	return true
}

// discFolders decides whether d (which has no audio of its own) is one book
// spread over disc folders. Every audio-bearing sub-directory must be a disc:
// named like one (discDirRE), or all named by bare numbers ("1", "2") with
// their tracks tagged as one album. A disc holds audio directly, or (one
// level only) is a part made of discs itself: "Part 1/CD 1", "Part 1/CD 2",
// "Part 2/CD 1". It returns the folders holding the audio in play order
// (parts, then the discs inside, each in natural order) and every folder
// involved, or nil when d is not a multi-disc book.
func discFolders(d *dirNode, info infoFunc, nested bool) (discs, all []*dirNode) {
	var subs []*dirNode
	named, bare := true, true
	for _, sub := range d.Dirs {
		if !sub.AudioBelow {
			continue
		}
		subs = append(subs, sub)
		named = named && discDirRE.MatchString(sub.Name)
		bare = bare && bareDiscRE.MatchString(sub.Name)
	}
	if len(subs) == 0 || !(named || (bare && len(subs) >= 2 && oneAlbum(subs, info))) {
		return nil, nil
	}
	for _, sub := range subs {
		if len(sub.Audio) > 0 {
			for _, deeper := range sub.Dirs {
				if deeper.AudioBelow {
					return nil, nil
				}
			}
			discs, all = append(discs, sub), append(all, sub)
			continue
		}
		if nested {
			return nil, nil
		}
		inner, innerAll := discFolders(sub, info, true)
		if inner == nil {
			return nil, nil
		}
		discs = append(discs, inner...)
		all = append(append(all, sub), innerAll...)
	}
	return discs, all
}

// oneAlbum reports whether the tracks directly inside dirs all carry the same
// album tag (ignoring disc markers) and, where disc numbers are tagged, each
// folder has its own.
func oneAlbum(dirs []*dirNode, info infoFunc) bool {
	album := ""
	discs := map[int]bool{}
	for _, d := range dirs {
		disc := 0
		for _, f := range d.Audio {
			in := info(f.Rel)
			if in == nil {
				return false
			}
			key := nameKey(stripDiscMarker(usableTitle(in.Album)))
			if key == "" || (album != "" && key != album) {
				return false
			}
			album = key
			if in.Disc > 0 {
				if disc != 0 && in.Disc != disc {
					return false // one folder spanning several discs
				}
				disc = in.Disc
			}
		}
		if disc > 0 {
			if discs[disc] {
				return false
			}
			discs[disc] = true
		}
	}
	return album != ""
}

// tagOrder returns files in play order. Natural file-name order is kept when
// the names number the files (every name has digits, and no two names have
// the same digits). Otherwise, when every file has a track number tag and no
// two share a (disc, track) pair, the tags decide: "Chapter One.mp3" ...
// "Chapter Twelve.mp3", or files named after their chapter titles ("The Boy
// Who Lived.mp3"), would otherwise play alphabetically.
func tagOrder(files []fileEntry, info infoFunc) []fileEntry {
	if len(files) < 2 || namesNumberFiles(files) {
		return files
	}
	type pos struct{ disc, track int }
	keys := make(map[string]pos, len(files))
	seen := map[pos]bool{}
	for _, f := range files {
		in := info(f.Rel)
		if in == nil || in.Track <= 0 {
			return files
		}
		p := pos{in.Disc, in.Track}
		if seen[p] {
			return files
		}
		seen[p] = true
		keys[f.Rel] = p
	}
	out := slices.Clone(files)
	slices.SortStableFunc(out, func(a, b fileEntry) int {
		pa, pb := keys[a.Rel], keys[b.Rel]
		return cmp.Or(cmp.Compare(pa.disc, pb.disc), cmp.Compare(pa.track, pb.track))
	})
	return out
}

// namesNumberFiles reports whether every file name (without extension)
// contains digits and no two names carry the same sequence of numbers.
func namesNumberFiles(files []fileEntry) bool {
	seen := map[string]bool{}
	for _, f := range files {
		nums := digitRuns(stripExt(f.Name))
		if nums == "" || seen[nums] {
			return false
		}
		seen[nums] = true
	}
	return true
}

// digitRuns lists the numbers in s, without leading zeros: "CD 01 - 7" ->
// "1 7".
func digitRuns(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		if !isDigit(s[i]) {
			i++
			continue
		}
		j := i
		for j < len(s) && isDigit(s[j]) {
			j++
		}
		n := strings.TrimLeft(s[i:j], "0")
		if n == "" {
			n = "0"
		}
		if b.Len() > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(n)
		i = j
	}
	return b.String()
}
