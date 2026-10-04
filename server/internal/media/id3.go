package media

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"io"
	"strconv"
	"strings"
)

// ID3v2 tag header flags.
const (
	id3Unsync   = 0x80
	id3Extended = 0x40 // in v2.2 this bit means "compressed", which was never defined
	id3Footer   = 0x10
)

// ID3v2 frame format flags (second flag byte).
const (
	id3v23Compressed = 0x0080
	id3v23Encrypted  = 0x0040
	id3v23Grouped    = 0x0020
	id3v24Grouped    = 0x0040
	id3v24Compressed = 0x0008
	id3v24Encrypted  = 0x0004
	id3v24Unsync     = 0x0002
	id3v24DataLength = 0x0001
)

// Bounds on ID3 structures beyond the generic size caps.
const (
	maxID3Tags   = 8    // stacked ID3v2 tags at the start of a file
	maxID3Frames = 4096 // frames per tag
	maxTOCDepth  = 8    // nesting of CTOC frames
	smallID3Tag  = 64 << 10
)

// id3TextKeys maps the text frames we use onto tagMap keys.
var id3TextKeys = map[string]string{
	"TIT2": "TITLE",
	"TALB": "ALBUM",
	"TPE1": "ARTIST",
	"TPE2": "ALBUMARTIST",
	"TCOM": "COMPOSER",
	"TCON": "GENRE",
	"TYER": "YEAR",
	"TDRC": "DATE",
	"TRCK": "TRACKNUMBER",
	"TPOS": "DISCNUMBER",
	"TDES": "DESCRIPTION", // iTunes podcast description
	"MVNM": "MVNM",        // iTunes movement name, used for series
	"MVIN": "MVIN",        // iTunes movement number, used for series part
}

// id3v22IDs maps the three-character ID3v2.2 frame IDs we use to their
// v2.3 equivalents; v2.2 PIC differs from APIC and is special-cased.
var id3v22IDs = map[string]string{
	"TT2": "TIT2", "TAL": "TALB", "TP1": "TPE1", "TP2": "TPE2", "TCM": "TCOM",
	"TCO": "TCON", "TYE": "TYER", "TRK": "TRCK", "TPA": "TPOS", "COM": "COMM",
	"TXX": "TXXX", "PIC": "APIC",
}

type id3Header struct {
	version byte  // major version: 2, 3 or 4
	flags   byte  //
	size    int64 // tag body size: everything after the header, excluding a footer
}

// total is the full length of the tag including header and footer.
func (h id3Header) total() int64 {
	if h.version == 4 && h.flags&id3Footer != 0 {
		return 20 + h.size
	}
	return 10 + h.size
}

func readID3Header(src *source, off int64) (id3Header, bool) {
	b := src.peek(off, 10)
	if len(b) < 10 || string(b[:3]) != "ID3" || b[3] < 2 || b[3] > 4 || b[4] == 0xFF ||
		(b[6]|b[7]|b[8]|b[9])&0x80 != 0 {
		return id3Header{}, false
	}
	return id3Header{version: b[3], flags: b[5], size: syncsafe(b[6:10])}, true
}

// syncsafe decodes an ID3 "synchsafe" integer (7 bits per byte).
func syncsafe(b []byte) int64 {
	var v int64
	for _, x := range b {
		v = v<<7 | int64(x&0x7F)
	}
	return v
}

// skipID3v2 returns the offset just past any ID3v2 tags stacked at off.
func skipID3v2(src *source, off int64) int64 {
	for range maxID3Tags {
		h, ok := readID3Header(src, off)
		if !ok {
			break
		}
		off += h.total()
	}
	return off
}

// id3v2Tags parses any ID3v2 tags stacked at off and returns the offset just
// past them. Each tag gets its own tag set, so the first tag wins.
func (p *prober) id3v2Tags(src *source, off int64) int64 {
	for range maxID3Tags {
		h, ok := readID3Header(src, off)
		if !ok {
			break
		}
		p.parseID3v2(src, off, h)
		off += h.total()
	}
	return off
}

// id3Layout describes how the frames of one tag are encoded.
type id3Layout struct {
	version byte
	unsync  bool // v2.4 tag-wide unsynchronisation: applies to every frame
}

// id3Tag is the state of one ID3v2 tag being parsed.
type id3Tag struct {
	id3Layout
	p    *prober
	tags tagMap

	comment      string
	commentScore int

	chapters []id3Chapter
	tocs     map[string][]string // CTOC element ID → child element IDs
	topTOC   string
}

type id3Chapter struct {
	id         string
	start, end float64
	title      string
}

func (p *prober) parseID3v2(src *source, off int64, h id3Header) {
	if h.version == 2 && h.flags&id3Extended != 0 {
		return // compressed v2.2 tag: no compression scheme was ever specified
	}
	body := src.section(off+10, h.size)
	// v2.2/v2.3 unsynchronise the whole tag, and frame sizes refer to the
	// restored data, so such a tag must be decoded before parsing. Small
	// tags (no sizeable picture) are also read in one go rather than with
	// a read per frame; large ones are walked so images can be skipped.
	unsyncAll := h.flags&id3Unsync != 0 && h.version < 4
	if unsyncAll || body.size <= smallID3Tag {
		raw, err := body.read(0, min(body.size, maxTagSize))
		if err != nil {
			return
		}
		if unsyncAll {
			raw = removeUnsync(raw)
		}
		body = newByteSource(raw)
	}
	if h.flags&id3Extended != 0 {
		b := body.peek(0, 4)
		if len(b) < 4 {
			return
		}
		ext := syncsafe(b) // v2.4: size includes itself
		if h.version == 3 {
			ext = 4 + int64(binary.BigEndian.Uint32(b)) // v2.3: size excludes itself
		}
		body = body.section(ext, body.size-ext)
	}

	t := &id3Tag{
		id3Layout: id3Layout{version: h.version, unsync: h.version == 4 && h.flags&id3Unsync != 0},
		p:         p,
		tags:      p.newTagSet(),
		tocs:      map[string][]string{},
	}
	t.eachFrame(body, t.frame)
	t.finish()
}

// eachFrame calls fn for every frame in body, with v2.2 IDs translated to
// their v2.3 equivalents. It stops at padding or the first malformed header.
func (l id3Layout) eachFrame(body *source, fn func(body *source, id string, flags uint16, off, size int64)) {
	hdrLen := int64(10)
	if l.version == 2 {
		hdrLen = 6
	}
	pos := int64(0)
	for range maxID3Frames {
		hdr := body.peek(pos, hdrLen)
		if int64(len(hdr)) < hdrLen {
			return
		}
		var (
			id    string
			size  int64
			flags uint16
		)
		if l.version == 2 {
			if !validFrameID(hdr[:3]) {
				return
			}
			id = string(hdr[:3])
			if v23, ok := id3v22IDs[id]; ok {
				id = v23
			}
			size = int64(hdr[3])<<16 | int64(hdr[4])<<8 | int64(hdr[5])
		} else {
			if !validFrameID(hdr[:4]) {
				return
			}
			id = string(hdr[:4])
			size = int64(binary.BigEndian.Uint32(hdr[4:8]))
			if l.version == 4 {
				size = id3v24FrameSize(body, pos, hdr[4:8])
			}
			flags = binary.BigEndian.Uint16(hdr[8:10])
		}
		pos += hdrLen
		if size > body.size-pos {
			return // truncated frame
		}
		fn(body, id, flags, pos, size)
		pos += size
	}
}

func validFrameID(id []byte) bool {
	for _, c := range id {
		if (c < 'A' || c > 'Z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}

// id3v24FrameSize decodes a v2.4 frame size. The standard requires a
// synchsafe integer, but iTunes and others have written plain 32-bit sizes.
// As TagLib does, the plain reading is used when the synchsafe one does not
// land on another frame (or padding, or the end of the tag) but it does.
func id3v24FrameSize(body *source, pos int64, raw []byte) int64 {
	plain := int64(binary.BigEndian.Uint32(raw))
	if (raw[0]|raw[1]|raw[2]|raw[3])&0x80 != 0 {
		return plain // cannot be synchsafe
	}
	safe := syncsafe(raw)
	if safe < 0x80 || id3FrameBoundary(body, pos+10+safe) || !id3FrameBoundary(body, pos+10+plain) {
		return safe
	}
	return plain
}

func id3FrameBoundary(body *source, off int64) bool {
	if off == body.size {
		return true
	}
	b := body.peek(off, 4)
	return len(b) == 4 && (b[0] == 0 || validFrameID(b))
}

// frameData returns the decoded payload of a frame: grouping and length
// prefixes stripped, unsynchronisation removed, zlib compression undone.
// It reports false for encrypted or undecodable frames.
func (l id3Layout) frameData(body *source, flags uint16, off, size int64) ([]byte, bool) {
	raw, err := body.read(off, size)
	if err != nil {
		return nil, false
	}
	strip := func(n int) bool {
		if len(raw) < n {
			return false
		}
		raw = raw[n:]
		return true
	}
	compressed := false
	switch l.version {
	case 3: // extra bytes follow the header in flag order: size, method, group
		if flags&id3v23Encrypted != 0 {
			return nil, false
		}
		if flags&id3v23Compressed != 0 && !strip(4) {
			return nil, false
		}
		if flags&id3v23Grouped != 0 && !strip(1) {
			return nil, false
		}
		compressed = flags&id3v23Compressed != 0
	case 4: // extra bytes in flag order: group, method, data length
		if flags&id3v24Encrypted != 0 {
			return nil, false
		}
		if flags&id3v24Grouped != 0 && !strip(1) {
			return nil, false
		}
		if flags&id3v24DataLength != 0 && !strip(4) {
			return nil, false
		}
		if flags&id3v24Unsync != 0 || l.unsync {
			raw = removeUnsync(raw)
		}
		compressed = flags&id3v24Compressed != 0
	}
	if compressed {
		if raw, err = inflate(raw); err != nil {
			return nil, false
		}
	}
	return raw, true
}

// removeUnsync reverses ID3 unsynchronisation (0xFF 0x00 → 0xFF).
func removeUnsync(b []byte) []byte {
	if !bytes.Contains(b, []byte{0xFF, 0x00}) {
		return b
	}
	out := make([]byte, 0, len(b))
	for i := 0; i < len(b); i++ {
		out = append(out, b[i])
		if b[i] == 0xFF && i+1 < len(b) && b[i+1] == 0x00 {
			i++
		}
	}
	return out
}

// inflate decompresses zlib data, refusing output beyond maxTagSize.
func inflate(b []byte) ([]byte, error) {
	zr, err := zlib.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	out, err := io.ReadAll(io.LimitReader(zr, maxTagSize+1))
	if err != nil {
		return nil, err
	}
	if len(out) > maxTagSize {
		return nil, errTooLarge
	}
	return out, nil
}

// frame handles one top-level frame.
func (t *id3Tag) frame(body *source, id string, flags uint16, off, size int64) {
	switch id {
	case "APIC":
		t.picture(body, flags, off, size)
		return
	case "CHAP":
		t.chapter(body, flags, off, size)
		return
	case "CTOC":
		if data, ok := t.frameData(body, flags, off, size); ok {
			t.tocFrame(data)
		}
		return
	}
	if id != "COMM" && id != "TXXX" && id3TextKeys[id] == "" {
		return // not a frame we use: never read it
	}
	data, ok := t.frameData(body, flags, off, size)
	if !ok || len(data) == 0 {
		return
	}
	enc, data := data[0], data[1:]
	switch id {
	case "COMM":
		t.commentFrame(enc, data)
	case "TXXX":
		desc, value, _ := id3Cut(enc, data)
		t.tags.add(id3Decode(enc, desc), id3Strings(enc, value)...)
	case "TCON":
		t.tags.add("GENRE", id3Genres(id3Strings(enc, data))...)
	default:
		t.tags.add(id3TextKeys[id], id3Strings(enc, data)...)
	}
}

// commentFrame considers a COMM frame. Several are common (iTunes stores
// machine data such as iTunNORM in them); the one with an empty description
// is the real comment, preferably in English.
func (t *id3Tag) commentFrame(enc byte, data []byte) {
	if len(data) < 3 {
		return
	}
	lang := string(data[:3])
	desc, text, _ := id3Cut(enc, data[3:])
	d := id3Decode(enc, desc)
	value := cleanText(strings.Join(id3Strings(enc, text), ", "))
	if value == "" || strings.HasPrefix(d, "iTun") {
		return
	}
	score := 1
	if d == "" {
		score = 3
	}
	if strings.EqualFold(lang, "eng") {
		score++
	}
	if score > t.commentScore {
		t.comment, t.commentScore = value, score
	}
}

// picture handles an APIC (or v2.2 PIC) frame. Unless the image bytes are
// wanted, only the frame's leading fields are read.
func (t *id3Tag) picture(body *source, flags uint16, off, size int64) {
	if size > maxPictureSize+4096 {
		return
	}
	// Frames without format flags store the payload verbatim, so the header
	// fields can be parsed from a short peek without reading the image.
	verbatim := flags == 0 && !t.unsync
	data, total := body.peek(off, min(size, 1024)), size
	if !verbatim {
		var ok bool
		if data, ok = t.frameData(body, flags, off, size); !ok {
			return
		}
		total = int64(len(data))
	}
	loadAll := func() bool {
		if int64(len(data)) == total {
			return true
		}
		var err error
		data, err = body.read(off, size)
		return err == nil
	}
	mime, typ, imgOff, ok := t.pictureHeader(data)
	if !ok && int64(len(data)) < total && loadAll() { // description longer than the peek
		mime, typ, imgOff, ok = t.pictureHeader(data)
	}
	if !ok || mime == "-->" || int64(imgOff) >= total || total-int64(imgOff) > maxPictureSize {
		return // malformed, a URL link, no image data, or too large to use
	}
	if t.p.wantPicture(typ) && loadAll() {
		t.p.setPicture(typ, mime, data[imgOff:])
	}
}

// pictureHeader parses the fields preceding the image in an APIC/PIC frame:
// it returns the MIME type (or v2.2 image format), picture type and offset
// of the image bytes.
func (l id3Layout) pictureHeader(b []byte) (mime string, typ, imgOff int, ok bool) {
	if len(b) < 2 {
		return "", 0, 0, false
	}
	enc, rest := b[0], b[1:]
	if l.version == 2 {
		if len(rest) < 3 {
			return "", 0, 0, false
		}
		mime, rest = string(rest[:3]), rest[3:]
	} else {
		m, r, found := id3Cut(0, rest)
		if !found {
			return "", 0, 0, false
		}
		mime, rest = string(m), r
	}
	if len(rest) < 1 {
		return "", 0, 0, false
	}
	typ, rest = int(rest[0]), rest[1:]
	if _, rest, ok = id3Cut(enc, rest); !ok {
		return "", 0, 0, false
	}
	return mime, typ, len(b) - len(rest), true
}

// chapter handles a CHAP frame: element ID, start/end times in ms, byte
// offsets (unused) and embedded sub-frames, of which TIT2 is the title.
func (t *id3Tag) chapter(body *source, flags uint16, off, size int64) {
	if len(t.chapters) >= maxChapters {
		return
	}
	data, ok := t.frameData(body, flags, off, size)
	if !ok {
		return
	}
	id, rest, found := id3Cut(0, data)
	if !found || len(rest) < 16 {
		return
	}
	ch := id3Chapter{
		id:    string(id),
		start: float64(binary.BigEndian.Uint32(rest[0:4])) / 1000,
		end:   float64(binary.BigEndian.Uint32(rest[4:8])) / 1000,
	}
	// Sub-frames were already de-unsynchronised with the CHAP frame, so
	// the tag-wide flag must not be applied to them a second time.
	sub := id3Layout{version: t.version}
	sub.eachFrame(newByteSource(rest[16:]), func(b *source, fid string, fflags uint16, foff, fsize int64) {
		if fid != "TIT2" || ch.title != "" {
			return
		}
		if d, ok := sub.frameData(b, fflags, foff, fsize); ok && len(d) > 0 {
			ch.title = strings.Join(id3Strings(d[0], d[1:]), ", ")
		}
	})
	t.chapters = append(t.chapters, ch)
}

// tocFrame records a CTOC frame: element ID, flags, then child element IDs.
func (t *id3Tag) tocFrame(data []byte) {
	id, rest, found := id3Cut(0, data)
	if !found || len(rest) < 2 {
		return
	}
	flags, count, rest := rest[0], int(rest[1]), rest[2:]
	var children []string
	for range count {
		child, r, ok := id3Cut(0, rest)
		if len(child) > 0 {
			children = append(children, string(child))
		}
		if !ok {
			break
		}
		rest = r
	}
	t.tocs[string(id)] = children
	if flags&0x02 != 0 && t.topTOC == "" { // top-level table of contents
		t.topTOC = string(id)
	}
}

// finish adds the selected comment and the chapters, ordered by the
// top-level table of contents (chapters it does not list follow in frame
// order; normalisation later sorts by start time, keeping this order for ties).
func (t *id3Tag) finish() {
	t.tags.add("COMMENT", t.comment)
	if len(t.chapters) == 0 {
		return
	}
	index := make(map[string]int, len(t.chapters))
	for i, c := range t.chapters {
		if _, dup := index[c.id]; !dup {
			index[c.id] = i
		}
	}
	used := make([]bool, len(t.chapters))
	visited := map[string]bool{}
	var walk func(id string, depth int)
	walk = func(id string, depth int) {
		if i, ok := index[id]; ok {
			if !used[i] {
				used[i] = true
				t.addChapter(t.chapters[i])
			}
			return
		}
		if depth >= maxTOCDepth || visited[id] {
			return
		}
		visited[id] = true
		for _, child := range t.tocs[id] {
			walk(child, depth+1)
		}
	}
	if t.topTOC != "" {
		walk(t.topTOC, 0)
	}
	for i, c := range t.chapters {
		if !used[i] {
			t.addChapter(c)
		}
	}
}

func (t *id3Tag) addChapter(c id3Chapter) {
	t.p.addChapter(Chapter{Title: c.title, Start: c.start, End: c.end})
}

// id3Cut splits b at the first string terminator of encoding enc: one NUL
// byte, or an aligned NUL pair for UTF-16. ok is false if there is none.
func id3Cut(enc byte, b []byte) (s, rest []byte, ok bool) {
	if enc == 1 || enc == 2 {
		for i := 0; i+1 < len(b); i += 2 {
			if b[i] == 0 && b[i+1] == 0 {
				return b[:i], b[i+2:], true
			}
		}
		return b, nil, false
	}
	if i := bytes.IndexByte(b, 0); i >= 0 {
		return b[:i], b[i+1:], true
	}
	return b, nil, false
}

// id3Decode converts one ID3 string in encoding enc to UTF-8.
func id3Decode(enc byte, b []byte) string {
	bigEndian := enc == 2
	return id3DecodeBOM(enc, b, &bigEndian)
}

// id3DecodeBOM decodes one string; for UTF-16 a byte-order mark updates
// *bigEndian, which carries over to following values that lack one.
func id3DecodeBOM(enc byte, b []byte, bigEndian *bool) string {
	switch enc {
	case 1, 2:
		if len(b) >= 2 {
			switch {
			case b[0] == 0xFE && b[1] == 0xFF:
				*bigEndian, b = true, b[2:]
			case b[0] == 0xFF && b[1] == 0xFE:
				*bigEndian, b = false, b[2:]
			}
		}
		return utf16String(b, *bigEndian)
	default: // 0 = "ISO-8859-1", 3 = "UTF-8"; both are often really a Windows code page
		return legacyText(b)
	}
}

// id3Strings decodes a text payload into its NUL-separated values.
func id3Strings(enc byte, b []byte) []string {
	var out []string
	bigEndian := enc == 2 // UTF-16 without a BOM is most often little-endian
	for len(b) > 0 && len(out) < maxTagValues {
		s, rest, _ := id3Cut(enc, b)
		out = append(out, id3DecodeBOM(enc, s, &bigEndian))
		b = rest
	}
	return out
}

// id3Genres resolves numeric genre references: "(17)", "(17)Rock",
// "(17)(18)", "17" (v2.4), "(RX)"/"(CR)", with "((" escaping a literal "(".
func id3Genres(values []string) []string {
	var out []string
	for _, v := range values {
		v = strings.TrimSpace(v)
		for strings.HasPrefix(v, "(") && !strings.HasPrefix(v, "((") {
			end := strings.IndexByte(v, ')')
			if end < 0 {
				break
			}
			g := genreName(v[1:end])
			if g == "" {
				break
			}
			out = append(out, g)
			v = v[end+1:]
		}
		if strings.HasPrefix(v, "((") {
			v = v[1:]
		} else if g := genreName(v); g != "" {
			v = g
		}
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

// genreName resolves an ID3v1 genre number (or RX/CR) to its name.
func genreName(ref string) string {
	switch ref {
	case "RX":
		return "Remix"
	case "CR":
		return "Cover"
	}
	n, err := strconv.Atoi(ref)
	if err != nil || n < 0 || n >= len(id3v1Genres) {
		return ""
	}
	return id3v1Genres[n]
}

// trailingTags parses an ID3v1 tag and skips an APEv2 tag at the end of the
// data, returning where the audio ends.
func (p *prober) trailingTags(src *source) int64 {
	end := src.size
	tail := src.peek(max(0, end-160), min(end, 160))
	if n := len(tail); n >= 128 && string(tail[n-128:n-125]) == "TAG" {
		p.id3v1(tail[n-128:])
		end -= 128
		tail = tail[:n-128]
	}
	if n := len(tail); n >= 32 && string(tail[n-32:n-24]) == "APETAGEX" {
		footer := tail[n-32:]
		size := int64(binary.LittleEndian.Uint32(footer[12:16]))
		if binary.LittleEndian.Uint32(footer[20:24])&(1<<31) != 0 {
			size += 32 // a header precedes the items
		}
		if size <= end {
			end -= size
		}
	}
	return end
}

// id3v1 parses a 128-byte ID3v1 or v1.1 tag as a fallback tag set.
func (p *prober) id3v1(b []byte) {
	field := func(f []byte) string {
		if i := bytes.IndexByte(f, 0); i >= 0 {
			f = f[:i]
		}
		return legacyText(f)
	}
	t := p.newTagSet()
	t.add("TITLE", field(b[3:33]))
	t.add("ARTIST", field(b[33:63]))
	t.add("ALBUM", field(b[63:93]))
	t.add("YEAR", field(b[93:97]))
	comment := b[97:127]
	if comment[28] == 0 && comment[29] != 0 { // v1.1 track number
		t.add("TRACKNUMBER", strconv.Itoa(int(comment[29])))
		comment = comment[:28]
	}
	t.add("COMMENT", field(comment))
	// Genre 0 ("Blues") is what blank tags and many rippers leave in that
	// byte, so it means "unset" (an audiobook tagged Blues is far rarer).
	if g := int(b[127]); g > 0 && g < len(id3v1Genres) && len(t) > 0 {
		t.add("GENRE", id3v1Genres[g])
	}
}

// id3v1Genres is the ID3v1 genre list including the Winamp extensions.
var id3v1Genres = [...]string{
	"Blues", "Classic Rock", "Country", "Dance", "Disco", "Funk", "Grunge", "Hip-Hop",
	"Jazz", "Metal", "New Age", "Oldies", "Other", "Pop", "R&B", "Rap", "Reggae", "Rock",
	"Techno", "Industrial", "Alternative", "Ska", "Death Metal", "Pranks", "Soundtrack",
	"Euro-Techno", "Ambient", "Trip-Hop", "Vocal", "Jazz+Funk", "Fusion", "Trance",
	"Classical", "Instrumental", "Acid", "House", "Game", "Sound Clip", "Gospel", "Noise",
	"Alternative Rock", "Bass", "Soul", "Punk", "Space", "Meditative", "Instrumental Pop",
	"Instrumental Rock", "Ethnic", "Gothic", "Darkwave", "Techno-Industrial", "Electronic",
	"Pop-Folk", "Eurodance", "Dream", "Southern Rock", "Comedy", "Cult", "Gangsta", "Top 40",
	"Christian Rap", "Pop/Funk", "Jungle", "Native American", "Cabaret", "New Wave",
	"Psychedelic", "Rave", "Showtunes", "Trailer", "Lo-Fi", "Tribal", "Acid Punk",
	"Acid Jazz", "Polka", "Retro", "Musical", "Rock & Roll", "Hard Rock", "Folk",
	"Folk-Rock", "National Folk", "Swing", "Fast Fusion", "Bebop", "Latin", "Revival",
	"Celtic", "Bluegrass", "Avantgarde", "Gothic Rock", "Progressive Rock",
	"Psychedelic Rock", "Symphonic Rock", "Slow Rock", "Big Band", "Chorus",
	"Easy Listening", "Acoustic", "Humour", "Speech", "Chanson", "Opera", "Chamber Music",
	"Sonata", "Symphony", "Booty Bass", "Primus", "Porn Groove", "Satire", "Slow Jam",
	"Club", "Tango", "Samba", "Folklore", "Ballad", "Power Ballad", "Rhythmic Soul",
	"Freestyle", "Duet", "Punk Rock", "Drum Solo", "A Cappella", "Euro-House", "Dance Hall",
	"Goa", "Drum & Bass", "Club-House", "Hardcore Techno", "Terror", "Indie", "BritPop",
	"Afro-Punk", "Polsk Punk", "Beat", "Christian Gangsta Rap", "Heavy Metal",
	"Black Metal", "Crossover", "Contemporary Christian", "Christian Rock", "Merengue",
	"Salsa", "Thrash Metal", "Anime", "JPop", "Synthpop", "Abstract", "Art Rock", "Baroque",
	"Bhangra", "Big Beat", "Breakbeat", "Chillout", "Downtempo", "Dub", "EBM", "Eclectic",
	"Electro", "Electroclash", "Emo", "Experimental", "Garage", "Global", "IDM",
	"Illbient", "Industro-Goth", "Jam Band", "Krautrock", "Leftfield", "Lounge",
	"Math Rock", "New Romantic", "Nu-Breakz", "Post-Punk", "Post-Rock", "Psytrance",
	"Shoegaze", "Space Rock", "Trop Rock", "World Music", "Neoclassical", "Audiobook",
	"Audio Theatre", "Neue Deutsche Welle", "Podcast", "Indie Rock", "G-Funk", "Dubstep",
	"Garage Rock", "Psybient",
}
