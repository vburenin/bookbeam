package media

import (
	"encoding/binary"
	"errors"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Bounds on MP4 structures.
const (
	maxMP4Boxes    = 1024 // children visited per container
	maxChapterText = 1024 // bytes read per chapter-title sample
)

// mp4Keys maps iTunes-style ilst item types onto tagMap keys.
var mp4Keys = map[string]string{
	"\xa9nam": "TITLE",
	"\xa9alb": "ALBUM",
	"\xa9ART": "ARTIST",
	"aART":    "ALBUMARTIST",
	"\xa9wrt": "COMPOSER",
	"\xa9gen": "GENRE",
	"gnre":    "GENRE",
	"\xa9day": "DATE",
	"trkn":    "TRACKNUMBER",
	"disk":    "DISCNUMBER",
	"\xa9cmt": "COMMENT",
	"desc":    "DESCRIPTION",
	"ldes":    "LONGDESCRIPTION",
	"\xa9nrt": "NARRATOR",
	"\xa9mvn": "MVNM",
	"\xa9mvi": "MVIN",
}

// mp4Box locates a box's payload (the bytes after its header).
type mp4Box struct {
	typ  string
	off  int64
	size int64
}

func (b mp4Box) end() int64 { return b.off + b.size }

// isMP4TopLevel reports whether typ is a box type that starts ISO BMFF /
// QuickTime files (older QuickTime files have no ftyp).
func isMP4TopLevel(typ string) bool {
	switch typ {
	case "ftyp", "moov", "mdat", "free", "skip", "wide", "pnot":
		return true
	}
	return false
}

// eachBox calls fn for each box in [start, end) until fn returns false.
// Sizes of 0 (to the end) and 1 (64-bit size follows) are handled; a box
// claiming to extend past end is clamped, which keeps truncated files usable.
func (s *source) eachBox(start, end int64, fn func(mp4Box) bool) {
	end = min(end, s.size)
	for pos, n := start, 0; pos+8 <= end && n < maxMP4Boxes; n++ {
		h := s.peek(pos, 16)
		if len(h) < 8 {
			return
		}
		size, hdr := int64(binary.BigEndian.Uint32(h)), int64(8)
		switch size {
		case 0:
			size = end - pos
		case 1:
			if len(h) < 16 {
				return
			}
			size, hdr = int64(binary.BigEndian.Uint64(h[8:])), 16
		}
		if size < hdr {
			return
		}
		size = min(size, end-pos)
		if !fn(mp4Box{typ: string(h[4:8]), off: pos + hdr, size: size - hdr}) {
			return
		}
		pos += size
	}
}

// mp4Track is what we need to know about one trak box.
type mp4Track struct {
	id         uint32
	handler    string // "soun", "text", "vide", ...
	timescale  uint32
	duration   uint64
	chapterIDs []uint32 // tref/chap: tracks holding chapter titles
	stbl       mp4Box
	sampleRate int
	channels   int
}

func (p *prober) mp4() error {
	p.info.Format = "mp4"
	var moov mp4Box
	p.src.eachBox(0, p.src.size, func(b mp4Box) bool {
		if b.typ == "moov" {
			moov = b
			return false
		}
		return true
	})
	if moov.typ == "" {
		return errors.New("media: mp4: no moov box (truncated file?)")
	}

	var (
		timescale            uint32
		duration, fragmented uint64
		tracks               []mp4Track
		nero                 []Chapter
	)
	p.src.eachBox(moov.off, moov.end(), func(b mp4Box) bool {
		switch b.typ {
		case "mvhd":
			timescale, duration = p.mp4TimeHeader(b)
		case "mvex": // fragmented file: the overall duration lives in mehd
			p.src.eachBox(b.off, b.end(), func(m mp4Box) bool {
				if m.typ == "mehd" {
					fragmented = p.mp4FragmentDuration(m)
				}
				return true
			})
		case "trak":
			tracks = append(tracks, p.mp4Track(b))
		case "udta":
			p.src.eachBox(b.off, b.end(), func(u mp4Box) bool {
				switch u.typ {
				case "chpl":
					nero = parseNeroChapters(p.src.peek(u.off, min(u.size, 1<<20)))
				case "meta":
					p.mp4Meta(u)
				}
				return true
			})
		case "meta":
			p.mp4Meta(b)
		}
		return true
	})

	// Duration: the movie header (all-ones means unknown), else the
	// fragment duration, else the longest audio track.
	if duration == 0 || duration == 1<<32-1 || duration == 1<<64-1 {
		duration = fragmented
	}
	if timescale > 0 && duration > 0 {
		p.info.Duration = float64(duration) / float64(timescale)
	}
	var (
		audio   *mp4Track
		longest float64
	)
	for i := range tracks {
		t := &tracks[i]
		if t.handler != "soun" {
			continue
		}
		if audio == nil {
			audio = t
		}
		if t.timescale > 0 {
			longest = max(longest, float64(t.duration)/float64(t.timescale))
		}
	}
	if audio == nil {
		return errors.New("media: mp4: no audio track")
	}
	if p.info.Duration == 0 {
		p.info.Duration = longest
	}
	p.info.SampleRate, p.info.Channels = audio.sampleRate, audio.channels
	if p.info.SampleRate == 0 {
		p.info.SampleRate = int(audio.timescale)
	}
	if p.info.Duration > 0 {
		p.info.Bitrate = int(float64(p.src.size) * 8 / p.info.Duration)
	}

	// QuickTime chapter track, preferred over Nero chapters when it has at
	// least as many entries.
	var qt []Chapter
	for _, id := range audio.chapterIDs {
		for _, t := range tracks {
			if t.id == id && t.handler != "soun" && t.handler != "vide" {
				qt = p.mp4TextSamples(t)
			}
		}
		if len(qt) > 0 {
			break
		}
	}
	chapters := nero
	if len(qt) > 0 && len(qt) >= len(nero) {
		chapters = qt
	}
	for _, c := range chapters {
		p.addChapter(c)
	}
	return nil
}

// mp4TimeHeader parses an mvhd or mdhd box: after version/flags come
// creation and modification times (32 or 64 bits by version), the
// timescale and the duration.
func (p *prober) mp4TimeHeader(b mp4Box) (timescale uint32, duration uint64) {
	c := cursor{b: p.src.peek(b.off, min(b.size, 32))}
	version := c.u8()
	c.skip(3)
	if version == 1 {
		c.skip(16)
		timescale, duration = c.u32(), c.u64()
	} else {
		c.skip(8)
		timescale, duration = c.u32(), uint64(c.u32())
	}
	if c.bad {
		return 0, 0
	}
	return timescale, duration
}

// mp4FragmentDuration parses mehd (fragment duration in movie timescale).
func (p *prober) mp4FragmentDuration(b mp4Box) uint64 {
	c := cursor{b: p.src.peek(b.off, min(b.size, 12))}
	version := c.u8()
	c.skip(3)
	if version == 1 {
		return c.u64()
	}
	return uint64(c.u32())
}

func (p *prober) mp4Track(trak mp4Box) mp4Track {
	var t mp4Track
	p.src.eachBox(trak.off, trak.end(), func(b mp4Box) bool {
		switch b.typ {
		case "tkhd":
			c := cursor{b: p.src.peek(b.off, min(b.size, 32))}
			version := c.u8()
			c.skip(3)
			if version == 1 {
				c.skip(16)
			} else {
				c.skip(8)
			}
			t.id = c.u32()
		case "tref":
			p.src.eachBox(b.off, b.end(), func(r mp4Box) bool {
				if r.typ == "chap" {
					c := cursor{b: p.src.peek(r.off, min(r.size, 64))}
					for c.len() >= 4 {
						t.chapterIDs = append(t.chapterIDs, c.u32())
					}
				}
				return true
			})
		case "mdia":
			p.mp4Media(b, &t)
		}
		return true
	})
	return t
}

func (p *prober) mp4Media(mdia mp4Box, t *mp4Track) {
	p.src.eachBox(mdia.off, mdia.end(), func(b mp4Box) bool {
		switch b.typ {
		case "mdhd":
			t.timescale, t.duration = p.mp4TimeHeader(b)
		case "hdlr":
			if h := p.src.peek(b.off, 12); len(h) == 12 {
				t.handler = string(h[8:12]) // after version/flags and pre_defined
			}
		case "minf":
			p.src.eachBox(b.off, b.end(), func(m mp4Box) bool {
				if m.typ == "stbl" {
					t.stbl = m
					p.mp4SampleDescription(m, t)
				}
				return true
			})
		}
		return true
	})
}

// mp4SampleDescription reads channels and sample rate from the first
// sample entry of an audio track's stsd.
func (p *prober) mp4SampleDescription(stbl mp4Box, t *mp4Track) {
	p.src.eachBox(stbl.off, stbl.end(), func(b mp4Box) bool {
		if b.typ != "stsd" {
			return true
		}
		// version/flags, entry count, then the entry box header (8 bytes),
		// 6 reserved + 2 data reference index, version, revision, vendor,
		// channels, sample size, compression id, packet size and a 16.16
		// fixed-point sample rate. QuickTime version 2 descriptions keep
		// placeholders there (the caller falls back to the timescale).
		c := cursor{b: p.src.peek(b.off, 8+8+8+8+12)}
		c.skip(8 + 8 + 8)
		version := c.u16()
		c.skip(6)
		channels := c.u16()
		c.skip(6)
		rate := c.u32() >> 16
		if !c.bad && version < 2 {
			t.channels, t.sampleRate = int(channels), int(rate)
		}
		return false
	})
}

// mp4TextSamples reads the samples of a QuickTime text track as chapters:
// each sample is a 16-bit length followed by the title, and the sample
// durations (stts) give the start times.
func (p *prober) mp4TextSamples(t mp4Track) []Chapter {
	if t.timescale == 0 {
		return nil
	}
	tables := map[string][]byte{}
	p.src.eachBox(t.stbl.off, t.stbl.end(), func(b mp4Box) bool {
		switch b.typ {
		case "stts", "stsc", "stsz", "stco", "co64":
			// A chapter track has few samples; cap what is read in case
			// a corrupt file points at a large track.
			tables[b.typ] = p.src.peek(b.off, min(b.size, 16+12*maxChapters))
		}
		return true
	})
	sizes := mp4SampleSizes(tables["stsz"])
	offsets := mp4ChunkOffsets(tables["stco"], tables["co64"])
	if len(sizes) == 0 || len(offsets) == 0 {
		return nil
	}

	// Lay the samples out in their chunks: each stsc run gives the samples
	// per chunk from its first chunk (1-based) up to the next run's.
	runs := mp4ChunkRuns(tables["stsc"])
	starts := make([]int64, 0, len(sizes))
	for chunk, run := 0, 0; chunk < len(offsets) && len(runs) > 0 && len(starts) < len(sizes); chunk++ {
		for run+1 < len(runs) && uint32(chunk+1) >= runs[run+1].firstChunk {
			run++
		}
		off := offsets[chunk]
		for k := uint32(0); k < runs[run].perChunk && len(starts) < len(sizes); k++ {
			starts = append(starts, off)
			off += int64(sizes[len(starts)-1])
		}
	}

	var chapters []Chapter
	stts := cursor{b: tables["stts"]}
	stts.skip(4)
	entries := int(stts.u32())
	var now uint64
	sample := 0
	for e := 0; e < entries && !stts.bad && sample < len(starts); e++ {
		count, delta := stts.u32(), stts.u32()
		for k := uint32(0); k < count && sample < len(starts); k++ {
			title := ""
			if b := p.src.peek(starts[sample], min(int64(sizes[sample]), maxChapterText)); len(b) >= 2 {
				n := int(binary.BigEndian.Uint16(b))
				title = bomText(b[2:min(2+n, len(b))])
			}
			chapters = append(chapters, Chapter{
				Title: title,
				Start: float64(now) / float64(t.timescale),
				End:   float64(now+uint64(delta)) / float64(t.timescale),
			})
			now += uint64(delta)
			sample++
		}
	}
	return chapters
}

type mp4ChunkRun struct{ firstChunk, perChunk uint32 }

// mp4ChunkRuns decodes stsc (capped at maxChapters runs).
func mp4ChunkRuns(b []byte) []mp4ChunkRun {
	c := cursor{b: b}
	c.skip(4)
	count := int(min(c.u32(), maxChapters))
	var runs []mp4ChunkRun
	for range count {
		r := mp4ChunkRun{firstChunk: c.u32(), perChunk: c.u32()}
		c.skip(4) // sample description index
		if c.bad {
			break
		}
		runs = append(runs, r)
	}
	return runs
}

// mp4SampleSizes decodes stsz (capped at maxChapters samples).
func mp4SampleSizes(b []byte) []uint32 {
	c := cursor{b: b}
	c.skip(4)
	fixed, count := c.u32(), int(min(c.u32(), maxChapters))
	if c.bad {
		return nil
	}
	sizes := make([]uint32, 0, count)
	for range count {
		size := fixed
		if fixed == 0 {
			if size = c.u32(); c.bad {
				break
			}
		}
		sizes = append(sizes, size)
	}
	return sizes
}

// mp4ChunkOffsets decodes stco or co64 (capped at maxChapters chunks).
func mp4ChunkOffsets(stco, co64 []byte) []int64 {
	wide := stco == nil
	c := cursor{b: stco}
	if wide {
		c.b = co64
	}
	c.skip(4)
	count := int(min(c.u32(), maxChapters))
	var offsets []int64
	for range count {
		var off uint64
		if wide {
			off = c.u64()
		} else {
			off = uint64(c.u32())
		}
		if c.bad || off > 1<<62 {
			break
		}
		offsets = append(offsets, int64(off))
	}
	return offsets
}

// parseNeroChapters decodes a Nero chpl box: version/flags, (version 1: 4
// reserved bytes), an 8-bit count, then per chapter a start time in 100 ns
// units and a length-prefixed UTF-8 title.
func parseNeroChapters(b []byte) []Chapter {
	c := cursor{b: b}
	version := c.u8()
	c.skip(3)
	if version == 1 {
		c.skip(4)
	}
	n := int(c.u8())
	var chapters []Chapter
	for range n {
		start := c.u64()
		title := c.take(int(c.u8()))
		if c.bad {
			break
		}
		chapters = append(chapters, Chapter{Title: string(title), Start: float64(start) / 1e7})
	}
	return chapters
}

// mp4Meta parses a meta box holding an ilst item list. ISO meta is a full
// box (4 bytes of version/flags before its children); QuickTime's is not.
func (p *prober) mp4Meta(meta mp4Box) {
	start := meta.off
	if h := p.src.peek(start, 4); len(h) == 4 && binary.BigEndian.Uint32(h) == 0 {
		start += 4
	}
	var keys []string
	p.src.eachBox(start, meta.end(), func(b mp4Box) bool {
		switch b.typ {
		case "keys":
			keys = parseMP4Keys(p.src.peek(b.off, min(b.size, 1<<20)))
		case "ilst":
			p.mp4ItemList(b, keys)
		}
		return true
	})
}

// parseMP4Keys decodes a QuickTime keys box (handler "mdta", written by
// FFmpeg's use_metadata_tags and by Apple devices): version/flags, a count,
// then per key its size, a namespace and the name. ilst items then refer to
// keys by 1-based index instead of by four-character code. Reverse-DNS
// names such as "com.apple.quicktime.title" are reduced to their last part.
func parseMP4Keys(b []byte) []string {
	c := cursor{b: b}
	c.skip(4)
	n := int(c.u32())
	var keys []string
	for range min(n, maxMP4Boxes) {
		size := int(c.u32())
		c.skip(4) // namespace
		name := string(c.take(size - 8))
		if c.bad {
			break
		}
		if i := strings.LastIndexByte(name, '.'); i >= 0 {
			name = name[i+1:]
		}
		keys = append(keys, name)
	}
	return keys
}

// mp4ItemList parses ilst items: iTunes four-character codes, freeform
// "----" items, or indexes into keys (QuickTime mdta metadata).
func (p *prober) mp4ItemList(ilst mp4Box, keys []string) {
	tags := p.newTagSet()
	p.src.eachBox(ilst.off, ilst.end(), func(item mp4Box) bool {
		if item.typ == "covr" {
			p.mp4Cover(item)
			return true
		}
		key := mp4Keys[item.typ]
		if i := int(binary.BigEndian.Uint32([]byte(item.typ))); key == "" && i >= 1 && i <= len(keys) {
			key = keys[i-1]
		}
		if key == "" && item.typ != "----" {
			return true
		}
		raw, err := p.src.read(item.off, item.size)
		if err != nil {
			return true
		}
		// Children: data boxes, plus mean/name for freeform ("----") items
		// whose name is the tag key (e.g. com.apple.iTunes:SERIES).
		items := newByteSource(raw)
		var values []string
		items.eachBox(0, items.size, func(b mp4Box) bool {
			d := raw[b.off:b.end()]
			switch {
			case b.typ == "name" && len(d) >= 4:
				key = string(d[4:])
			case b.typ == "data" && len(d) >= 8:
				if v := mp4Value(item.typ, binary.BigEndian.Uint32(d)&0xFFFFFF, d[8:]); v != "" {
					values = append(values, v)
				}
			}
			return true
		})
		tags.add(key, values...)
		return true
	})
}

// mp4Value decodes the payload of a data box according to its item and its
// well-known type code (1 UTF-8, 2 UTF-16BE, 21 big-endian signed integer,
// 0 implicit).
func mp4Value(item string, typ uint32, d []byte) string {
	switch item {
	case "trkn", "disk": // reserved(2) number(2) total(2)
		if len(d) < 6 {
			return ""
		}
		n, total := binary.BigEndian.Uint16(d[2:4]), binary.BigEndian.Uint16(d[4:6])
		if total > 0 {
			return strconv.Itoa(int(n)) + "/" + strconv.Itoa(int(total))
		}
		return strconv.Itoa(int(n))
	case "gnre": // ID3v1 genre number + 1
		if len(d) < 2 {
			return ""
		}
		return genreName(strconv.Itoa(int(binary.BigEndian.Uint16(d)) - 1))
	}
	switch typ {
	case 1:
		return legacyText(d) // UTF-8 by spec, but not always
	case 2:
		return utf16String(d, true)
	case 21:
		var v int64
		switch len(d) {
		case 1:
			v = int64(int8(d[0]))
		case 2:
			v = int64(int16(binary.BigEndian.Uint16(d)))
		case 4:
			v = int64(int32(binary.BigEndian.Uint32(d)))
		case 8:
			v = int64(binary.BigEndian.Uint64(d))
		default:
			return ""
		}
		return strconv.FormatInt(v, 10)
	case 0: // implicit: some writers store text this way
		if utf8.Valid(d) {
			return string(d)
		}
	}
	return ""
}

// mp4Cover handles covr: the first image is the cover (data type 13 JPEG,
// 14 PNG, 27 BMP; the bytes are sniffed anyway).
func (p *prober) mp4Cover(covr mp4Box) {
	p.src.eachBox(covr.off, covr.end(), func(b mp4Box) bool {
		if b.typ != "data" || b.size <= 8 || b.size-8 > maxPictureSize {
			return true
		}
		if p.wantPicture(pictureFrontCover) {
			if d, err := p.src.read(b.off+8, b.size-8); err == nil {
				p.setPicture(pictureFrontCover, "", d)
			}
		}
		return false
	})
}
