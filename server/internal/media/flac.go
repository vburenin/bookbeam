package media

import (
	"bytes"
	"encoding/base64"
	"errors"
	"maps"
	"math"
	"slices"
	"strconv"
	"strings"
)

// FLAC metadata block types.
const (
	flacStreamInfo    = 0
	flacVorbisComment = 4
	flacPicture       = 6
	flacInvalid       = 127
)

// Bounds on FLAC / Vorbis comment structures.
const (
	maxFLACBlocks     = 1024
	maxVorbisComments = 10000
)

func (p *prober) flac() error {
	p.info.Format = "flac"
	// ID3v2 in front of FLAC is non-standard but seen in the wild: skip it.
	start := skipID3v2(p.src, 0)
	if magic := p.src.peek(start, 4); string(magic) != "fLaC" {
		return errors.New("media: flac: missing fLaC marker")
	}
	var totalSamples uint64
	pos := start + 4
	haveInfo := false
	for range maxFLACBlocks {
		h := p.src.peek(pos, 4)
		if len(h) < 4 {
			break
		}
		last, typ := h[0]&0x80 != 0, h[0]&0x7F
		size := int64(h[1])<<16 | int64(h[2])<<8 | int64(h[3])
		body := pos + 4
		if typ == flacInvalid || size > p.src.size-body {
			break
		}
		switch typ {
		case flacStreamInfo:
			var ok bool
			if totalSamples, ok = p.flacStreamInfo(p.src.peek(body, min(size, 34))); ok {
				haveInfo = true
			}
		case flacVorbisComment:
			if d, err := p.src.read(body, size); err == nil {
				p.vorbisComments(d)
			}
		case flacPicture:
			p.flacPictureBlock(body, size)
		}
		pos = body + size
		if last {
			break
		}
	}
	if !haveInfo {
		return errors.New("media: flac: missing STREAMINFO")
	}
	if p.info.SampleRate > 0 && totalSamples > 0 {
		p.info.Duration = float64(totalSamples) / float64(p.info.SampleRate)
		p.info.Bitrate = int(float64(p.src.size-pos) * 8 / p.info.Duration)
	}
	return nil
}

// flacStreamInfo decodes STREAMINFO: after the block/frame size bounds (10
// bytes) come 20 bits of sample rate, 3 bits of channels-1, 5 bits of
// bits-per-sample-1 and 36 bits of total samples (0 = unknown).
func (p *prober) flacStreamInfo(b []byte) (totalSamples uint64, ok bool) {
	if len(b) < 18 {
		return 0, false
	}
	rate := int(b[10])<<12 | int(b[11])<<4 | int(b[12])>>4
	if rate == 0 {
		return 0, false
	}
	p.info.SampleRate = rate
	p.info.Channels = int(b[12]>>1&7) + 1
	totalSamples = uint64(b[13]&0x0F)<<32 | uint64(b[14])<<24 | uint64(b[15])<<16 | uint64(b[16])<<8 | uint64(b[17])
	return totalSamples, true
}

// flacPictureBlock handles a PICTURE block, reading the image only when it
// is wanted (the picture type is the block's first 4 bytes).
func (p *prober) flacPictureBlock(off, size int64) {
	if size <= 32 || size > maxPictureSize+64<<10 {
		return
	}
	h := p.src.peek(off, 4)
	if len(h) < 4 || !p.wantPicture(int(h[0])<<24|int(h[1])<<16|int(h[2])<<8|int(h[3])) {
		return
	}
	if d, err := p.src.read(off, size); err == nil {
		if typ, mime, img, ok := parseFLACPicture(d); ok {
			p.setPicture(typ, mime, img)
		}
	}
}

// parseFLACPicture decodes the FLAC picture structure, used by PICTURE
// blocks and by Vorbis METADATA_BLOCK_PICTURE comments: type, MIME type,
// description, width/height/depth/colours and the image data (big-endian
// lengths throughout).
func parseFLACPicture(b []byte) (typ int, mime string, img []byte, ok bool) {
	c := cursor{b: b}
	typ = int(c.u32())
	mime = string(c.take(int(c.u32())))
	c.skip(int(c.u32())) // description
	c.skip(16)
	img = c.take(int(c.u32()))
	return typ, mime, img, !c.bad && len(img) > 0
}

// vorbisComments parses a Vorbis comment structure (as found in FLAC,
// Ogg Vorbis and Opus): a vendor string, then "KEY=value" entries, all with
// 32-bit little-endian lengths. Besides plain tags it understands embedded
// pictures (METADATA_BLOCK_PICTURE, legacy COVERART) and chapters
// (CHAPTER001=00:00:00.000 with CHAPTER001NAME=title).
func (p *prober) vorbisComments(b []byte) {
	c := cursor{b: b}
	c.skip(int(c.u32le())) // vendor
	n := int(c.u32le())
	tags := p.newTagSet()
	chapters := map[int]*Chapter{}
	for range min(n, maxVorbisComments) {
		entry := c.take(int(c.u32le()))
		if c.bad {
			break
		}
		key, value, ok := bytes.Cut(entry, []byte("="))
		if !ok {
			continue
		}
		k := strings.ToUpper(string(key))
		switch {
		case k == "METADATA_BLOCK_PICTURE":
			p.vorbisPicture(value)
		case k == "COVERART":
			if p.wantPicture(pictureFrontCover) {
				if img, err := base64.StdEncoding.DecodeString(string(value)); err == nil {
					p.setPicture(pictureFrontCover, "", img)
				}
			}
		case strings.HasPrefix(k, "CHAPTER") && vorbisChapter(chapters, k[len("CHAPTER"):], string(value)):
			// recorded in chapters
		default:
			tags.add(k, legacyText(value)) // UTF-8 by spec, but not always
		}
	}
	// FFmpeg and several taggers store the comment field as DESCRIPTION.
	if len(tags["COMMENT"]) == 0 {
		tags.add("COMMENT", tags["DESCRIPTION"]...)
	}
	for _, n := range slices.Sorted(maps.Keys(chapters)) {
		if ch := chapters[n]; ch.Start >= 0 {
			p.addChapter(*ch)
		}
	}
}

// vorbisPicture handles a base64 METADATA_BLOCK_PICTURE. The picture type
// is decoded from the first 8 base64 characters, so the image itself is only
// decoded when it is wanted.
func (p *prober) vorbisPicture(value []byte) {
	if len(value) < 8 || len(value) > maxPictureSize/3*4+64<<10 {
		return
	}
	var head [6]byte
	if _, err := base64.StdEncoding.Decode(head[:], value[:8]); err != nil {
		return
	}
	if !p.wantPicture(int(head[0])<<24 | int(head[1])<<16 | int(head[2])<<8 | int(head[3])) {
		return
	}
	raw, err := base64.StdEncoding.DecodeString(string(value))
	if err != nil {
		return
	}
	if typ, mime, img, ok := parseFLACPicture(raw); ok {
		p.setPicture(typ, mime, img)
	}
}

// vorbisChapter records CHAPTERnnn (start time) and CHAPTERnnnNAME (title)
// comments; rest is the key after "CHAPTER". It reports whether the key was
// a chapter key. Chapters with a name but no valid time are dropped later
// (Start stays -1).
func vorbisChapter(chapters map[int]*Chapter, rest, value string) bool {
	digits := 0
	for digits < len(rest) && rest[digits] >= '0' && rest[digits] <= '9' {
		digits++
	}
	if digits == 0 || digits > 6 {
		return false
	}
	suffix := rest[digits:]
	if suffix != "" && suffix != "NAME" {
		return suffix == "URL" // known but unused
	}
	n, _ := strconv.Atoi(rest[:digits])
	ch := chapters[n]
	if ch == nil {
		if len(chapters) >= maxChapters {
			return true
		}
		ch = &Chapter{Start: -1}
		chapters[n] = ch
	}
	if suffix == "NAME" {
		ch.Title = value
	} else if t, ok := parseClock(value); ok {
		ch.Start = t
	}
	return true
}

// parseClock parses "HH:MM:SS.sss" (also "MM:SS.sss" or plain seconds).
func parseClock(s string) (float64, bool) {
	parts := strings.Split(strings.TrimSpace(s), ":")
	if len(parts) > 3 {
		return 0, false
	}
	total := 0.0
	for _, part := range parts {
		v, err := strconv.ParseFloat(part, 64)
		if err != nil || v < 0 || math.IsInf(v, 0) || math.IsNaN(v) {
			return 0, false
		}
		total = total*60 + v
	}
	return total, true
}
