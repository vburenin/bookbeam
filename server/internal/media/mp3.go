package media

import (
	"bufio"
	"errors"
	"io"
)

// MPEG audio versions.
const (
	mpeg1 = iota + 1
	mpeg2
	mpeg25
)

// mpegBitrates in kbit/s, indexed by [MPEG-1 or not][layer-1][bitrate index].
var mpegBitrates = [2][3][16]int{
	{
		{0, 32, 64, 96, 128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448, 0},
		{0, 32, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384, 0},
		{0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 0},
	},
	{
		{0, 32, 48, 56, 64, 80, 96, 112, 128, 144, 160, 176, 192, 224, 256, 0},
		{0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160, 0},
		{0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160, 0},
	},
}

// mpegSampleRates indexed by [version-1][sample rate index].
var mpegSampleRates = [3][3]int{
	{44100, 48000, 32000},
	{22050, 24000, 16000},
	{11025, 12000, 8000},
}

// mpegHeader is a decoded MPEG audio frame header.
type mpegHeader struct {
	version    int // mpeg1, mpeg2 or mpeg25
	layer      int // 1..3
	bitrate    int // bits per second
	sampleRate int
	mono       bool
	size       int // frame length in bytes, header included
	samples    int // samples per channel in the frame
}

// parseMPEGHeader decodes a frame header, rejecting reserved and free-format
// values so that random data is unlikely to pass.
func parseMPEGHeader(b []byte) (mpegHeader, bool) {
	if len(b) < 4 || b[0] != 0xFF || b[1]&0xE0 != 0xE0 {
		return mpegHeader{}, false
	}
	verBits, layerBits := (b[1]>>3)&3, (b[1]>>1)&3
	brIndex, srIndex := b[2]>>4, (b[2]>>2)&3
	if verBits == 1 || layerBits == 0 || brIndex == 0 || brIndex == 15 || srIndex == 3 || b[3]&3 == 2 {
		return mpegHeader{}, false
	}
	h := mpegHeader{layer: 4 - int(layerBits), mono: b[3]>>6 == 3}
	switch verBits {
	case 3:
		h.version = mpeg1
	case 2:
		h.version = mpeg2
	default:
		h.version = mpeg25
	}
	table := 1
	if h.version == mpeg1 {
		table = 0
	}
	h.bitrate = mpegBitrates[table][h.layer-1][brIndex] * 1000
	h.sampleRate = mpegSampleRates[h.version-1][srIndex]
	padding := int(b[2]>>1) & 1
	switch {
	case h.layer == 1:
		h.samples = 384
		h.size = (12*h.bitrate/h.sampleRate + padding) * 4
	case h.layer == 3 && h.version != mpeg1:
		h.samples = 576
		h.size = 72*h.bitrate/h.sampleRate + padding
	default:
		h.samples = 1152
		h.size = 144*h.bitrate/h.sampleRate + padding
	}
	return h, true
}

func isMPEGFrame(b []byte) bool {
	_, ok := parseMPEGHeader(b)
	return ok
}

// sameStream reports whether two frames can belong to the same stream.
func (h mpegHeader) sameStream(o mpegHeader) bool {
	return h.version == o.version && h.layer == o.layer && h.sampleRate == o.sampleRate
}

// findMPEGFrame returns the first frame header in [start, min(end,
// start+limit)) that is followed by consistent frames, so sync-like bytes in
// junk or picture data are skipped. With ref set, frames must match it.
func findMPEGFrame(src *source, start, end, limit int64, ref *mpegHeader) (mpegHeader, int64, bool) {
	const window = 64 << 10
	stop := min(end, start+limit)
	for base := start; base < stop; base += window {
		buf := src.peek(base, min(window+3, end-base)) // +3: headers straddling windows
		for i := 0; i+4 <= len(buf) && base+int64(i) < stop; i++ {
			if buf[i] != 0xFF {
				continue
			}
			h, ok := parseMPEGHeader(buf[i:])
			if !ok || (ref != nil && !h.sameStream(*ref)) {
				continue
			}
			if pos := base + int64(i); confirmMPEGFrame(src, h, pos, end) {
				return h, pos, true
			}
		}
	}
	return mpegHeader{}, 0, false
}

// confirmMPEGFrame checks that the two frames after the one at pos are valid
// and match it. Reaching the end of the audio counts as success.
func confirmMPEGFrame(src *source, h mpegHeader, pos, end int64) bool {
	next := pos + int64(h.size)
	for range 2 {
		if next+4 > end {
			return true
		}
		n, ok := parseMPEGHeader(src.peek(next, 4))
		if !ok || !n.sameStream(h) {
			return false
		}
		next += int64(n.size)
	}
	return true
}

// vbrHeader is the information in a Xing/Info or VBRI header frame.
type vbrHeader struct {
	frames         int64 // audio frames, excluding the header frame itself
	bytes          int64 // audio bytes, 0 if unknown
	delay, padding int   // encoder delay and padding in samples (LAME tag)
	cbr            bool  // an "Info" header: the stream is constant-bitrate
}

// truncated reports whether the stream that starts with this header at pos
// (audio bytes up to the end of the stream) was cut short, judging by the
// byte count the header promises or, without one, by the bitrate its frame
// count implies. Encoders differ on whether the byte count includes a
// leading ID3v2 tag, so the tag is counted in the file's favour.
func (v vbrHeader) truncated(first mpegHeader, pos, audio int64) bool {
	const slack = 1.02
	if v.bytes > 0 {
		return float64(v.bytes) > float64(pos+audio)*slack
	}
	seconds := float64(v.frames*int64(first.samples)) / float64(first.sampleRate)
	implied := float64(audio) * 8 / seconds // bits per second the file can hold
	if v.cbr {
		// An Info header marks a constant-bitrate stream: every frame has the
		// header frame's bitrate.
		return implied*slack < float64(first.bitrate)
	}
	// VBR frames vary, but an average far below the header frame's bitrate
	// means frames are missing.
	return implied < float64(first.bitrate)/4
}

// parseXing reads a Xing (VBR) or Info (CBR) header with its optional LAME
// extension from the first frame.
func parseXing(frame []byte, h mpegHeader) (vbrHeader, bool) {
	off := 4 + 17 // side information follows the 4-byte header
	switch {
	case h.version == mpeg1 && !h.mono:
		off = 4 + 32
	case h.version != mpeg1 && h.mono:
		off = 4 + 9
	}
	if len(frame) < off {
		return vbrHeader{}, false
	}
	c := cursor{b: frame[off:]}
	tag := string(c.take(4))
	if tag != "Xing" && tag != "Info" {
		return vbrHeader{}, false
	}
	v := vbrHeader{cbr: tag == "Info"}
	flags := c.u32()
	if flags&1 != 0 {
		v.frames = int64(c.u32())
	}
	if flags&2 != 0 {
		v.bytes = int64(c.u32())
	}
	if c.bad {
		return vbrHeader{}, false
	}
	if flags&4 != 0 {
		c.skip(100) // seek table
	}
	if flags&8 != 0 {
		c.skip(4) // quality
	}
	// LAME extension: 9-byte encoder string; then revision, lowpass, peak,
	// two replay gains, flags and bitrate (12 bytes); then 12 bits of delay
	// and 12 bits of padding. FFmpeg writes the same layout.
	switch string(c.take(4)) {
	case "LAME", "Lavf", "Lavc":
		c.skip(5 + 12)
		if d := c.u24(); !c.bad {
			v.delay, v.padding = int(d>>12), int(d&0xFFF)
		}
	}
	return v, true
}

// parseVBRI reads a Fraunhofer VBRI header, which sits 32 bytes after the
// frame header regardless of channel mode.
func parseVBRI(frame []byte) (vbrHeader, bool) {
	if len(frame) < 36+18 || string(frame[36:40]) != "VBRI" {
		return vbrHeader{}, false
	}
	c := cursor{b: frame[40:]}
	c.skip(6) // version, delay, quality
	v := vbrHeader{bytes: int64(c.u32()), frames: int64(c.u32())}
	return v, !c.bad
}

func (p *prober) mp3() error {
	p.info.Format = "mp3"
	start := p.id3v2Tags(p.src, 0)
	end := p.trailingTags(p.src)
	if end <= start {
		return errors.New("media: mp3: no audio data")
	}
	first, pos, ok := findMPEGFrame(p.src, start, end, 1<<20, nil)
	if !ok {
		return errors.New("media: mp3: no MPEG audio frames found")
	}
	p.info.SampleRate = first.sampleRate
	p.info.Channels = 2
	if first.mono {
		p.info.Channels = 1
	}
	audio := end - pos

	head := p.src.peek(pos, 512)
	v, ok := parseXing(head, first)
	if !ok || v.frames == 0 {
		v, ok = parseVBRI(head)
	}
	if ok && v.frames > 0 {
		if !v.truncated(first, pos, audio) {
			samples := v.frames * int64(first.samples)
			if trimmed := samples - int64(v.delay+v.padding); trimmed > 0 {
				samples = trimmed
			}
			p.info.Duration = float64(samples) / float64(first.sampleRate)
			if v.bytes <= 0 || v.bytes > audio {
				v.bytes = audio
			}
			p.info.Bitrate = int(float64(v.bytes) * 8 / p.info.Duration)
			return nil
		}
		// The header describes more audio than the file holds (an interrupted
		// copy or download): measure what is really there instead. The header
		// frame itself carries no audio.
		pos += int64(first.size)
		audio = end - pos
		if audio <= 0 {
			return errors.New("media: mp3: no audio data")
		}
	}

	if isConstantBitrate(p.src, first, pos, end) {
		p.info.Duration = float64(audio) * 8 / float64(first.bitrate)
		p.info.Bitrate = first.bitrate
		return nil
	}

	// VBR without a header: count every frame.
	samples, walked, limited := walkFrames(p.src, pos, end, maxScanBytes, 4, func(b []byte) (int, int, bool) {
		h, ok := parseMPEGHeader(b)
		if !ok || !h.sameStream(first) {
			return 0, 0, false
		}
		return h.size, h.samples, true
	})
	if walked == 0 {
		return errors.New("media: mp3: no MPEG audio frames found")
	}
	p.info.Duration = float64(samples) / float64(first.sampleRate)
	if limited {
		p.info.Duration *= float64(audio) / float64(walked)
	}
	p.info.Bitrate = int(float64(audio) * 8 / p.info.Duration)
	return nil
}

// isConstantBitrate reports whether a stream without a VBR header looks
// CBR: its first frames, and frames sampled further in, share the first
// frame's bitrate. The deeper samples catch VBR files that open with
// constant-bitrate silence.
func isConstantBitrate(src *source, first mpegHeader, pos, end int64) bool {
	buf := src.peek(pos, 16<<10)
	for off, n := 0, 0; n < 10; n++ {
		h, ok := parseMPEGHeader(buf[min(off, len(buf)):])
		if !ok || !h.sameStream(first) {
			break
		}
		if h.bitrate != first.bitrate {
			return false
		}
		off += h.size
	}
	for _, quarter := range []int64{1, 2, 3} {
		at := pos + (end-pos)*quarter/4
		if h, _, ok := findMPEGFrame(src, at, end, 64<<10, &first); ok && h.bitrate != first.bitrate {
			return false
		}
	}
	return true
}

// walkFrames sums consecutive frames in [start, end), reading at most limit
// bytes. parse recognises a frame header and returns the frame size and its
// sample count. After damage, up to 64 KiB of unrecognised bytes are skipped
// to resynchronise; a longer run ends the walk (trailing junk is not audio).
// It returns the samples counted, the bytes walked, and whether the limit cut
// the walk short, in which case callers extrapolate from what was walked.
func walkFrames(src *source, start, end, limit int64, hdrLen int, parse func([]byte) (size, samples int, ok bool)) (samples, walked int64, limited bool) {
	const maxJunk = 64 << 10
	span := min(end-start, limit)
	br := bufio.NewReaderSize(io.NewSectionReader(src.r, start, span), 256<<10)
	junk := 0
	for pos := int64(0); pos+int64(hdrLen) <= span; {
		b, err := br.Peek(hdrLen)
		if err != nil {
			break
		}
		size, n, ok := parse(b)
		if !ok || size < hdrLen {
			if junk++; junk > maxJunk {
				return samples, walked, false
			}
			br.Discard(1)
			pos++
			continue
		}
		junk = 0
		if pos+int64(size) > span {
			break
		}
		if _, err := br.Discard(size); err != nil {
			break
		}
		pos += int64(size)
		samples += int64(n)
		walked = pos
	}
	return samples, walked, span < end-start
}
