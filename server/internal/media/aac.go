package media

import "errors"

// adtsSampleRates is indexed by the ADTS sampling frequency index.
var adtsSampleRates = [...]int{96000, 88200, 64000, 48000, 44100, 32000, 24000, 22050, 16000, 12000, 11025, 8000, 7350}

// adtsHeader is a decoded ADTS frame header.
type adtsHeader struct {
	sampleRate int
	channels   int // 0 when defined in-band by a program config element
	size       int // frame length in bytes, header included
	samples    int // 1024 per raw data block
}

// parseADTS decodes a 7-byte ADTS header: 12-bit sync, MPEG version,
// layer (always 0), protection-absent flag, profile, sampling frequency
// index, channel configuration, 13-bit frame length and the number of raw
// data blocks minus one.
func parseADTS(b []byte) (adtsHeader, bool) {
	if len(b) < 7 || b[0] != 0xFF || b[1]&0xF6 != 0xF0 {
		return adtsHeader{}, false
	}
	sf := int(b[2]>>2) & 0x0F
	if sf >= len(adtsSampleRates) {
		return adtsHeader{}, false
	}
	h := adtsHeader{
		sampleRate: adtsSampleRates[sf],
		channels:   int(b[2]&1)<<2 | int(b[3]>>6),
		size:       int(b[3]&3)<<11 | int(b[4])<<3 | int(b[5]>>5),
		samples:    1024 * (int(b[6]&3) + 1),
	}
	headerLen := 7
	if b[1]&1 == 0 { // CRC present
		headerLen = 9
	}
	return h, h.size >= headerLen
}

func isADTS(b []byte) bool {
	_, ok := parseADTS(b)
	return ok
}

// findADTS returns the first ADTS header in the first MiB after start that
// is followed by another frame with the same sample rate (or the end).
func findADTS(src *source, start, end int64) (adtsHeader, int64, bool) {
	buf := src.peek(start, min(end-start, 1<<20))
	for i := 0; i+7 <= len(buf); i++ {
		h, ok := parseADTS(buf[i:])
		if !ok {
			continue
		}
		pos := start + int64(i)
		next := pos + int64(h.size)
		if next+7 > end {
			return h, pos, true
		}
		if n, ok := parseADTS(src.peek(next, 7)); ok && n.sampleRate == h.sampleRate {
			return h, pos, true
		}
	}
	return adtsHeader{}, 0, false
}

func (p *prober) aac() error {
	p.info.Format = "aac"
	start := p.id3v2Tags(p.src, 0)
	end := p.trailingTags(p.src)
	first, pos, ok := findADTS(p.src, start, end)
	if !ok {
		return errors.New("media: aac: no ADTS frames found")
	}
	p.info.SampleRate, p.info.Channels = first.sampleRate, first.channels

	// ADTS has no duration field: sum the frames, or for streams beyond
	// maxScanBytes extrapolate from the first MiB.
	audio := end - pos
	limit := int64(maxScanBytes)
	if audio > maxScanBytes {
		limit = 1 << 20
	}
	samples, walked, limited := walkFrames(p.src, pos, end, limit, 7, func(b []byte) (int, int, bool) {
		h, ok := parseADTS(b)
		if !ok || h.sampleRate != first.sampleRate {
			return 0, 0, false
		}
		return h.size, h.samples, true
	})
	if walked == 0 {
		return errors.New("media: aac: no ADTS frames found")
	}
	p.info.Duration = float64(samples) / float64(first.sampleRate)
	if limited {
		p.info.Duration *= float64(audio) / float64(walked)
	}
	p.info.Bitrate = int(float64(audio) * 8 / p.info.Duration)
	return nil
}
