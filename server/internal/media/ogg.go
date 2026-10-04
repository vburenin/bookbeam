package media

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

// Ogg page layout: "OggS", version, header type, granule position (64-bit
// LE), serial (32-bit LE), sequence, CRC, segment count, segment table.
const (
	oggHeaderLen = 27
	oggBOS       = 0x02 // header type: first page of a logical stream
)

// Bounds on Ogg parsing.
const (
	maxOggStreams = 16      // beginning-of-stream pages examined
	maxOggPages   = 1 << 16 // pages followed while reassembling a packet
)

type oggPage struct {
	headerType byte
	granule    int64
	serial     uint32
	segments   []byte // lacing values
	bodyOff    int64
	bodyLen    int64
}

func (pg oggPage) end() int64 { return pg.bodyOff + pg.bodyLen }

func readOggPage(src *source, off int64) (oggPage, bool) {
	h := src.peek(off, oggHeaderLen)
	if len(h) < oggHeaderLen || string(h[:4]) != "OggS" || h[4] != 0 {
		return oggPage{}, false
	}
	nseg := int64(h[26])
	segs := src.peek(off+oggHeaderLen, nseg)
	if int64(len(segs)) < nseg {
		return oggPage{}, false
	}
	pg := oggPage{
		headerType: h[5],
		granule:    int64(binary.LittleEndian.Uint64(h[6:14])),
		serial:     binary.LittleEndian.Uint32(h[14:18]),
		segments:   segs,
		bodyOff:    off + oggHeaderLen + nseg,
	}
	for _, s := range segs {
		pg.bodyLen += int64(s)
	}
	return pg, true
}

func (p *prober) ogg() error {
	// The beginning-of-stream pages come first, each holding one stream's
	// identification header; pick the first Vorbis or Opus stream.
	var (
		serial  uint32
		preSkip int64
		off     int64
		found   bool
	)
	for range maxOggStreams {
		pg, ok := readOggPage(p.src, off)
		if !ok || pg.headerType&oggBOS == 0 {
			break
		}
		off = pg.end()
		ident := p.src.peek(pg.bodyOff, min(pg.bodyLen, 64))
		c := cursor{b: ident}
		switch {
		case bytes.HasPrefix(ident, []byte("\x01vorbis")):
			c.skip(7 + 4) // magic, version
			p.info.Format = "ogg"
			p.info.Channels = int(c.u8())
			p.info.SampleRate = int(c.u32le())
		case bytes.HasPrefix(ident, []byte("OpusHead")):
			c.skip(8 + 1) // magic, version
			p.info.Format = "opus"
			p.info.Channels = int(c.u8())
			preSkip = int64(c.u16le())
			p.info.SampleRate = 48000 // Opus always decodes at 48 kHz
		default:
			continue
		}
		if c.bad || p.info.SampleRate <= 0 {
			return errors.New("media: ogg: malformed identification header")
		}
		serial, found = pg.serial, true
		break
	}
	if !found {
		return fmt.Errorf("%w: ogg stream is neither Vorbis nor Opus", ErrUnsupported)
	}

	// The comment header is the stream's second packet.
	if pkt := p.oggPacket(off, serial); pkt != nil {
		switch {
		case bytes.HasPrefix(pkt, []byte("\x03vorbis")):
			p.vorbisComments(pkt[7:])
		case bytes.HasPrefix(pkt, []byte("OpusTags")):
			p.vorbisComments(pkt[8:])
		}
	}

	if granule, ok := lastGranule(p.src, serial); ok && granule > preSkip {
		p.info.Duration = float64(granule-preSkip) / float64(p.info.SampleRate)
		p.info.Bitrate = int(float64(p.src.size) * 8 / p.info.Duration)
	}
	return nil
}

// oggPacket reassembles the first packet of the given stream that starts at
// or after off, following it across pages. It returns nil if the packet is
// truncated or exceeds maxTagSize.
func (p *prober) oggPacket(off int64, serial uint32) []byte {
	var pkt []byte
	for range maxOggPages {
		pg, ok := readOggPage(p.src, off)
		if !ok {
			return nil
		}
		off = pg.end()
		if pg.serial != serial {
			continue
		}
		body, err := p.src.read(pg.bodyOff, pg.bodyLen)
		if err != nil {
			return nil
		}
		for _, seg := range pg.segments {
			pkt = append(pkt, body[:seg]...)
			body = body[seg:]
			if len(pkt) > maxTagSize {
				return nil
			}
			if seg < 255 { // a lacing value below 255 ends the packet
				return pkt
			}
		}
	}
	return nil
}

// lastGranule returns the granule position of the last complete page of the
// stream, searching backwards from the end of the file. Candidate pages are
// verified by CRC, so "OggS" inside packet data is never mistaken for one.
func lastGranule(src *source, serial uint32) (int64, bool) {
	for _, window := range []int64{64 << 10, 1 << 20} {
		start := max(0, src.size-window)
		buf := src.peek(start, src.size-start)
		for i := len(buf); ; {
			if i = bytes.LastIndex(buf[:i], []byte("OggS")); i < 0 {
				break
			}
			if g, ok := oggPageGranule(buf[i:], serial); ok {
				return g, true
			}
		}
		if start == 0 {
			break
		}
	}
	return 0, false
}

// oggPageGranule validates the page at the start of b (complete within b,
// matching serial, intact CRC) and returns its granule position; pages
// without one (-1) are rejected.
func oggPageGranule(b []byte, serial uint32) (int64, bool) {
	if len(b) < oggHeaderLen || b[4] != 0 {
		return 0, false
	}
	n := oggHeaderLen + int(b[26])
	if len(b) < n {
		return 0, false
	}
	for _, s := range b[oggHeaderLen:n] {
		n += int(s)
	}
	granule := int64(binary.LittleEndian.Uint64(b[6:14]))
	if len(b) < n || binary.LittleEndian.Uint32(b[14:18]) != serial || granule == -1 {
		return 0, false
	}
	crc := oggCRC(0, b[:22])
	crc = oggCRC(crc, []byte{0, 0, 0, 0}) // the CRC field counts as zero
	crc = oggCRC(crc, b[26:n])
	return granule, crc == binary.LittleEndian.Uint32(b[22:26])
}

// oggCRCTable is for Ogg's CRC-32: polynomial 0x04C11DB7, not reflected,
// zero initial value (unlike hash/crc32's IEEE variant).
var oggCRCTable = func() (t [256]uint32) {
	for i := range t {
		r := uint32(i) << 24
		for range 8 {
			if r&0x80000000 != 0 {
				r = r<<1 ^ 0x04C11DB7
			} else {
				r <<= 1
			}
		}
		t[i] = r
	}
	return t
}()

func oggCRC(crc uint32, b []byte) uint32 {
	for _, x := range b {
		crc = crc<<8 ^ oggCRCTable[byte(crc>>24)^x]
	}
	return crc
}
