package media

import (
	"encoding/binary"
	"errors"
)

// Bounds on RIFF parsing.
const (
	maxRIFFChunks = 1024
	maxRIFFList   = 1 << 20 // LIST chunks larger than this are not tag lists
)

// riffInfoKeys maps LIST/INFO chunk IDs onto tagMap keys.
var riffInfoKeys = map[string]string{
	"INAM": "TITLE",
	"IART": "ARTIST",
	"IPRD": "ALBUM",
	"ICMT": "COMMENT",
	"ICRD": "DATE",
	"IGNR": "GENRE",
	"ITRK": "TRACKNUMBER",
	"IPRT": "TRACKNUMBER",
}

// WAVE format tags whose duration follows from the byte rate exactly.
const (
	wavePCM        = 0x0001
	waveFloat      = 0x0003
	waveALaw       = 0x0006
	waveMuLaw      = 0x0007
	waveExtensible = 0xFFFE
)

func (p *prober) wav() error {
	p.info.Format = "wav"
	rf64 := string(p.src.peek(0, 4)) == "RF64"
	var (
		format      uint16
		byteRate    uint32
		haveFmt     bool
		dataSize    = int64(-1)
		ds64Data    = int64(-1)
		factSamples int64
	)
	for pos, n := int64(12), 0; pos+8 <= p.src.size && n < maxRIFFChunks; n++ {
		h := p.src.peek(pos, 8)
		if len(h) < 8 {
			break
		}
		id, size := string(h[:4]), int64(binary.LittleEndian.Uint32(h[4:8]))
		body := pos + 8
		switch id {
		case "ds64": // RF64: 64-bit RIFF size, data size and sample count
			c := cursor{b: p.src.peek(body, 24)}
			c.skip(8)
			data, samples := int64(c.u64le()), int64(c.u64le())
			if !c.bad && data >= 0 && samples >= 0 {
				ds64Data, factSamples = data, samples
			}
		case "fmt ":
			c := cursor{b: p.src.peek(body, min(size, 16))}
			format = c.u16le()
			p.info.Channels = int(c.u16le())
			p.info.SampleRate = int(c.u32le())
			byteRate = c.u32le()
			haveFmt = !c.bad
		case "fact":
			if b := p.src.peek(body, 4); len(b) == 4 && factSamples == 0 {
				factSamples = int64(binary.LittleEndian.Uint32(b))
			}
		case "data":
			if rf64 && size == 0xFFFFFFFF && ds64Data >= 0 {
				size = ds64Data
			}
			// A size of all-ones (streamed writers) or past the end of the
			// file (truncated copy) means "the rest of the file".
			if size == 0xFFFFFFFF || size > p.src.size-body {
				size = p.src.size - body
			}
			dataSize = size
		case "LIST":
			if size <= maxRIFFList {
				p.riffInfo(p.src.peek(body, size))
			}
		case "id3 ", "ID3 ":
			p.id3v2Tags(p.src.section(body, size), 0)
		}
		pos = body + size + size&1 // chunks are word aligned
	}
	if !haveFmt || dataSize < 0 {
		return errors.New("media: wav: missing fmt or data chunk")
	}
	switch format {
	case wavePCM, waveFloat, waveALaw, waveMuLaw, waveExtensible:
		if byteRate > 0 {
			p.info.Duration = float64(dataSize) / float64(byteRate)
		}
	default: // compressed: the byte rate is only an average
		if factSamples > 0 && p.info.SampleRate > 0 {
			p.info.Duration = float64(factSamples) / float64(p.info.SampleRate)
		} else if byteRate > 0 {
			p.info.Duration = float64(dataSize) / float64(byteRate)
		}
	}
	p.info.Bitrate = int(byteRate) * 8
	return nil
}

// riffInfo parses a LIST chunk of type INFO: sub-chunks holding
// NUL-terminated strings.
func (p *prober) riffInfo(b []byte) {
	if len(b) < 4 || string(b[:4]) != "INFO" {
		return
	}
	tags := p.newTagSet()
	c := cursor{b: b[4:]}
	for c.len() >= 8 {
		id := string(c.take(4))
		n := int(c.u32le())
		v := c.take(n)
		if c.bad {
			break
		}
		if key := riffInfoKeys[id]; key != "" {
			tags.add(key, legacyText(v))
		}
		if n%2 == 1 && c.len() > 0 {
			c.skip(1)
		}
	}
}
