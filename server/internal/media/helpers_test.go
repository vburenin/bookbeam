package media

import (
	"bytes"
	"encoding/binary"
	"math"
	"os"
	"reflect"
	"testing"
	"unicode/utf16"
)

// probeBytes runs the native parsers on in-memory data without the panic
// recovery of ProbeFile, so that tests surface any panic directly.
func probeBytes(b []byte, ext string, opts Options) (*Info, error) {
	return probe(bytes.NewReader(b), int64(len(b)), ext, opts)
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func mustProbe(t *testing.T, b []byte, ext string, opts Options) *Info {
	t.Helper()
	info, err := probeBytes(b, ext, opts)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	return info
}

// expectFields checks every non-zero string and int field of want.
func expectFields(t *testing.T, got *Info, want Info) {
	t.Helper()
	gv, wv := reflect.ValueOf(*got), reflect.ValueOf(want)
	for i := range wv.NumField() {
		f := wv.Field(i)
		if (f.Kind() != reflect.String && f.Kind() != reflect.Int) || f.IsZero() {
			continue
		}
		if g := gv.Field(i).Interface(); g != f.Interface() {
			t.Errorf("%s = %#v, want %#v", wv.Type().Field(i).Name, g, f.Interface())
		}
	}
}

// expectDuration checks d against want within a relative tolerance.
func expectDuration(t *testing.T, got, want, tolerance float64) {
	t.Helper()
	if math.Abs(got-want) > want*tolerance {
		t.Errorf("Duration = %.4f, want %.4f (±%.1f%%)", got, want, tolerance*100)
	}
}

// expectChapters compares titles exactly and times within 0.1 s.
func expectChapters(t *testing.T, got []Chapter, want ...Chapter) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d chapters %+v, want %d %+v", len(got), got, len(want), want)
	}
	for i, w := range want {
		g := got[i]
		if g.Title != w.Title || math.Abs(g.Start-w.Start) > 0.1 || math.Abs(g.End-w.End) > 0.1 {
			t.Errorf("chapter %d = %+v, want %+v", i, g, w)
		}
	}
}

func be16(v int) []byte { return binary.BigEndian.AppendUint16(nil, uint16(v)) }
func be32(v int) []byte { return binary.BigEndian.AppendUint32(nil, uint32(v)) }
func be64(v int) []byte { return binary.BigEndian.AppendUint64(nil, uint64(v)) }
func le16(v int) []byte { return binary.LittleEndian.AppendUint16(nil, uint16(v)) }
func le32(v int) []byte { return binary.LittleEndian.AppendUint32(nil, uint32(v)) }
func le64(v int) []byte { return binary.LittleEndian.AppendUint64(nil, uint64(v)) }

func cat(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

// utf16Bytes encodes s as UTF-16 with an optional byte-order mark.
func utf16Bytes(s string, bigEndian, bom bool) []byte {
	var out []byte
	if bom {
		if bigEndian {
			out = append(out, 0xFE, 0xFF)
		} else {
			out = append(out, 0xFF, 0xFE)
		}
	}
	for _, u := range utf16.Encode([]rune(s)) {
		if bigEndian {
			out = binary.BigEndian.AppendUint16(out, u)
		} else {
			out = binary.LittleEndian.AppendUint16(out, u)
		}
	}
	return out
}

// Tiny but valid images for picture tests.
var (
	testPNG  = []byte("\x89PNG\r\n\x1a\n\x00\x00\x00\x0dIHDR fake png body")
	testJPEG = []byte("\xFF\xD8\xFF\xE0\x00\x10JFIF fake jpeg body")
)

// --- MPEG audio ---

// mpegFrame returns an MPEG-1 layer III mono 44.1 kHz frame with the given
// bitrate (kbit/s, from the standard table) and a zero payload.
func mpegFrame(kbps int) []byte {
	index := map[int]byte{32: 1, 40: 2, 48: 3, 56: 4, 64: 5, 80: 6, 96: 7, 112: 8, 128: 9, 160: 10, 192: 11, 224: 12, 256: 13, 320: 14}[kbps]
	f := make([]byte, 144*kbps*1000/44100)
	copy(f, []byte{0xFF, 0xFB, index << 4, 0xC0})
	return f
}

// mpegStream concatenates frames with the bitrates in pattern, repeated n times.
func mpegStream(n int, pattern ...int) []byte {
	var out []byte
	for range n {
		for _, kbps := range pattern {
			out = append(out, mpegFrame(kbps)...)
		}
	}
	return out
}

// xingFrame returns a 128 kbit/s frame carrying a Xing header with a frame
// count and a LAME tag with the given encoder delay and padding.
func xingFrame(tag string, frames, delay, padding int) []byte {
	f := mpegFrame(128)
	x := cat([]byte(tag), be32(0x3), be32(frames), be32(frames*417),
		[]byte("LAME3.100"), make([]byte, 12),
		[]byte{byte(delay >> 4), byte(delay<<4) | byte(padding>>8), byte(padding)})
	copy(f[4+17:], x) // mono MPEG-1: 17 bytes of side information
	return f
}

// --- ID3v2 ---

// id3TagBytes assembles an ID3v2 tag of the given version and header flags.
func id3TagBytes(version, flags byte, body ...[]byte) []byte {
	b := cat(body...)
	return cat([]byte{'I', 'D', '3', version, 0, flags}, syncsafeBytes(len(b)), b)
}

func syncsafeBytes(n int) []byte {
	return []byte{byte(n >> 21 & 0x7F), byte(n >> 14 & 0x7F), byte(n >> 7 & 0x7F), byte(n & 0x7F)}
}

// id3Frame23 builds a v2.3 frame (plain 32-bit size).
func id3Frame23(id string, flags uint16, data []byte) []byte {
	return cat([]byte(id), be32(len(data)), be16(int(flags)), data)
}

// id3Frame24 builds a v2.4 frame (synchsafe size).
func id3Frame24(id string, flags uint16, data []byte) []byte {
	return cat([]byte(id), syncsafeBytes(len(data)), be16(int(flags)), data)
}

// id3Frame22 builds a v2.2 frame (3-byte ID and size).
func id3Frame22(id string, data []byte) []byte {
	n := len(data)
	return cat([]byte(id), []byte{byte(n >> 16), byte(n >> 8), byte(n)}, data)
}

// id3Text is a text frame payload in UTF-8 (encoding 3) with NUL-separated values.
func id3Text(values ...string) []byte {
	return cat([]byte{3}, bytes.Join(func() (out [][]byte) {
		for _, v := range values {
			out = append(out, []byte(v))
		}
		return
	}(), []byte{0}))
}

// --- FLAC / Vorbis comments ---

func flacBlock(typ byte, last bool, data []byte) []byte {
	if last {
		typ |= 0x80
	}
	n := len(data)
	return cat([]byte{typ, byte(n >> 16), byte(n >> 8), byte(n)}, data)
}

func flacStreamInfoBlock(rate, channels int, samples uint64) []byte {
	b := make([]byte, 34)
	b[10] = byte(rate >> 12)
	b[11] = byte(rate >> 4)
	b[12] = byte(rate<<4) | byte(channels-1)<<1
	b[13] = byte(15<<4) | byte(samples>>32&0x0F) // 16 bits per sample
	binary.BigEndian.PutUint32(b[14:], uint32(samples))
	return b
}

func vorbisCommentData(comments ...string) []byte {
	out := cat(le32(6), []byte("tester"), le32(len(comments)))
	for _, c := range comments {
		out = cat(out, le32(len(c)), []byte(c))
	}
	return out
}

func flacPictureData(typ int, mime string, img []byte) []byte {
	return cat(be32(typ), be32(len(mime)), []byte(mime), be32(4), []byte("desc"),
		make([]byte, 16), be32(len(img)), img)
}

// --- Ogg ---

// oggPacket is one packet of an Ogg stream and the granule position at its end.
type oggPacket struct {
	data    []byte
	granule int64
}

// oggStream lays packets out in pages, as a muxer would: the first packet
// alone on a BOS page, then at most maxSegs lacing values per page. A page's
// granule is that of its last completed packet, or -1.
func oggStream(serial uint32, maxSegs int, packets ...oggPacket) []byte {
	var out []byte
	seq := uint32(0)
	flush := func(headerType byte, granule int64, segs []byte, body []byte) {
		page := cat([]byte("OggS"), []byte{0, headerType}, le64(int(granule)), le32(int(serial)),
			le32(int(seq)), le32(0), []byte{byte(len(segs))}, segs, body)
		binary.LittleEndian.PutUint32(page[22:], oggCRC(0, page))
		out = append(out, page...)
		seq++
	}
	// Identification header on its own BOS page.
	first := packets[0]
	flush(oggBOS, first.granule, lacing(len(first.data)), first.data)

	var segs, body []byte
	granule := int64(-1)
	continued := false
	for _, p := range packets[1:] {
		lace := lacing(len(p.data))
		data := p.data
		for len(lace) > 0 {
			room := maxSegs - len(segs)
			take := min(room, len(lace))
			n := 0
			for _, l := range lace[:take] {
				n += int(l)
			}
			segs, body = append(segs, lace[:take]...), append(body, data[:n]...)
			lace, data = lace[take:], data[n:]
			if len(lace) == 0 {
				granule = p.granule
			}
			if len(segs) == maxSegs {
				var ht byte
				if continued {
					ht = 1
				}
				flush(ht, granule, segs, body)
				continued = len(lace) > 0
				segs, body, granule = nil, nil, -1
			}
		}
	}
	if len(segs) > 0 {
		var ht byte
		if continued {
			ht = 1
		}
		flush(ht|0x04, granule, segs, body)
	}
	return out
}

// lacing returns the Ogg lacing values for a packet of n bytes.
func lacing(n int) []byte {
	out := bytes.Repeat([]byte{255}, n/255)
	return append(out, byte(n%255))
}

// --- RIFF ---

func riffChunk(id string, data []byte) []byte {
	out := cat([]byte(id), le32(len(data)), data)
	if len(data)%2 == 1 {
		out = append(out, 0)
	}
	return out
}

func wavFmt(format, channels, rate, bits int) []byte {
	align := channels * bits / 8
	return riffChunk("fmt ", cat(le16(format), le16(channels), le32(rate), le32(rate*align), le16(align), le16(bits)))
}

func wavFile(chunks ...[]byte) []byte {
	body := cat(chunks...)
	return cat([]byte("RIFF"), le32(4+len(body)), []byte("WAVE"), body)
}

// --- ADTS ---

// adtsFrame returns an ADTS frame (no CRC) for the sample rate index and
// channel configuration with a zero payload of n bytes.
func adtsFrame(sfIndex, channels, n int) []byte {
	size := 7 + n
	h := []byte{
		0xFF, 0xF1,
		byte(1<<6 | sfIndex<<2 | channels>>2),
		byte((channels&3)<<6 | size>>11),
		byte(size >> 3),
		byte((size&7)<<5 | 0x1F),
		0xFC,
	}
	return cat(h, make([]byte, n))
}

// --- MP4 ---

func box(typ string, payload ...[]byte) []byte {
	b := cat(payload...)
	return cat(be32(8+len(b)), []byte(typ), b)
}

func fullBox(typ string, version byte, payload ...[]byte) []byte {
	return box(typ, append([][]byte{{version, 0, 0, 0}}, payload...)...)
}

// ilstItem builds an iTunes item with one data box of the given type code.
func ilstItem(typ string, code int, value []byte) []byte {
	return box(typ, box("data", be32(code), be32(0), value))
}

// freeform builds a "----" item (mean/name/data).
func freeform(name, value string) []byte {
	return box("----", fullBox("mean", 0, []byte("com.apple.iTunes")), fullBox("name", 0, []byte(name)),
		box("data", be32(1), be32(0), []byte(value)))
}

// mvhd builds a version 0 movie header (only the fields we read).
func mvhd(timescale, duration int) []byte {
	return fullBox("mvhd", 0, be32(0), be32(0), be32(timescale), be32(duration), make([]byte, 80))
}

// mp4AudioTrak builds an audio track: tkhd, optional tref/chap, mdia with
// mdhd/hdlr and an mp4a sample description.
func mp4AudioTrak(id, timescale, duration, channels, rate int, chapterTrack int) []byte {
	var tref []byte
	if chapterTrack > 0 {
		tref = box("tref", box("chap", be32(chapterTrack)))
	}
	entry := box("mp4a", make([]byte, 6), be16(1), make([]byte, 8), be16(channels), be16(16), be16(0), be16(0), be32(rate<<16))
	return box("trak",
		fullBox("tkhd", 0, be32(0), be32(0), be32(id), make([]byte, 60)),
		tref,
		box("mdia",
			fullBox("mdhd", 0, be32(0), be32(0), be32(timescale), be32(duration), make([]byte, 4)),
			fullBox("hdlr", 0, be32(0), []byte("soun"), make([]byte, 13)),
			box("minf", box("stbl", fullBox("stsd", 0, be32(1), entry)))))
}

// mp4TextTrak builds a QuickTime text track whose samples live at the given
// file offsets, laid out by the given stsc runs (first chunk, samples per chunk).
func mp4TextTrak(id, timescale int, durations []int, sizes []int, chunkOffsets []int, runs [][2]int, wide bool) []byte {
	stts := cat(be32(len(durations)))
	for _, d := range durations {
		stts = cat(stts, be32(1), be32(d))
	}
	stsc := cat(be32(len(runs)))
	for _, r := range runs {
		stsc = cat(stsc, be32(r[0]), be32(r[1]), be32(1))
	}
	stsz := cat(be32(0), be32(len(sizes)))
	for _, s := range sizes {
		stsz = cat(stsz, be32(s))
	}
	var offsets []byte
	if wide {
		offsets = cat(be32(len(chunkOffsets)))
		for _, o := range chunkOffsets {
			offsets = cat(offsets, be64(o))
		}
		offsets = fullBox("co64", 0, offsets)
	} else {
		offsets = cat(be32(len(chunkOffsets)))
		for _, o := range chunkOffsets {
			offsets = cat(offsets, be32(o))
		}
		offsets = fullBox("stco", 0, offsets)
	}
	return box("trak",
		fullBox("tkhd", 0, be32(0), be32(0), be32(id), make([]byte, 60)),
		box("mdia",
			fullBox("mdhd", 0, be32(0), be32(0), be32(timescale), be32(0), make([]byte, 4)),
			fullBox("hdlr", 0, be32(0), []byte("text"), make([]byte, 13)),
			box("minf", box("stbl",
				fullBox("stts", 0, stts), fullBox("stsc", 0, stsc), fullBox("stsz", 0, stsz), offsets))))
}

// textSample is a QuickTime text sample: 16-bit length and the text.
func textSample(s string) []byte { return cat(be16(len(s)), []byte(s)) }
