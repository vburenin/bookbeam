package media

import (
	"bytes"
	"encoding/base64"
	"errors"
	"math"
	"math/rand/v2"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// corpus returns structurally rich inputs for every parser: the committed
// fixtures plus synthetic files exercising the less common code paths.
// Keys carry the extension passed to the prober.
func corpus(t testing.TB) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	for _, name := range []string{"chapters.mp3", "book.m4b", "tagged.opus"} {
		b, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			t.Fatal(err)
		}
		out[name] = b
	}

	chap := id3Frame24("CHAP", 0, cat([]byte("c0\x00"), be32(0), be32(1000), be32(-1), be32(-1), id3Frame24("TIT2", 0, id3Text("Ch"))))
	out["id3v24-vbr.mp3"] = cat(
		id3TagBytes(4, id3Footer|id3Unsync, id3Frame24("TIT2", id3v24DataLength, cat(syncsafeBytes(4), id3Text("abc"))),
			id3Frame24("TCOM", id3v24Compressed, zlibBytes(id3Text("zip"))), chap,
			id3Frame24("CTOC", 0, []byte("t\x00\x03\x01c0\x00")),
			id3Frame24("APIC", 0, apic("image/png", 3, testPNG))),
		[]byte("3DI\x04\x00\x10\x00\x00\x00\x00"),
		xingFrame("Xing", 30, 576, 300), mpegStream(10, 128, 64, 320))
	out["id3v23-unsync.mp3"] = cat(id3TagBytes(3, id3Unsync|id3Extended,
		unsync(cat(be32(6), make([]byte, 6), id3Frame23("APIC", 0, apic("image/jpeg", 3, testJPEG)),
			id3Frame23("COMM", 0, commFrame(1, "eng", "", "x")), id3Frame23("TXXX", 0, txxx("SERIES", "s"))))),
		mpegStream(30, 128), cat([]byte("TAG"), make([]byte, 125)))
	out["id3v22.mp3"] = cat(id3TagBytes(2, 0, id3Frame22("TT2", id3Text("t")), id3Frame22("PIC", cat([]byte{0}, []byte("PNG\x03d\x00"), testPNG))),
		mpegStream(20, 128))
	picture := "METADATA_BLOCK_PICTURE=" + base64.StdEncoding.EncodeToString(flacPictureData(3, "image/png", testPNG))
	out["comments.flac"] = cat([]byte("fLaC"),
		flacBlock(flacStreamInfo, false, flacStreamInfoBlock(44100, 2, 44100*60)),
		flacBlock(flacVorbisComment, false, vorbisCommentData("TITLE=t", picture, "CHAPTER001=00:00:01.000", "CHAPTER001NAME=c")),
		flacBlock(flacPicture, true, flacPictureData(3, "image/jpeg", testJPEG)), make([]byte, 256))
	out["vorbis.ogg"] = oggStream(5, 4,
		oggPacket{vorbisIdent(2, 44100), 0},
		oggPacket{cat([]byte("\x03vorbis"), vorbisCommentData("TITLE=o", picture), []byte{1}), 0},
		oggPacket{make([]byte, 600), 44100},
		oggPacket{make([]byte, 600), 88200})
	out["opus.opus"] = oggStream(6, 255, oggPacket{opusHead(1, 312), 0},
		oggPacket{cat([]byte("OpusTags"), vorbisCommentData("title=x")), 0}, oggPacket{make([]byte, 100), 96312})
	out["info.wav"] = wavFile(wavFmt(1, 2, 44100, 16), riffChunk("LIST", cat([]byte("INFO"), riffChunk("INAM", []byte("w\x00")))),
		riffChunk("id3 ", id3TagBytes(3, 0, id3Frame23("TIT2", 0, id3Text("i")))), riffChunk("data", make([]byte, 1000)))
	out["rf64.wav"] = cat([]byte("RF64"), le32(-1), []byte("WAVE"), riffChunk("ds64", cat(le64(0), le64(800), le64(0), le32(0))),
		wavFmt(1, 1, 8000, 16), cat([]byte("data"), le32(-1), make([]byte, 800)))
	var adts []byte
	for range 40 {
		adts = append(adts, adtsFrame(4, 2, 150)...)
	}
	out["stream.aac"] = cat(id3TagBytes(4, 0, id3Frame24("TIT2", 0, id3Text("a"))), adts)
	ilst := box("ilst", ilstItem("\xa9nam", 1, []byte("m")), freeform("SERIES", "s"), ilstItem("trkn", 0, make([]byte, 8)),
		box("covr", box("data", be32(14), be32(0), testPNG)))
	keys := fullBox("keys", 0, be32(1), cat(be32(13), []byte("mdtatitle")))
	out["book.m4b"+"-synthetic"] = mp4Book(t, []string{"a", "b", "c"}, []int{10, 20, 30}, true,
		box("udta", fullBox("meta", 0, ilst), fullBox("chpl", 0, []byte{1}, be64(0), []byte{1, 'x'})),
		box("meta", box("hdlr"), keys, box("ilst", box(string(be32(1)), box("data", be32(1), be32(0), []byte("k"))))),
		box("mvex", fullBox("mehd", 1, be64(5))))
	return out
}

// extOf returns the extension a corpus key implies.
func extOf(name string) string {
	name, _, _ = strings.Cut(name, "-synthetic")
	return filepath.Ext(name)
}

// checkInvariants verifies properties every successful probe must have,
// however damaged the input.
func checkInvariants(t *testing.T, label string, info *Info) {
	t.Helper()
	if math.IsNaN(info.Duration) || math.IsInf(info.Duration, 0) || info.Duration < 0 {
		t.Errorf("%s: Duration = %v", label, info.Duration)
	}
	for i, c := range info.Chapters {
		if c.Title == "" || c.Start < 0 || c.End < c.Start || (i > 0 && c.Start <= info.Chapters[i-1].Start) {
			t.Errorf("%s: bad chapter %d %+v", label, i, c)
		}
	}
	if info.Picture != nil && (!info.HasPicture || len(info.Picture.Data) == 0 || len(info.Picture.Data) > maxPictureSize || info.Picture.MIME == "") {
		t.Errorf("%s: bad picture (HasPicture=%v, %d bytes, %q)", label, info.HasPicture, len(info.Picture.Data), info.Picture.MIME)
	}
	for _, s := range []string{info.Title, info.Album, info.Artist, info.Comment, info.Description, info.Genre} {
		if !utf8.ValidString(s) {
			t.Errorf("%s: invalid UTF-8 %q", label, s)
		}
	}
}

// probeNoPanic probes data with both picture settings; probe (unlike
// ProbeFile) does not recover, so any panic fails the test with its stack.
func probeNoPanic(t *testing.T, label string, data []byte, ext string) {
	t.Helper()
	for _, opts := range []Options{{}, {WantPicture: true}} {
		if info, err := probeBytes(data, ext, opts); err == nil {
			checkInvariants(t, label, info)
		}
	}
}

func TestCorpusProbesCleanly(t *testing.T) {
	for name, data := range corpus(t) {
		info := mustProbe(t, data, extOf(name), Options{WantPicture: true})
		checkInvariants(t, name, info)
		if info.Duration <= 0 {
			t.Errorf("%s: no duration", name)
		}
	}
}

func TestTruncatedInputs(t *testing.T) {
	for name, data := range corpus(t) {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			cuts := map[int]bool{}
			for i := range min(len(data), 1024) { // every cut through the headers
				cuts[i] = true
			}
			for i := range 257 { // and evenly spread ones through the rest
				cuts[len(data)*i/256] = true
			}
			for cut := range cuts {
				probeNoPanic(t, name, data[:cut], extOf(name))
			}
		})
	}
}

func TestCorruptedInputs(t *testing.T) {
	iterations := 400
	if testing.Short() {
		iterations = 50
	}
	for name, data := range corpus(t) {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			rng := rand.New(rand.NewPCG(uint64(len(data)), 42))
			for range iterations {
				m := bytes.Clone(data)
				for range 1 + rng.IntN(8) {
					pos := rng.IntN(len(m))
					if rng.IntN(2) == 0 { // headers live near the start
						pos = rng.IntN(min(len(m), 4096))
					}
					switch rng.IntN(4) {
					case 0:
						m[pos] ^= 1 << rng.IntN(8)
					case 1:
						m[pos] = 0xFF
					case 2:
						m[pos] = 0
					default: // a huge length field
						copy(m[pos:], []byte{0x7F, 0xFF, 0xFF, 0xFF})
					}
				}
				probeNoPanic(t, name, m, extOf(name))
			}
		})
	}
}

func TestGarbageInputs(t *testing.T) {
	prefixes := []string{
		"", "ID3\x04\x00\x00", "ID3\x03\x00\x80", "ID3\x02\x00\x00", "ID3\x04\x00\x50", "fLaC", "OggS\x00\x02",
		"RIFF\x00\x00\x00\x00WAVE", "RF64\xff\xff\xff\xffWAVE", "\x00\x00\x00\x18ftypM4A ", "\x00\x00\x00\x00moov",
		"\x00\x00\x00\x01mdat", "\xFF\xFB\x90\xC0", "\xFF\xF1\x50\x80", "\x1A\x45\xDF\xA3",
	}
	exts := []string{"", ".mp3", ".aac", ".m4b", ".ogg"}
	rng := rand.New(rand.NewPCG(7, 7))
	for _, prefix := range prefixes {
		for i := range 200 {
			tail := make([]byte, rng.IntN(4096))
			for j := range tail {
				tail[j] = byte(rng.Uint32())
			}
			probeNoPanic(t, prefix, cat([]byte(prefix), tail), exts[i%len(exts)])
		}
	}
}

func TestHugeDeclaredSizesStayBounded(t *testing.T) {
	ftyp := box("ftyp", []byte("M4A "), be32(0))
	inputs := map[string][]byte{
		"id3 tag and frame": cat([]byte("ID3\x04\x00\x00\x7F\x7F\x7F\x7F"), []byte("APIC"), syncsafeBytes(200<<20), be16(0), make([]byte, 64)),
		"id3 unsync tag":    cat([]byte("ID3\x03\x00\x80\x7F\x7F\x7F\x7F"), make([]byte, 64)),
		"flac block":        cat([]byte("fLaC"), []byte{0x04, 0xFF, 0xFF, 0xFF}, make([]byte, 64)),
		"vorbis counts":     cat([]byte("fLaC"), flacBlock(flacStreamInfo, false, flacStreamInfoBlock(8000, 1, 8000)), flacBlock(flacVorbisComment, true, cat(le32(0), le32(-1), le32(-1)))),
		"mp4 largesize":     cat(ftyp, be32(1), []byte("moov"), be64(1<<62), make([]byte, 64)),
		"mp4 tables":        cat(ftyp, box("moov", mvhd(1000, 1000), mp4AudioTrak(1, 1000, 1000, 1, 8000, 2), box("trak", fullBox("tkhd", 0, be32(0), be32(0), be32(2)), box("mdia", fullBox("mdhd", 0, be32(0), be32(0), be32(1000), be32(0)), fullBox("hdlr", 0, be32(0), []byte("text")), box("minf", box("stbl", fullBox("stsz", 0, be32(0), be32(-1)), fullBox("stco", 0, be32(-1)), fullBox("stts", 0, be32(-1)), fullBox("stsc", 0, be32(-1)))))))),
		"mp4 keys":          cat(ftyp, box("moov", box("meta", box("hdlr"), fullBox("keys", 0, be32(-1), be32(-1))))),
		"ogg segments":      cat([]byte("OggS\x00\x02"), make([]byte, 20), []byte{255}, bytes.Repeat([]byte{255}, 255)),
		"wav list":          cat([]byte("RIFF\x00\x00\x00\x00WAVE"), []byte("LIST"), le32(-16), make([]byte, 64)),
	}
	for name, data := range inputs {
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		probeNoPanic(t, name, data, "")
		runtime.ReadMemStats(&after)
		if alloc := after.TotalAlloc - before.TotalAlloc; alloc > 2<<20 {
			t.Errorf("%s: allocated %d bytes for a %d-byte input", name, alloc, len(data))
		}
	}
}

func TestLargeSparseFiles(t *testing.T) {
	dir := t.TempDir()
	sparse := func(name string, head []byte, size int64, tail []byte) string {
		path := filepath.Join(dir, name)
		f, err := os.Create(path)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if _, err := f.Write(head); err != nil {
			t.Fatal(err)
		}
		if err := f.Truncate(size); err != nil {
			t.Skipf("sparse files unsupported: %v", err)
		}
		if _, err := f.WriteAt(tail, size); err != nil {
			t.Fatal(err)
		}
		return path
	}
	var adts []byte
	for len(adts) < 2<<20 {
		adts = append(adts, adtsFrame(4, 2, 300)...)
	}
	ftyp := box("ftyp", []byte("M4A "), be32(0))
	const mdatSize = 3 << 30
	moov := box("moov", mvhd(1000, 3600*1000), mp4AudioTrak(1, 44100, 44100*3600, 2, 44100, 0))

	files := map[string]string{
		"vbr.mp3":  sparse("vbr.mp3", mpegStream(1500, 128, 64), 3<<30, nil),
		"long.aac": sparse("long.aac", adts, 200<<20, nil),
		"late.m4a": sparse("late.m4a", cat(ftyp, be32(1), []byte("mdat"), be64(mdatSize)), int64(len(ftyp))+mdatSize, moov),
	}
	for name, path := range files {
		start := time.Now()
		info, err := ProbeFile(path, Options{})
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if elapsed := time.Since(start); elapsed > 2*time.Second {
			t.Errorf("%s: probe took %v", name, elapsed)
		}
		if info.Duration <= 0 {
			t.Errorf("%s: Duration = %v", name, info.Duration)
		}
	}
}

// failingReader simulates I/O errors and panics from the underlying file.
type failingReader struct{ panics bool }

func (r failingReader) ReadAt(p []byte, off int64) (int, error) {
	if r.panics {
		panic("read exploded")
	}
	return 0, errors.New("disk on fire")
}

func TestReaderFailures(t *testing.T) {
	if _, err := probeSafely(failingReader{}, 1<<20, ".mp3", Options{}); err == nil {
		t.Error("I/O errors: want an error")
	}
	if _, err := probeSafely(failingReader{panics: true}, 1<<20, ".mp3", Options{}); err == nil || !strings.Contains(err.Error(), "read exploded") {
		t.Errorf("panic: err = %v, want it recovered into an error", err)
	}
}

// FuzzProbe feeds arbitrary bytes to every parser. `go test` runs the seed
// corpus; run `go test -fuzz=FuzzProbe ./internal/media` to explore further.
func FuzzProbe(f *testing.F) {
	for name, data := range corpus(f) {
		f.Add(data, extOf(name))
	}
	f.Fuzz(func(t *testing.T, data []byte, ext string) {
		probeNoPanic(t, "fuzz", data, ext)
	})
}
