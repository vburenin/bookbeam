package media

import (
	"bytes"
	"testing"
)

// mp4Book assembles ftyp, a 64-bit-size mdat holding the chapter text
// samples, then moov (so moov comes after mdat, as FFmpeg writes it).
func mp4Book(t testing.TB, titles []string, durations []int, wideOffsets bool, moovExtra ...[]byte) []byte {
	t.Helper()
	ftyp := box("ftyp", []byte("M4B "), be32(0), []byte("isomM4B "))
	base := len(ftyp) + 16
	var payload []byte
	var sizes, chunkOffsets []int
	for i, title := range titles {
		s := textSample(title)
		if i == 2 { // chunk 2 starts after a gap
			payload = append(payload, make([]byte, 7)...)
		}
		if i == 0 || i == 2 {
			chunkOffsets = append(chunkOffsets, base+len(payload))
		}
		sizes = append(sizes, len(s))
		payload = append(payload, s...)
	}
	payload = append(payload, make([]byte, 4096)...) // "audio"
	mdat := cat(be32(1), []byte("mdat"), be64(16+len(payload)), payload)
	// Chunk 1 holds samples 0-1, every later chunk one sample.
	runs := [][2]int{{1, 2}, {2, 1}}
	moov := box("moov", append([][]byte{
		mvhd(1000, 10000),
		mp4AudioTrak(1, 44100, 44100*10, 2, 44100, 2),
		mp4TextTrak(2, 1000, durations, sizes, chunkOffsets, runs, wideOffsets),
	}, moovExtra...)...)
	return cat(ftyp, mdat, moov)
}

func TestMP4(t *testing.T) {
	ilst := box("ilst",
		ilstItem("\xa9nam", 1, []byte("MP4 Title")),
		ilstItem("\xa9alb", 1, []byte("MP4 Album")),
		ilstItem("\xa9ART", 1, []byte("MP4 Author")),
		ilstItem("aART", 1, []byte("MP4 Author")),
		ilstItem("\xa9wrt", 1, []byte("MP4 Composer")),
		ilstItem("gnre", 0, be16(184)),
		ilstItem("\xa9day", 1, []byte("2015-01-01T00:00:00Z")),
		ilstItem("trkn", 0, cat(be16(0), be16(3), be16(10), be16(0))),
		ilstItem("disk", 0, cat(be16(0), be16(1), be16(2))),
		ilstItem("\xa9cmt", 1, []byte("A comment")),
		ilstItem("desc", 1, []byte("Short")),
		ilstItem("ldes", 2, utf16Bytes("Long description", true, false)),
		ilstItem("\xa9nrt", 1, []byte("MP4 Narrator")),
		ilstItem("\xa9mvn", 1, []byte("Movement")),
		ilstItem("tmpo", 21, be16(120)),
		freeform("SERIES", "MP4 Series"),
		freeform("SERIES-PART", "2"),
		box("covr", box("data", be32(14), be32(0), testPNG), box("data", be32(13), be32(0), testJPEG)),
	)
	nero := fullBox("chpl", 1, be32(0), []byte{2}, be64(0), []byte{5}, []byte("Nero1"), be64(50000000), []byte{5}, []byte("Nero2"))
	udta := box("udta", fullBox("meta", 0, fullBox("hdlr", 0, be32(0), []byte("mdir"), make([]byte, 13)), ilst), nero)

	for _, wide := range []bool{false, true} {
		data := mp4Book(t, []string{"One", "Two", "Três"}, []int{1000, 2000, 3000}, wide, udta)
		info := mustProbe(t, data, ".m4b", Options{WantPicture: true})
		expectDuration(t, info.Duration, 10, 1e-9)
		expectFields(t, info, Info{
			Format: "mp4", SampleRate: 44100, Channels: 2,
			Title: "MP4 Title", Album: "MP4 Album", Artist: "MP4 Author", AlbumArtist: "MP4 Author",
			Composer: "MP4 Composer", Narrator: "MP4 Narrator", Genre: "Audiobook", Year: "2015",
			Track: 3, TrackTotal: 10, Disc: 1, DiscTotal: 2, Comment: "A comment",
			Description: "Long description", Series: "MP4 Series", SeriesPart: "2",
		})
		// The QuickTime track (3 entries) beats Nero chpl (2 entries).
		expectChapters(t, info.Chapters,
			Chapter{Title: "One", Start: 0, End: 1},
			Chapter{Title: "Two", Start: 1, End: 3},
			Chapter{Title: "Três", Start: 3, End: 10})
		if info.Picture == nil || !bytes.Equal(info.Picture.Data, testPNG) || info.Picture.MIME != "image/png" {
			t.Errorf("Picture = %+v, want the first covr image", info.Picture)
		}
	}

	// With fewer QuickTime entries than Nero ones, chpl wins.
	data := mp4Book(t, []string{"Only"}, []int{10000}, false, udta)
	expectChapters(t, mustProbe(t, data, "", Options{}).Chapters,
		Chapter{Title: "Nero1", Start: 0, End: 5}, Chapter{Title: "Nero2", Start: 5, End: 10})
}

func TestMP4MetadataVariants(t *testing.T) {
	// QuickTime-style meta (not a full box) directly under moov, using mdta
	// keys; plus movement name/number as series fallbacks.
	keys := fullBox("keys", 0, be32(3),
		cat(be32(8+25), []byte("mdta"), []byte("com.apple.quicktime.title")),
		cat(be32(8+6), []byte("mdta"), []byte("SERIES")),
		cat(be32(8+6), []byte("mdta"), []byte("artist")))
	meta := box("meta", fullBox("hdlr", 0, be32(0), []byte("mdta"), make([]byte, 13)), keys, box("ilst",
		box(string(be32(1)), box("data", be32(1), be32(0), []byte("Keyed Title"))),
		box(string(be32(2)), box("data", be32(1), be32(0), []byte("Keyed Series"))),
		box(string(be32(9)), box("data", be32(1), be32(0), []byte("index out of range"))),
	))
	udta := box("udta", fullBox("meta", 0, fullBox("hdlr", 0, be32(0), []byte("mdir"), make([]byte, 13)), box("ilst",
		ilstItem("\xa9mvn", 1, []byte("Movement Series")),
		ilstItem("\xa9mvi", 21, be16(3)),
	)))
	data := mp4Book(t, []string{"A", "B", "C"}, []int{1000, 1000, 1000}, false, meta, udta)
	info := mustProbe(t, data, "", Options{})
	expectFields(t, info, Info{Title: "Keyed Title", Series: "Keyed Series", SeriesPart: "3"})
}

func TestMP4DurationFallbacks(t *testing.T) {
	trak := mp4AudioTrak(1, 48000, 48000*42, 1, 48000, 0)
	unknown := mvhd(1000, 0)

	fragmented := box("moov", unknown, box("mvex", fullBox("mehd", 0, be32(33000))), trak)
	if info := mustProbe(t, fragmented, "", Options{}); info.Duration != 33 {
		t.Errorf("mehd: Duration = %v, want 33", info.Duration)
	}
	plain := box("moov", unknown, trak)
	if info := mustProbe(t, plain, "", Options{}); info.Duration != 42 {
		t.Errorf("mdhd fallback: Duration = %v, want 42", info.Duration)
	}
}

func TestMP4Errors(t *testing.T) {
	ftyp := box("ftyp", []byte("M4A "), be32(0))
	if _, err := probeBytes(cat(ftyp, box("mdat", make([]byte, 100))), ".m4a", Options{}); err == nil {
		t.Error("no moov: want an error")
	}
	if _, err := probeBytes(cat(ftyp, box("moov", mvhd(1000, 1000))), ".m4a", Options{}); err == nil {
		t.Error("no audio track: want an error")
	}
	// Box sizes smaller than their header stop the walk without looping.
	if _, err := probeBytes(cat(ftyp, be32(4), []byte("moov")), ".m4a", Options{}); err == nil {
		t.Error("bad box size: want an error")
	}
}
