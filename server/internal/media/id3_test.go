package media

import (
	"bytes"
	"compress/zlib"
	"slices"
	"testing"
)

// commFrame builds a COMM payload: encoding, language, description, text.
func commFrame(enc byte, lang, desc, text string) []byte {
	return cat([]byte{enc}, []byte(lang), []byte(desc), []byte{0}, []byte(text))
}

// txxx builds a UTF-8 TXXX payload.
func txxx(desc, value string) []byte {
	return cat([]byte{3}, []byte(desc), []byte{0}, []byte(value))
}

// apic builds an APIC payload with a Latin-1 description.
func apic(mime string, typ byte, img []byte) []byte {
	return cat([]byte{0}, []byte(mime), []byte{0, typ}, []byte("cover"), []byte{0}, img)
}

func zlibBytes(b []byte) []byte {
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	w.Write(b)
	w.Close()
	return buf.Bytes()
}

// unsync applies ID3 unsynchronisation (insert 0x00 after every 0xFF).
func unsync(b []byte) []byte {
	var out []byte
	for _, c := range b {
		out = append(out, c)
		if c == 0xFF {
			out = append(out, 0)
		}
	}
	return out
}

func TestID3v24(t *testing.T) {
	long := bytes.Repeat([]byte("x"), 300)
	compressed := zlibBytes(id3Text("Compressed Composer"))
	tag := id3TagBytes(4, id3Extended|id3Footer,
		cat(syncsafeBytes(6), []byte{1, 0}), // extended header, size includes itself
		id3Frame24("TIT2", 0, id3Text("Part One", "Part Two")),
		id3Frame24("TPE1", 0, cat([]byte{1}, utf16Bytes("Ärtist", false, true))),
		id3Frame24("TALB", 0, cat([]byte{2}, utf16Bytes("Albüm", true, false))),
		id3Frame24("TPE2", 0, cat([]byte{0}, []byte("Caf\xe9"))),
		id3Frame24("TCON", 0, id3Text("183")),
		id3Frame24("TDRC", 0, id3Text("2011-05-03")),
		id3Frame24("TRCK", 0, id3Text("3/12")),
		id3Frame24("TPOS", 0, id3Text("1/2")),
		// Data-length indicator and per-frame unsynchronisation.
		id3Frame24("TXXX", id3v24DataLength|id3v24Unsync, cat(syncsafeBytes(19), unsync([]byte("\x00Series\x00The \xff Series")))), // Latin-1
		id3Frame24("TXXX", 0, txxx("series-part", "4")),
		id3Frame24("TXXX", 0, txxx("NARRATOR", "Narr Ator")),
		id3Frame24("TXXX", id3v24Grouped, cat([]byte{7}, txxx("DESCRIPTION", "Synopsis text"))),
		id3Frame24("TCOM", id3v24Compressed|id3v24DataLength, cat(syncsafeBytes(20), compressed)),
		id3Frame24("TIT3", id3v24Encrypted, cat([]byte{1}, []byte("garbage"))),
		id3Frame24("COMM", 0, commFrame(0, "eng", "iTunNORM", " 0000 0000")),
		id3Frame24("COMM", 0, commFrame(0, "fra", "note", "French note")),
		id3Frame24("COMM", 0, commFrame(3, "eng", "", "Real comment")),
		// iTunes-style plain (non-synchsafe) size on a frame of ≥128 bytes.
		cat([]byte("PRIV"), be32(len(long)), be16(0), long),
		id3Frame24("TPE3", 0, id3Text("after the plain-size frame")),
		make([]byte, 64), // padding
	)
	// Footer: "3DI" copy of the header after the tag.
	tag = cat(tag, []byte("3DI"), tag[3:10])
	data := cat(tag, mpegStream(100, 128))
	info := mustProbe(t, data, ".mp3", Options{})
	expectFields(t, info, Info{
		Title: "Part One, Part Two", Artist: "Ärtist", Album: "Albüm", AlbumArtist: "Café",
		Genre: "Audiobook", Year: "2011", Track: 3, TrackTotal: 12, Disc: 1, DiscTotal: 2,
		Series: "The ÿ Series", SeriesPart: "4", Narrator: "Narr Ator",
		Description: "Synopsis text", Composer: "Compressed Composer", Comment: "Real comment",
	})
	expectDuration(t, info.Duration, 100*1152/44100.0, 0.01)
}

func TestID3v23(t *testing.T) {
	compressed := zlibBytes(id3Text("Zipped Title"))
	frames := cat(
		id3Frame23("TIT2", id3v23Compressed, cat(be32(13), compressed)),
		id3Frame23("TPE1", id3v23Grouped, cat([]byte{9}, cat([]byte{1}, utf16Bytes("Ëmily", true, true)))),
		id3Frame23("TCON", 0, cat([]byte{0}, []byte("(17)Rock"))),
		id3Frame23("TYER", 0, cat([]byte{0}, []byte("1999"))),
		id3Frame23("TALB", id3v23Encrypted, cat([]byte{1}, []byte("secret"))),
		id3Frame23("MVNM", 0, id3Text("Movement Series")),
		id3Frame23("MVIN", 0, id3Text("7")),
		id3Frame23("APIC", 0, apic("image/jpeg", 3, testJPEG)), // 0xFF bytes get unsynchronised
	)
	ext := cat(be32(6), make([]byte, 6)) // v2.3 extended header: size excludes itself
	tag := id3TagBytes(3, id3Unsync|id3Extended, unsync(cat(ext, frames)))
	info := mustProbe(t, cat(tag, mpegStream(50, 128)), "", Options{WantPicture: true})
	expectFields(t, info, Info{
		Title: "Zipped Title", Artist: "Ëmily", Genre: "Rock", Year: "1999",
		Series: "Movement Series", SeriesPart: "7",
	})
	if info.Album != "" {
		t.Errorf("encrypted frame decoded: Album = %q", info.Album)
	}
	if info.Picture == nil || !bytes.Equal(info.Picture.Data, testJPEG) || info.Picture.MIME != "image/jpeg" {
		t.Errorf("Picture = %+v, want the JPEG restored from unsynchronisation", info.Picture)
	}
}

func TestID3v22(t *testing.T) {
	tag := id3TagBytes(2, 0,
		id3Frame22("TT2", cat([]byte{0}, []byte("Old Title"))),
		id3Frame22("TP1", cat([]byte{1}, utf16Bytes("Old Artist", false, true))),
		id3Frame22("TCO", cat([]byte{0}, []byte("(101)"))),
		id3Frame22("COM", commFrame(0, "eng", "", "Old comment")),
		id3Frame22("PIC", cat([]byte{0}, []byte("PNG"), []byte{3}, []byte("d\x00"), testPNG)),
		id3Frame22("XYZ", []byte("unknown frame")),
	)
	info := mustProbe(t, cat(tag, mpegStream(10, 128)), "", Options{WantPicture: true})
	expectFields(t, info, Info{Title: "Old Title", Artist: "Old Artist", Genre: "Speech", Comment: "Old comment"})
	if info.Picture == nil || info.Picture.MIME != "image/png" {
		t.Errorf("Picture = %+v, want PNG", info.Picture)
	}
}

func TestID3Pictures(t *testing.T) {
	longDesc := bytes.Repeat([]byte("d"), 2000) // longer than the header peek
	tag := id3TagBytes(3, 0,
		id3Frame23("APIC", 0, cat([]byte{0}, []byte("-->"), []byte{0, 3, 0}, []byte("http://example.com/c.jpg"))),
		id3Frame23("APIC", 0, apic("image/png", 0, testPNG)),
		id3Frame23("APIC", 0, cat([]byte{0}, []byte("image/jpeg"), []byte{0, 3}, longDesc, []byte{0}, testJPEG)),
		id3Frame23("APIC", 0, apic("image/png", 4, testPNG)), // back cover: never preferred
	)
	data := cat(tag, mpegStream(10, 128))

	info := mustProbe(t, data, "", Options{WantPicture: true})
	if info.Picture == nil || !bytes.Equal(info.Picture.Data, testJPEG) {
		t.Errorf("Picture = %+v, want the front cover JPEG", info.Picture)
	}
	info = mustProbe(t, data, "", Options{})
	if !info.HasPicture || info.Picture != nil {
		t.Errorf("without WantPicture: HasPicture=%v Picture=%v", info.HasPicture, info.Picture)
	}

	// Only a link: no usable picture.
	linkOnly := cat(id3TagBytes(3, 0, id3Frame23("APIC", 0, cat([]byte{0}, []byte("-->"), []byte{0, 3, 0}, []byte("http://x")))), mpegStream(10, 128))
	if info := mustProbe(t, linkOnly, "", Options{}); info.HasPicture {
		t.Error("URL-only APIC reported as a picture")
	}
}

func TestID3Chapters(t *testing.T) {
	chap := func(id string, startMS, endMS int, sub ...[]byte) []byte {
		return id3Frame24("CHAP", 0, cat([]byte(id), []byte{0}, be32(startMS), be32(endMS), be32(-1), be32(-1), cat(sub...)))
	}
	title := func(s string) []byte {
		return id3Frame24("TIT2", 0, cat([]byte{1}, utf16Bytes(s, false, true), []byte{0, 0}))
	}
	toc := id3Frame24("CTOC", 0, cat([]byte("toc\x00"), []byte{0x03, 3}, []byte("c1\x00c0\x00nested\x00")))
	nested := id3Frame24("CTOC", 0, cat([]byte("nested\x00"), []byte{0x01, 2}, []byte("c2\x00toc\x00"))) // cycle back to toc
	tag := id3TagBytes(4, 0,
		chap("c2", 120000, 180000), // untitled
		chap("c0", 0, 60000, title("Zero"), id3Frame24("APIC", 0, apic("image/png", 3, testPNG))),
		chap("c1", 60000, 120000, title("One")),
		toc, nested,
	)
	info := mustProbe(t, cat(tag, mpegStream(7000, 128)), "", Options{}) // ≈183 s
	expectChapters(t, info.Chapters,
		Chapter{Title: "Zero", Start: 0, End: 60},
		Chapter{Title: "One", Start: 60, End: 120},
		Chapter{Title: "Chapter 3", Start: 120, End: info.Duration})
	if info.HasPicture {
		t.Error("a chapter image must not count as cover art")
	}
}

func TestID3v1Fallback(t *testing.T) {
	v1 := make([]byte, 128)
	copy(v1, "TAG")
	copy(v1[3:], "V1 Title")
	copy(v1[33:], "V1 Artist")
	copy(v1[63:], "V1 Album")
	copy(v1[93:], "1987")
	copy(v1[97:], "V1 comment")
	v1[126] = 4   // ID3v1.1 track
	v1[127] = 101 // Speech
	v2 := id3TagBytes(3, 0, id3Frame23("TIT2", 0, id3Text("V2 Title")))
	info := mustProbe(t, cat(v2, mpegStream(10, 128), v1), "", Options{})
	expectFields(t, info, Info{
		Title: "V2 Title", Artist: "V1 Artist", Album: "V1 Album", Year: "1987",
		Comment: "V1 comment", Track: 4, Genre: "Speech",
	})
}

func TestStackedID3Tags(t *testing.T) {
	first := id3TagBytes(4, 0, id3Frame24("TIT2", 0, id3Text("First")))
	second := id3TagBytes(3, 0, id3Frame23("TIT2", 0, id3Text("Second")), id3Frame23("TPE1", 0, id3Text("Second Artist")))
	info := mustProbe(t, cat(first, second, mpegStream(10, 128)), "", Options{})
	expectFields(t, info, Info{Title: "First", Artist: "Second Artist"})
}

func TestTrailingTagsExcludedFromAudio(t *testing.T) {
	ape := cat([]byte("APETAGEX"), le32(2000), le32(32+64), le32(1), le32(1<<31), make([]byte, 8))
	apeTag := cat(ape, make([]byte, 64), ape) // header, items, footer
	v1 := cat([]byte("TAG"), make([]byte, 125))
	audio := mpegStream(200, 128)
	plain := mustProbe(t, audio, "", Options{})
	tagged := mustProbe(t, cat(audio, apeTag, v1), "", Options{})
	if plain.Duration != tagged.Duration {
		t.Errorf("duration with APEv2+ID3v1 = %v, without = %v", tagged.Duration, plain.Duration)
	}
}

func TestID3Genres(t *testing.T) {
	tests := map[string][]string{
		"(17)":       {"Rock"},
		"(17)Rock":   {"Rock", "Rock"}, // tagMap removes the duplicate
		"(17)(101)":  {"Rock", "Speech"},
		"(183)Story": {"Audiobook", "Story"},
		"183":        {"Audiobook"},
		"((Weird)":   {"(Weird)"},
		"(RX)":       {"Remix"},
		"(999)":      {"(999)"},
		"Fantasy":    {"Fantasy"},
	}
	for in, want := range tests {
		if got := id3Genres([]string{in}); !slices.Equal(got, want) {
			t.Errorf("id3Genres(%q) = %q, want %q", in, got, want)
		}
	}
	if len(id3v1Genres) != 192 || id3v1Genres[183] != "Audiobook" || id3v1Genres[191] != "Psybient" {
		t.Errorf("genre table has %d entries", len(id3v1Genres))
	}
}

func TestID3Strings(t *testing.T) {
	// UTF-16 values where only the first carries a BOM keep its byte order.
	b := cat(utf16Bytes("Ünï", true, true), []byte{0, 0}, utf16Bytes("Two", true, false))
	if got := id3Strings(1, b); !slices.Equal(got, []string{"Ünï", "Two"}) {
		t.Errorf("id3Strings = %q", got)
	}
	if got := id3Strings(3, []byte("a\x00b\x00")); !slices.Equal(got, []string{"a", "b"}) {
		t.Errorf("id3Strings utf8 = %q", got)
	}
}
