package media

import (
	"encoding/base64"
	"errors"
	"math"
	"testing"
)

func vorbisIdent(channels, rate int) []byte {
	return cat([]byte("\x01vorbis"), le32(0), []byte{byte(channels)}, le32(rate), le32(0), le32(96000), le32(0), []byte{0xB8, 1})
}

func opusHead(channels, preSkip int) []byte {
	return cat([]byte("OpusHead"), []byte{1, byte(channels)}, le16(preSkip), le32(44100), le16(0), []byte{0})
}

func TestOggVorbisCommentSpanningPages(t *testing.T) {
	// A large picture forces the comment packet across many small pages.
	img := cat(testJPEG, make([]byte, 20000))
	picture := "METADATA_BLOCK_PICTURE=" + base64.StdEncoding.EncodeToString(flacPictureData(3, "image/jpeg", img))
	comment := cat([]byte("\x03vorbis"), vorbisCommentData("TITLE=Ogg Title", picture, "ARTIST=Ogg Artist",
		"CHAPTER000=00:00:00.000", "CHAPTER000NAME=Intro", "CHAPTER001=00:00:04.000", "CHAPTER001NAME=Body"), []byte{1})
	data := oggStream(0x1234, 16,
		oggPacket{vorbisIdent(2, 44100), 0},
		oggPacket{comment, 0},
		oggPacket{cat([]byte("\x05vorbis"), make([]byte, 100)), 0}, // setup header
		oggPacket{make([]byte, 3000), 44100 * 5},
		oggPacket{make([]byte, 3000), 44100 * 10},
	)
	info := mustProbe(t, data, ".ogg", Options{WantPicture: true})
	expectDuration(t, info.Duration, 10, 1e-9)
	expectFields(t, info, Info{Format: "ogg", SampleRate: 44100, Channels: 2, Title: "Ogg Title", Artist: "Ogg Artist"})
	expectChapters(t, info.Chapters, Chapter{Title: "Intro", Start: 0, End: 4}, Chapter{Title: "Body", Start: 4, End: 10})
	if info.Picture == nil || len(info.Picture.Data) != len(img) {
		t.Errorf("Picture not reassembled across pages: %v", info.Picture != nil)
	}
}

func TestOggOpusDurationAndLastPage(t *testing.T) {
	// Two lacing values per page: each 500-byte packet ends on its own page.
	stream := oggStream(7, 2,
		oggPacket{opusHead(2, 312), 0},
		oggPacket{cat([]byte("OpusTags"), vorbisCommentData("title=Opus")), 0},
		oggPacket{make([]byte, 500), 48000*4 + 312},
		oggPacket{make([]byte, 500), 48000*8 + 312},
	)
	info := mustProbe(t, stream, ".opus", Options{})
	expectDuration(t, info.Duration, 8, 1e-9)
	expectFields(t, info, Info{Format: "opus", SampleRate: 48000, Channels: 2, Title: "Opus"})

	// A trailing page of another logical stream must not be used.
	other := oggStream(99, 255, oggPacket{[]byte("other stream"), 48000 * 1000})
	if info := mustProbe(t, cat(stream, other), "", Options{}); math.Abs(info.Duration-8) > 1e-9 {
		t.Errorf("with foreign trailing page: Duration = %v", info.Duration)
	}

	// A last page with a broken CRC is skipped in favour of the previous one.
	broken := append([]byte(nil), stream...)
	broken[len(broken)-1] ^= 0xFF
	if info := mustProbe(t, broken, "", Options{}); math.Abs(info.Duration-4) > 1e-9 {
		t.Errorf("with corrupt last page: Duration = %v, want 4", info.Duration)
	}
}

func TestOggUnsupportedCodec(t *testing.T) {
	data := oggStream(1, 255, oggPacket{cat([]byte("\x7fFLAC"), make([]byte, 40)), 0}, oggPacket{make([]byte, 10), 100})
	if _, err := probeBytes(data, ".ogg", Options{}); !errors.Is(err, ErrUnsupported) {
		t.Errorf("Ogg FLAC: err = %v, want ErrUnsupported", err)
	}
}

func TestOggCRC(t *testing.T) {
	// Ogg's CRC is CRC-32/POSIX without the final inversion, whose check
	// value for "123456789" is 0x765e7680 ^ 0xffffffff.
	if got := oggCRC(0, []byte("123456789")); got != 0x89A1897F {
		t.Errorf("oggCRC = %#x, want 0x89a1897f", got)
	}
}
