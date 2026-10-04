package media

import (
	"math"
	"testing"
)

func TestWAV(t *testing.T) {
	info := cat([]byte("INFO"),
		riffChunk("INAM", []byte("Wav Title\x00")), riffChunk("IART", []byte("Wav Artist\x00")),
		riffChunk("IPRD", []byte("Wav Album\x00")), riffChunk("ICMT", []byte("Caf\xe9\x00")),
		riffChunk("ICRD", []byte("2005\x00")), riffChunk("IGNR", []byte("Speech\x00")),
		riffChunk("ITRK", []byte("4\x00")))
	data := wavFile(
		wavFmt(1, 2, 44100, 16),
		riffChunk("data", make([]byte, 44100*4*3+2)), // 3 s and a bit; odd sizes get padded
		riffChunk("LIST", info),                      // tags after the audio
	)
	got := mustProbe(t, data, ".wav", Options{})
	expectDuration(t, got.Duration, 3, 1e-4)
	expectFields(t, got, Info{
		Format: "wav", SampleRate: 44100, Channels: 2, Bitrate: 44100 * 4 * 8,
		Title: "Wav Title", Artist: "Wav Artist", Album: "Wav Album", Comment: "Café",
		Year: "2005", Genre: "Speech", Track: 4,
	})
}

func TestWAVSizes(t *testing.T) {
	audio := make([]byte, 8000*2*5) // 5 s of 8 kHz 16-bit mono
	fmtChunk := wavFmt(1, 1, 8000, 16)

	streamed := wavFile(fmtChunk, cat([]byte("data"), le32(-1), audio))
	truncated := wavFile(fmtChunk, cat([]byte("data"), le32(len(audio)*4), audio))
	ds64 := riffChunk("ds64", cat(le64(0), le64(len(audio)), le64(0), le32(0)))
	rf64 := cat([]byte("RF64"), le32(-1), []byte("WAVE"), ds64, fmtChunk, cat([]byte("data"), le32(-1), audio))
	id3 := riffChunk("id3 ", id3TagBytes(3, 0, id3Frame23("TIT2", 0, id3Text("From ID3"))))
	withID3 := wavFile(fmtChunk, riffChunk("data", audio), id3)

	for name, data := range map[string][]byte{"streamed": streamed, "truncated": truncated, "rf64": rf64, "id3": withID3} {
		info := mustProbe(t, data, "", Options{})
		if math.Abs(info.Duration-5) > 1e-9 {
			t.Errorf("%s: Duration = %v, want 5", name, info.Duration)
		}
	}
	if info := mustProbe(t, withID3, "", Options{}); info.Title != "From ID3" {
		t.Errorf("id3 chunk: Title = %q", info.Title)
	}
}

func TestWAVCompressedUsesFact(t *testing.T) {
	// MPEG layer III in WAV (format 0x55): the byte rate is only nominal.
	fmtChunk := riffChunk("fmt ", cat(le16(0x55), le16(1), le32(22050), le32(4000), le16(1), le16(0)))
	data := wavFile(fmtChunk, riffChunk("fact", le32(22050*7)), riffChunk("data", make([]byte, 9000)))
	if info := mustProbe(t, data, "", Options{}); math.Abs(info.Duration-7) > 1e-9 {
		t.Errorf("Duration = %v, want 7 (from fact)", info.Duration)
	}
}

func TestWAVMissingChunks(t *testing.T) {
	if _, err := probeBytes(wavFile(riffChunk("data", make([]byte, 100))), "", Options{}); err == nil {
		t.Error("WAV without fmt: want an error")
	}
}
