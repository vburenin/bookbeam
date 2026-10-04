package media

import (
	"math"
	"testing"
)

func TestADTS(t *testing.T) {
	var frames []byte
	for i := range 430 {
		frames = append(frames, adtsFrame(4, 2, 200+i%50)...) // 44.1 kHz stereo, varying sizes
	}
	v1 := cat([]byte("TAG"), []byte("V1 Title"), make([]byte, 117))
	data := cat(id3TagBytes(4, 0, id3Frame24("TIT2", 0, id3Text("ADTS Title")), id3Frame24("TPE1", 0, id3Text("ADTS Artist"))), frames, v1)

	info := mustProbe(t, data, ".aac", Options{})
	if want := 430 * 1024 / 44100.0; math.Abs(info.Duration-want) > 1e-9 {
		t.Errorf("Duration = %v, want %v", info.Duration, want)
	}
	expectFields(t, info, Info{Format: "aac", SampleRate: 44100, Channels: 2, Title: "ADTS Title", Artist: "ADTS Artist"})
}

func TestParseADTS(t *testing.T) {
	h, ok := parseADTS(adtsFrame(3, 1, 93))
	if !ok || h.sampleRate != 48000 || h.channels != 1 || h.size != 100 || h.samples != 1024 {
		t.Errorf("parseADTS = %+v, %v", h, ok)
	}
	bad := adtsFrame(15, 2, 10) // sampling index 15 is invalid
	if _, ok := parseADTS(bad); ok {
		t.Error("invalid sample rate index accepted")
	}
	short := adtsFrame(4, 2, 0)
	short[3], short[4], short[5] = short[3]&^3, 0, short[5]&0x1F // frame length 0
	if _, ok := parseADTS(short); ok {
		t.Error("frame shorter than its header accepted")
	}
}
