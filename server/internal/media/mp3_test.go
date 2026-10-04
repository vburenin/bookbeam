package media

import (
	"bytes"
	"math"
	"testing"
)

func TestMP3XingWithLAMEGapless(t *testing.T) {
	const frames, delay, padding = 1000, 576, 1000
	for _, tag := range []string{"Xing", "Info"} {
		data := cat(xingFrame(tag, frames, delay, padding), mpegStream(frames, 128))
		info := mustProbe(t, data, "", Options{})
		want := float64(frames*1152-delay-padding) / 44100
		if math.Abs(info.Duration-want) > 1e-9 {
			t.Errorf("%s: Duration = %v, want %v", tag, info.Duration, want)
		}
		expectFields(t, info, Info{Format: "mp3", SampleRate: 44100, Channels: 1})
	}
}

func TestMP3VBRI(t *testing.T) {
	f := mpegFrame(128)
	copy(f[36:], cat([]byte("VBRI"), be16(1), be16(0), be16(75), be32(500*417), be32(500)))
	info := mustProbe(t, cat(f, mpegStream(500, 128)), "", Options{})
	if want := 500 * 1152 / 44100.0; math.Abs(info.Duration-want) > 1e-9 {
		t.Errorf("Duration = %v, want %v", info.Duration, want)
	}
}

func TestMP3CBREstimate(t *testing.T) {
	info := mustProbe(t, mpegStream(1000, 64), "", Options{})
	// Frame lengths are rounded down, so the byte-based estimate runs a
	// fraction of a percent short of the exact frame count.
	expectDuration(t, info.Duration, 1000*1152/44100.0, 0.005)
	if info.Bitrate != 64000 {
		t.Errorf("Bitrate = %d, want 64000", info.Bitrate)
	}
}

func TestMP3VBRWithoutHeaderIsScanned(t *testing.T) {
	tests := map[string][]byte{
		"varying from the start": mpegStream(300, 128, 64, 320),
		// Constant-bitrate silence at the start fools a first-frames check;
		// the deeper spot checks must notice the VBR body.
		"silence then varying": cat(mpegStream(200, 32), mpegStream(300, 256, 160, 320)),
	}
	for name, data := range tests {
		frames := 0
		for pos := 0; pos < len(data); frames++ {
			h, _ := parseMPEGHeader(data[pos:])
			pos += h.size
		}
		info := mustProbe(t, data, "", Options{})
		if want := float64(frames*1152) / 44100; math.Abs(info.Duration-want) > 1e-9 {
			t.Errorf("%s: Duration = %v, want exactly %v", name, info.Duration, want)
		}
	}
}

func TestMP3JunkAndResync(t *testing.T) {
	// Zero padding and a stray sync pattern between the tag and the audio,
	// and a burst of damage in the middle of a VBR stream.
	fakeSync := cat([]byte{0xFF, 0xFB, 0x90, 0xC0}, bytes.Repeat([]byte{0x55}, 200))
	vbr := mpegStream(100, 128, 64)
	data := cat(id3TagBytes(3, 0, id3Frame23("TIT2", 0, id3Text("Junky"))), make([]byte, 3000), fakeSync,
		vbr[:len(vbr)/2], bytes.Repeat([]byte{0x11}, 100), vbr[len(vbr)/2:])
	info := mustProbe(t, data, "", Options{})
	if want := 200 * 1152 / 44100.0; math.Abs(info.Duration-want) > 1e-9 {
		t.Errorf("Duration = %v, want %v", info.Duration, want)
	}
	if info.Title != "Junky" {
		t.Errorf("Title = %q", info.Title)
	}
}

func TestMP3NoFrames(t *testing.T) {
	data := cat(id3TagBytes(3, 0, id3Frame23("TIT2", 0, id3Text("Tag only"))), bytes.Repeat([]byte{0xFF, 0xFB, 0x00}, 1000))
	if _, err := probeBytes(data, ".mp3", Options{}); err == nil {
		t.Error("want an error for a file without audio frames")
	}
}

func TestWalkFramesExtrapolates(t *testing.T) {
	data := mpegStream(1000, 128)
	src := newByteSource(data)
	parse := func(b []byte) (int, int, bool) {
		h, ok := parseMPEGHeader(b)
		return h.size, h.samples, ok
	}
	samples, walked, limited := walkFrames(src, 0, src.size, 100*417+10, 4, parse)
	if !limited || samples != 100*1152 || walked != 100*417 {
		t.Errorf("limited walk: samples=%d walked=%d limited=%v", samples, walked, limited)
	}
	samples, walked, limited = walkFrames(src, 0, src.size, maxScanBytes, 4, parse)
	if limited || samples != 1000*1152 || walked != src.size {
		t.Errorf("full walk: samples=%d walked=%d limited=%v", samples, walked, limited)
	}
}

func TestParseMPEGHeader(t *testing.T) {
	tests := []struct {
		hdr           []byte
		ok            bool
		size, samples int
		rate          int
	}{
		{[]byte{0xFF, 0xFB, 0x90, 0xC0}, true, 417, 1152, 44100}, // MPEG-1 L3 128k
		{[]byte{0xFF, 0xFB, 0x92, 0xC0}, true, 418, 1152, 44100}, // padded
		{[]byte{0xFF, 0xF3, 0x40, 0xC0}, true, 104, 576, 22050},  // MPEG-2 L3 32k
		{[]byte{0xFF, 0xE3, 0x18, 0xC4}, true, 72, 576, 8000},    // MPEG-2.5 L3 8k
		{[]byte{0xFF, 0xFD, 0xA0, 0x00}, true, 626, 1152, 44100}, // MPEG-1 L2 192k
		{[]byte{0xFF, 0xFF, 0x40, 0xC0}, true, 136, 384, 44100},  // MPEG-1 L1 128k
		{[]byte{0xFF, 0xFB, 0xF0, 0xC0}, false, 0, 0, 0},         // bad bitrate
		{[]byte{0xFF, 0xFB, 0x00, 0xC0}, false, 0, 0, 0},         // free format
		{[]byte{0xFF, 0xFB, 0x9C, 0xC0}, false, 0, 0, 0},         // reserved sample rate
		{[]byte{0xFF, 0xEB, 0x90, 0xC0}, false, 0, 0, 0},         // reserved version
		{[]byte{0xFF, 0xF9, 0x90, 0xC0}, false, 0, 0, 0},         // layer 0 (ADTS)
		{[]byte{0xFF, 0xFB, 0x90, 0xC2}, false, 0, 0, 0},         // reserved emphasis
		{[]byte{0xFF, 0xFB, 0x90}, false, 0, 0, 0},               // short
	}
	for _, tt := range tests {
		h, ok := parseMPEGHeader(tt.hdr)
		if ok != tt.ok || (ok && (h.size != tt.size || h.samples != tt.samples || h.sampleRate != tt.rate)) {
			t.Errorf("% x: ok=%v size=%d samples=%d rate=%d, want ok=%v size=%d samples=%d rate=%d",
				tt.hdr, ok, h.size, h.samples, h.sampleRate, tt.ok, tt.size, tt.samples, tt.rate)
		}
	}
}
