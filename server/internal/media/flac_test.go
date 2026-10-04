package media

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func TestFLAC(t *testing.T) {
	comments := vorbisCommentData(
		"TITLE=Flac Title", "album=Flac Album", "ARTIST=Writer", "ALBUM ARTIST=Writer",
		"PERFORMER=Performer", "NARRATOR=Real Narrator", "GENRE=Fantasy", "GENRE=Audiobook",
		"DATE=2001-02-03", "TRACKNUMBER=3", "TRACKTOTAL=9", "DISCNUMBER=1", "TOTALDISCS=2",
		"SERIES=Flac Series", "SERIES-PART=1", "DESCRIPTION=Long synopsis",
		"CHAPTER002=00:01:00.500", "CHAPTER002NAME=Second",
		"CHAPTER001=00:00:00.000", "CHAPTER001NAME=First", "CHAPTER001URL=http://x",
		"CHAPTER003NAME=No time: dropped", "CHAPTERS=not a chapter key",
		"no equals sign",
	)
	data := cat([]byte("fLaC"),
		flacBlock(flacStreamInfo, false, flacStreamInfoBlock(44100, 2, 44100*120)),
		flacBlock(flacVorbisComment, false, comments),
		flacBlock(flacPicture, false, flacPictureData(0, "image/png", testPNG)),
		flacBlock(flacPicture, false, flacPictureData(3, "image/jpeg", testJPEG)),
		flacBlock(1, true, make([]byte, 100)), // padding
		make([]byte, 5000),                    // "audio"
	)
	info := mustProbe(t, data, ".flac", Options{WantPicture: true})
	expectDuration(t, info.Duration, 120, 1e-9)
	expectFields(t, info, Info{
		Format: "flac", SampleRate: 44100, Channels: 2,
		Title: "Flac Title", Album: "Flac Album", Artist: "Writer", AlbumArtist: "Writer",
		Narrator: "Real Narrator", Genre: "Fantasy, Audiobook", Year: "2001",
		Track: 3, TrackTotal: 9, Disc: 1, DiscTotal: 2, Series: "Flac Series", SeriesPart: "1",
		Description: "Long synopsis", Comment: "Long synopsis",
	})
	expectChapters(t, info.Chapters,
		Chapter{Title: "First", Start: 0, End: 60.5},
		Chapter{Title: "Second", Start: 60.5, End: 120})
	if info.Picture == nil || !bytes.Equal(info.Picture.Data, testJPEG) {
		t.Errorf("Picture = %+v, want the front cover", info.Picture)
	}
	if info := mustProbe(t, data, ".flac", Options{}); !info.HasPicture || info.Picture != nil {
		t.Errorf("without WantPicture: HasPicture=%v Picture=%v", info.HasPicture, info.Picture)
	}

	// An ID3v2 tag in front of FLAC is skipped.
	withID3 := cat(id3TagBytes(3, 0, id3Frame23("TIT2", 0, id3Text("ignored"))), data)
	if info := mustProbe(t, withID3, ".flac", Options{}); info.Title != "Flac Title" {
		t.Errorf("FLAC behind ID3: Title = %q", info.Title)
	}
}

func TestFLACErrors(t *testing.T) {
	if _, err := probeBytes(cat([]byte("fLaC"), flacBlock(flacVorbisComment, true, vorbisCommentData())), "", Options{}); err == nil {
		t.Error("FLAC without STREAMINFO: want an error")
	}
	// Unknown total sample count: no duration, but not an error.
	info := mustProbe(t, cat([]byte("fLaC"), flacBlock(flacStreamInfo, true, flacStreamInfoBlock(48000, 1, 0))), "", Options{})
	if info.Duration != 0 || info.SampleRate != 48000 {
		t.Errorf("Duration=%v SampleRate=%d", info.Duration, info.SampleRate)
	}
}

func TestVorbisCommentPictures(t *testing.T) {
	block := base64.StdEncoding.EncodeToString(flacPictureData(3, "image/png", testPNG))
	legacy := base64.StdEncoding.EncodeToString(testJPEG)
	for name, comment := range map[string]string{
		"METADATA_BLOCK_PICTURE": "METADATA_BLOCK_PICTURE=" + block,
		"COVERART":               "COVERART=" + legacy,
	} {
		data := cat([]byte("fLaC"),
			flacBlock(flacStreamInfo, false, flacStreamInfoBlock(8000, 1, 8000)),
			flacBlock(flacVorbisComment, true, vorbisCommentData(comment)))
		info := mustProbe(t, data, "", Options{WantPicture: true})
		if info.Picture == nil || len(info.Picture.Data) == 0 {
			t.Errorf("%s: no picture", name)
		}
		if info := mustProbe(t, data, "", Options{}); !info.HasPicture {
			t.Errorf("%s: HasPicture = false", name)
		}
	}
}

func TestParseClock(t *testing.T) {
	tests := map[string]float64{"00:00:00.000": 0, "01:02:03.500": 3723.5, "02:03.25": 123.25, "42": 42}
	for in, want := range tests {
		if got, ok := parseClock(in); !ok || got != want {
			t.Errorf("parseClock(%q) = %v, %v", in, got, ok)
		}
	}
	for _, bad := range []string{"", "a:b", "1:2:3:4", "-1", "NaN", "Inf"} {
		if _, ok := parseClock(bad); ok {
			t.Errorf("parseClock(%q) accepted", bad)
		}
	}
}
