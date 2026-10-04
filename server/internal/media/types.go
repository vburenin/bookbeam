// Package media extracts metadata (tags, duration, chapters, cover art) from
// audiobook files using only the Go standard library. An optional ffprobe
// fallback is used when a native parser cannot determine the duration.
package media

import "errors"

// ErrUnsupported is returned when the file format is not recognised.
var ErrUnsupported = errors.New("media: unsupported format")

// Chapter is a named section inside a single audio file.
type Chapter struct {
	Title string  `json:"title"`
	Start float64 `json:"start"` // seconds from the start of the file
	End   float64 `json:"end"`   // seconds; always filled (next chapter start or file duration)
}

// Picture is embedded cover art.
type Picture struct {
	MIME string `json:"-"` // "image/jpeg", "image/png", ...
	Data []byte `json:"-"`
}

// Info is everything BookBeam needs to know about one audio file.
// Zero values mean "unknown".
type Info struct {
	Format     string  `json:"format"`            // "mp3", "mp4", "flac", "ogg", "opus", "wav", "aac"
	Duration   float64 `json:"duration"`          // seconds
	Bitrate    int     `json:"bitrate,omitempty"` // bits per second (average)
	SampleRate int     `json:"sampleRate,omitempty"`
	Channels   int     `json:"channels,omitempty"`

	Title       string `json:"title,omitempty"`
	Album       string `json:"album,omitempty"`
	Artist      string `json:"artist,omitempty"`
	AlbumArtist string `json:"albumArtist,omitempty"`
	Composer    string `json:"composer,omitempty"`
	Narrator    string `json:"narrator,omitempty"` // explicit narrator tag (MP4 ©nrt, TXXX:NARRATOR, Vorbis NARRATOR/PERFORMER)
	Genre       string `json:"genre,omitempty"`
	Year        string `json:"year,omitempty"`
	Comment     string `json:"comment,omitempty"`
	Description string `json:"description,omitempty"` // long description / synopsis when present
	Series      string `json:"series,omitempty"`      // TXXX:SERIES, MP4 ----:SERIES, ©mvn/MVNM, Vorbis SERIES
	SeriesPart  string `json:"seriesPart,omitempty"`  // TXXX:SERIES-PART, ©mvi/MVIN, Vorbis SERIES-PART/SERIESPART

	Track      int `json:"track,omitempty"`
	TrackTotal int `json:"trackTotal,omitempty"`
	Disc       int `json:"disc,omitempty"`
	DiscTotal  int `json:"discTotal,omitempty"`

	Chapters []Chapter `json:"chapters,omitempty"`

	// HasPicture reports whether embedded art exists (set even when
	// Options.WantPicture is false). Picture is only filled when requested.
	HasPicture bool     `json:"hasPicture,omitempty"`
	Picture    *Picture `json:"-"`
}

// Options controls probing.
type Options struct {
	// WantPicture loads embedded cover art bytes into Info.Picture.
	WantPicture bool
	// FFprobe enables the ffprobe fallback (only used if the binary is on PATH
	// and the native parser failed or returned no duration).
	FFprobe bool
}
