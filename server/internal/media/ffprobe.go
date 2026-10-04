package media

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

const (
	ffprobeTimeout   = 30 * time.Second
	maxFFprobeOutput = 16 << 20
)

// ffprobeOutput is the subset of `ffprobe -print_format json` we use.
type ffprobeOutput struct {
	Format struct {
		FormatName string            `json:"format_name"`
		Duration   string            `json:"duration"`
		BitRate    string            `json:"bit_rate"`
		Tags       map[string]string `json:"tags"`
	} `json:"format"`
	Streams []struct {
		CodecType   string            `json:"codec_type"`
		CodecName   string            `json:"codec_name"`
		SampleRate  string            `json:"sample_rate"`
		Channels    int               `json:"channels"`
		Tags        map[string]string `json:"tags"`
		Disposition struct {
			AttachedPic int `json:"attached_pic"`
		} `json:"disposition"`
	} `json:"streams"`
	Chapters []struct {
		StartTime string            `json:"start_time"`
		EndTime   string            `json:"end_time"`
		Tags      map[string]string `json:"tags"`
	} `json:"chapters"`
}

// runFFprobe probes path with the ffprobe binary, if one is on PATH.
func runFFprobe(path string) (*Info, error) {
	bin, err := exec.LookPath("ffprobe")
	if err != nil {
		return nil, err
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), ffprobeTimeout)
	defer cancel()
	// The file: prefix stops ffprobe from reading the name as a protocol
	// URL or treating characters such as '?' specially.
	cmd := exec.CommandContext(ctx, bin, "-v", "quiet", "-print_format", "json",
		"-show_format", "-show_chapters", "-show_streams", "file:"+abs)
	out := &cappedBuffer{limit: maxFFprobeOutput}
	cmd.Stdout = out
	cmd.WaitDelay = time.Second
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			err = ctx.Err() // killed on timeout: report it as such (see IsTransient)
		}
		return nil, fmt.Errorf("media: ffprobe: %w", err)
	}
	return parseFFprobe(out.buf)
}

// parseFFprobe converts ffprobe's JSON into an Info.
func parseFFprobe(data []byte) (*Info, error) {
	var out ffprobeOutput
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("media: ffprobe output: %w", err)
	}
	if out.Format.FormatName == "" {
		return nil, errors.New("media: ffprobe: no format detected")
	}
	info := &Info{}
	// Tag keys vary in case by container ("title", "TITLE", "album_artist"),
	// which tagMap normalises. Ogg keeps its comments on the stream.
	tags := tagMap{}
	addTags := func(m map[string]string) {
		for _, k := range slices.Sorted(maps.Keys(m)) {
			tags.add(k, m[k])
		}
	}
	addTags(out.Format.Tags)
	codec := ""
	for _, s := range out.Streams {
		switch {
		case s.Disposition.AttachedPic == 1:
			info.HasPicture = true
		case s.CodecType == "audio" && codec == "":
			codec = s.CodecName
			info.SampleRate, _ = strconv.Atoi(s.SampleRate)
			info.Channels = s.Channels
			addTags(s.Tags)
		}
	}
	tags.apply(info)

	info.Format = ffprobeFormat(out.Format.FormatName, codec)
	info.Duration, _ = strconv.ParseFloat(out.Format.Duration, 64)
	info.Bitrate, _ = strconv.Atoi(out.Format.BitRate)
	for _, c := range out.Chapters {
		start, err1 := strconv.ParseFloat(c.StartTime, 64)
		end, err2 := strconv.ParseFloat(c.EndTime, 64)
		if err1 != nil || err2 != nil || len(info.Chapters) >= maxChapters {
			continue
		}
		title := ""
		for k, v := range c.Tags {
			if strings.EqualFold(k, "title") {
				title = v
			}
		}
		info.Chapters = append(info.Chapters, Chapter{Title: title, Start: start, End: end})
	}
	info.normalize()
	return info, nil
}

// ffprobeFormat maps ffprobe's format name (and audio codec) onto the
// Info.Format vocabulary.
func ffprobeFormat(name, codec string) string {
	switch {
	case codec == "opus" && strings.Contains(name, "ogg"):
		return "opus"
	case strings.HasPrefix(name, "mov,mp4"):
		return "mp4"
	case strings.Contains(name, "webm") || strings.Contains(name, "matroska"):
		return "webm"
	}
	first, _, _ := strings.Cut(name, ",")
	return first
}

// mergeInfo fills gaps in the native result with ffprobe's. Native values
// win wherever both have one; a nil native result is replaced entirely.
func mergeInfo(native, ff *Info) *Info {
	if native == nil {
		return ff
	}
	out := *native
	fill(&out.Format, ff.Format)
	if out.Duration <= 0 {
		out.Duration = ff.Duration
	}
	fill(&out.Bitrate, ff.Bitrate)
	fill(&out.SampleRate, ff.SampleRate)
	fill(&out.Channels, ff.Channels)
	for _, f := range []struct {
		dst *string
		src string
	}{
		{&out.Title, ff.Title}, {&out.Album, ff.Album}, {&out.Artist, ff.Artist},
		{&out.AlbumArtist, ff.AlbumArtist}, {&out.Composer, ff.Composer},
		{&out.Narrator, ff.Narrator}, {&out.Genre, ff.Genre}, {&out.Year, ff.Year},
		{&out.Comment, ff.Comment}, {&out.Description, ff.Description},
		{&out.Series, ff.Series}, {&out.SeriesPart, ff.SeriesPart},
	} {
		fill(f.dst, f.src)
	}
	fill(&out.Track, ff.Track)
	fill(&out.TrackTotal, ff.TrackTotal)
	fill(&out.Disc, ff.Disc)
	fill(&out.DiscTotal, ff.DiscTotal)
	if len(out.Chapters) == 0 {
		out.Chapters = ff.Chapters
	}
	// ffprobe cannot hand back picture bytes, so Picture stays native-only.
	out.HasPicture = out.HasPicture || ff.HasPicture
	return &out
}

// cappedBuffer collects output up to limit bytes and then fails writes,
// which makes ffprobe's run fail instead of growing without bound.
type cappedBuffer struct {
	buf   []byte
	limit int
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	if len(b.buf)+len(p) > b.limit {
		return 0, errTooLarge
	}
	b.buf = append(b.buf, p...)
	return len(p), nil
}
