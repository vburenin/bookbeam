#!/usr/bin/env bash
# Regenerates the small committed fixtures used by the media tests when
# ffmpeg is not installed. Requires ffmpeg. Run from anywhere:
#   server/internal/media/testdata/generate.sh
# The tests assert the exact tags/chapters written here; keep them in sync.
set -euo pipefail
cd "$(dirname "$0")"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
ff() { ffmpeg -hide_banner -loglevel error -y "$@"; }

# 6 s of quiet tone, 8 kHz mono, and a 16x16 PNG cover.
ff -f lavfi -i "sine=frequency=440:sample_rate=8000:duration=6" -af volume=0.1 "$TMP/tone.wav"
ff -f lavfi -i "color=c=0x2a9d8f:s=16x16:d=1" -frames:v 1 "$TMP/cover.png"
cat > "$TMP/chapters.txt" <<'META'
;FFMETADATA1
[CHAPTER]
TIMEBASE=1/1000
START=0
END=2000
title=Opening
[CHAPTER]
TIMEBASE=1/1000
START=2000
END=4250
title=Middle – ünïcødé
[CHAPTER]
TIMEBASE=1/1000
START=4250
END=6000
title=Closing
META

# MP3 (MPEG-2.5 layer III, 8 kbit/s CBR with LAME Info header), ID3v2.3
# tags including TXXX series/narrator, CHAP/CTOC chapters and a front cover.
ff -i "$TMP/tone.wav" -i "$TMP/cover.png" -i "$TMP/chapters.txt" \
  -map 0:a -map 1:v -map_chapters 2 -c:a libmp3lame -b:a 8k -c:v copy \
  -id3v2_version 3 -metadata:s:v comment="Cover (front)" \
  -metadata title="Fixture Title" -metadata album="Fixture Album" \
  -metadata artist="Fixture Author" -metadata album_artist="Fixture Author" \
  -metadata composer="Fixture Reader" -metadata genre="Audiobook" \
  -metadata date="2020" -metadata track="2/5" -metadata disc="1/1" \
  -metadata comment="Fixture comment" -metadata SERIES="Fixture Series" \
  -metadata SERIES-PART="2" -metadata NARRATOR="Fixture Narrator" \
  chapters.mp3

# M4B (AAC-LC 8 kHz) with iTunes tags, Nero + QuickTime chapters and covr.
ff -i "$TMP/tone.wav" -i "$TMP/cover.png" -i "$TMP/chapters.txt" \
  -map 0:a -map 1:v -map_chapters 2 -c:a aac -b:a 12k -c:v copy \
  -disposition:v attached_pic \
  -metadata title="Fixture Book" -metadata album="Fixture Book" \
  -metadata artist="Fixture Author" -metadata composer="Fixture Reader" \
  -metadata genre="Audiobook" -metadata date="2021-06-01" -metadata track="1/1" \
  -metadata description="Short description." \
  -metadata synopsis="A much longer synopsis of the fixture book." \
  -f mp4 book.m4b

# Opus with Vorbis comments (PERFORMER, SERIES, DESCRIPTION) and chapters.
ff -i "$TMP/tone.wav" -i "$TMP/chapters.txt" -map 0:a -map_chapters 1 \
  -c:a libopus -b:a 8k \
  -metadata title="Chapter Five" -metadata album="Fixture Opus" \
  -metadata artist="Fixture Author" -metadata PERFORMER="Opus Reader" \
  -metadata SERIES="Opus Series" -metadata SERIES-PART="3" \
  -metadata track="5/12" -metadata DESCRIPTION="Opus description" \
  tagged.opus

ls -l chapters.mp3 book.m4b tagged.opus
