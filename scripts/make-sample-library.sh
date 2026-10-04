#!/usr/bin/env bash
# Generates a small but realistic audiobook library for development and tests.
# Usage: scripts/make-sample-library.sh <target-dir>
# Requires ffmpeg. Audio is quiet tones; durations are short but non-trivial.
set -euo pipefail

OUT=${1:?usage: $0 <target-dir>}
command -v ffmpeg >/dev/null || { echo "ffmpeg is required" >&2; exit 1; }
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

ff() { ffmpeg -hide_banner -loglevel error -y "$@"; }

# tone <seconds> <freq> <out> [extra ffmpeg output args...]
tone() {
  local secs=$1 freq=$2 out=$3; shift 3
  ff -f lavfi -i "sine=frequency=${freq}:sample_rate=22050:duration=${secs}" \
     -af "volume=0.08" -ac 1 "$@" "$out"
}

# cover <out.jpg> <hex colour> <label>
cover() {
  local out=$1 colour=$2 label=$3
  if ! ff -f lavfi -i "color=c=${colour}:s=600x600:d=1" \
       -vf "drawtext=text='${label}':fontcolor=white:fontsize=56:x=(w-text_w)/2:y=(h-text_h)/2" \
       -frames:v 1 "$out" 2>/dev/null; then
    ff -f lavfi -i "color=c=${colour}:s=600x600:d=1" -frames:v 1 "$out"
  fi
}

echo "==> Expanse/Leviathan Wakes (multi-file mp3, cover.jpg, tags)"
D="$OUT/Expanse/Leviathan Wakes"; mkdir -p "$D"
cover "$D/cover.jpg" "0x1d3557" "Leviathan Wakes"
for i in 1 2 3 4 5 6; do
  n=$(printf '%02d' "$i")
  tone $((240 + i * 30)) $((200 + i * 20)) "$D/$n - Chapter $i.mp3" -c:a libmp3lame -b:a 32k \
    -metadata title="Chapter $i" -metadata album="Leviathan Wakes" \
    -metadata artist="James S. A. Corey" -metadata album_artist="James S. A. Corey" \
    -metadata composer="Jefferson Mays" -metadata track="$i/6" -metadata genre="Science Fiction" \
    -metadata date="2011" -id3v2_version 3
done

echo "==> Expanse/Caliban's War (disc folders, embedded art only)"
cover "$TMP/caliban.jpg" "0x6a040f" "Caliban's War"
for disc in 1 2; do
  D="$OUT/Expanse/Caliban's War/CD $disc"; mkdir -p "$D"
  for i in 1 2 3; do
    tone 180 $((300 + disc * 40 + i * 10)) "$TMP/t.mp3" -c:a libmp3lame -b:a 32k
    ff -i "$TMP/t.mp3" -i "$TMP/caliban.jpg" -map 0:a -map 1:v -c copy -id3v2_version 3 \
      -metadata:s:v title="Album cover" -metadata:s:v comment="Cover (front)" \
      -metadata title="Part $disc.$i" -metadata album="Caliban's War" \
      -metadata artist="James S. A. Corey" -metadata composer="Jefferson Mays" \
      -metadata track="$i" -metadata disc="$disc/2" "$D/Track $i.mp3"
  done
done

# chapters ffmetadata: <file> <total seconds> <titles...>
chapters_meta() {
  local f=$1 total=$2; shift 2
  local n=$# i=0 start end
  {
    echo ";FFMETADATA1"
    for t in "$@"; do
      start=$(( total * i / n )); end=$(( total * (i + 1) / n ))
      printf '[CHAPTER]\nTIMEBASE=1/1000\nSTART=%d\nEND=%d\ntitle=%s\n' $((start * 1000)) $((end * 1000)) "$t"
      i=$((i + 1))
    done
  } > "$f"
}

echo "==> Single Books/*.m4b (two single-file books with chapters + covr)"
D="$OUT/Single Books"; mkdir -p "$D"
cover "$TMP/phm.jpg" "0x2a9d8f" "Project Hail Mary"
chapters_meta "$TMP/phm.txt" 1500 "Prologue" "Chapter 1: Ryland" "Chapter 2: The Lab" "Chapter 3: Rocky" "Chapter 4: Taumoeba" "Epilogue"
tone 1500 260 "$TMP/phm.m4a" -c:a aac -b:a 32k
ff -i "$TMP/phm.m4a" -i "$TMP/phm.txt" -i "$TMP/phm.jpg" -map 0:a -map 2:v -map_metadata 1 -map_chapters 1 \
  -c copy -disposition:v attached_pic -metadata title="Project Hail Mary" -metadata album="Project Hail Mary" \
  -metadata artist="Andy Weir" -metadata composer="Ray Porter" -metadata date="2021" \
  -metadata genre="Science Fiction" -metadata comment="A lone astronaut must save the earth from disaster in this incredible new science-based thriller." \
  -f mp4 "$D/Project Hail Mary.m4b"
cover "$TMP/martian.jpg" "0xe76f51" "The Martian"
chapters_meta "$TMP/martian.txt" 900 "Sol 6" "Sol 7" "Sol 10" "Sol 14"
tone 900 330 "$TMP/martian.m4a" -c:a aac -b:a 32k
ff -i "$TMP/martian.m4a" -i "$TMP/martian.txt" -i "$TMP/martian.jpg" -map 0:a -map 2:v -map_metadata 1 -map_chapters 1 \
  -c copy -disposition:v attached_pic -metadata title="The Martian" -metadata artist="Andy Weir" \
  -metadata composer="R. C. Bray" -metadata date="2011" -f mp4 "$D/The Martian.m4b"

echo "==> Kids/Winnie-the-Pooh (opus)"
D="$OUT/Kids/Winnie-the-Pooh"; mkdir -p "$D"
for i in 1 2 3 4 5 6 7 8 9 10 11 12; do
  tone 75 $((440 + i * 15)) "$D/Chapter $i.opus" -c:a libopus -b:a 24k \
    -metadata title="Chapter $i" -metadata album="Winnie-the-Pooh" -metadata artist="A. A. Milne" -metadata track="$i"
done
printf 'Peter Dennis\n' > "$D/reader.txt"
printf 'The adventures of Christopher Robin and his friends in the Hundred Acre Wood.\n' > "$D/desc.txt"

echo "==> Classics/Pride & Prejudice [Unabridged] (1813) (ogg vorbis, no tags)"
D="$OUT/Classics/Pride & Prejudice [Unabridged] (1813)"; mkdir -p "$D"
for i in 1 2 3 10; do
  tone 150 $((500 + i * 5)) "$D/pride_and_prejudice_$(printf '%02d' "$i").ogg" -c:a libvorbis -q:a 0
done

echo "==> Root-level single mp3 with ID3 CHAP chapters"
chapters_meta "$TMP/lonely.txt" 600 "Opening" "The Middle Bit" "Closing"
tone 600 180 "$TMP/lonely.mp3" -c:a libmp3lame -b:a 32k
ff -i "$TMP/lonely.mp3" -i "$TMP/lonely.txt" -map 0:a -map_metadata 1 -map_chapters 1 -c copy -id3v2_version 3 \
  -metadata title="A Single Lonely Book" -metadata artist="Anonymous" "$OUT/A Single Lonely Book.mp3"

echo "==> Weird #Name? 100% (wav + flac, special characters)"
D="$OUT/Weird #Name? 100%"; mkdir -p "$D"
tone 45 600 "$D/part 1 – intro.wav" -c:a pcm_s16le
tone 60 620 "$D/part 2 – ünïcødé.flac" -c:a flac -metadata title="Ünïcødé" -metadata album="Weird #Name? 100%"

echo "==> noise that must be ignored"
mkdir -p "$OUT/@eaDir/junk" "$OUT/.hidden" "$OUT/Empty Folder" "$OUT/Docs Only"
tone 5 100 "$OUT/@eaDir/junk/ignored.mp3" -c:a libmp3lame -b:a 32k
tone 5 100 "$OUT/.hidden/ignored.mp3" -c:a libmp3lame -b:a 32k
printf 'not audio\n' > "$OUT/Docs Only/readme.txt"

echo "==> legacy v1 state (session_secret, audiobooks.json, state/vlad.json)"
mkdir -p "$OUT/state"
head -c 32 /dev/urandom > "$OUT/session_secret"
printf '{"name":"Audiobooks","type":"directory","children":[]}' > "$OUT/audiobooks.json"
cat > "$OUT/state/vlad.json" <<'EOF'
{
  "currentUrl": "Expanse/Leviathan Wakes/03 - Chapter 3.mp3",
  "currentSrc": "http://localhost:8080/media/Expanse/Leviathan%20Wakes/03%20-%20Chapter%203.mp3",
  "currentTime": 123.5,
  "playbackRate": 1.5,
  "currentTrackIndex": 2,
  "currentBookTitle": "Leviathan Wakes",
  "expandedStates": {"Audiobooks/Expanse": true},
  "scrollPosition": 0,
  "listened": [
    "/media/Expanse/Leviathan%20Wakes/01%20-%20Chapter%201.mp3",
    "/media/Expanse/Leviathan%20Wakes/02%20-%20Chapter%202.mp3",
    "/media/Expanse/Leviathan%20Wakes/03%20-%20Chapter%203.mp3",
    "/media/Single%20Books/The%20Martian.m4b",
    "/media/Kids/Winnie-the-Pooh/Chapter%201.opus",
    "/media/Kids/Winnie-the-Pooh/Chapter%202.opus"
  ]
}
EOF

echo "done: $OUT"
