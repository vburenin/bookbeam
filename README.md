# BookBeam

BookBeam is a self-hosted audiobook server for your family. Point it at a folder of audiobooks and get a
fast web app that remembers everyone's place in every book, on every device. It is built for listening
**in the car (the Tesla browser in particular)** and on phones, and works just as well on a desktop.

- **One binary, no database.** Go server with the web app embedded. State is a few JSON files.
- **Your folders, understood.** Multi-file books, single-file `.m4b` books with chapters, `CD 1`/`Disc 2`
  folders, covers (folder images or embedded art), and tags (title, author, narrator, series) are
  detected automatically. MP3, M4A/M4B, AAC, FLAC, Ogg Vorbis, Opus and WAV are supported.
- **Built for the car.** A car mode with huge controls, a dark theme with an amber accent that won't
  dazzle at night, and **sign-in without typing**: the car shows a code and QR, and you approve it from
  your phone. Playback reconnects on its own when LTE drops.
- **A proper player.** Chapters (embedded or per file), a chapter scrubber, time left at your speed,
  per-book speed (0.5×–3.5×), a sleep timer (including "end of chapter") with fade-out, bookmarks with
  notes, smart rewind after pauses, lock-screen and media-key controls, and keyboard shortcuts.
- **Seamless hand-off.** Progress syncs live between devices. Start a book on your phone, get in the car
  and press Resume. Only one device plays at a time, and the other one pauses itself.
- **Library that helps you choose.** Continue listening, recently added, search, sorting, status filters,
  folder chips, and grid or list view.
- **Family friendly.** Separate logins and progress per person, device management (rename or sign out a
  device), and listening stats. On a shared device such as the family car, several people can stay
  signed in and switch with one tap ("Who's listening?").
- **Your place is never lost.** Restoring a missing chapter, renaming files or reorganising folders
  keeps everyone's place and bookmarks on the right file.
- **Installable.** Add it to your home screen as a PWA, with an offline app shell.

## Quick start

### Docker Compose

```sh
cp .env.bookbeam.example .env.bookbeam   # set BOOKBEAM_USERS and BOOKBEAM_DATA
docker compose up -d --build
```

Open <http://localhost:8180> and sign in.

### Docker CLI

```sh
docker build -t bookbeam .
docker run -d -p 8080:8080 \
  -v /path/to/audiobooks:/data \
  -e BOOKBEAM_USERS="mom:secret1,dad:secret2" \
  bookbeam
```

### From source (Go 1.25+)

```sh
cd server
go run . -data /path/to/audiobooks -u mom:secret1 -u dad:secret2
```

## Organising your library

BookBeam is forgiving, but these layouts work best:

```
Author or Series/
  Book Title/              ← a folder of audio files is one book (files play in natural order)
    01 - Opening.mp3
    02 - Chapter One.mp3
    cover.jpg              ← optional; otherwise embedded art is used
    desc.txt               ← optional description
    reader.txt             ← optional narrator
  Another Book/
    CD 1/ …  CD 2/ …       ← disc folders are merged into one book
Single Books/
  Project Hail Mary.m4b    ← several .m4b files in one folder become separate books
```

Tags are preferred when present: album → title, album artist/artist → author, narrator or composer
→ narrator, plus `SERIES`/`SERIES-PART` (or Apple's movement tags) for series. Folders such as
`@eaDir`, `#recycle` and dot-folders are ignored. New books appear automatically; the default scan
interval is 30 minutes, and Settings → Library → Rescan triggers one immediately.

Reorganising is safe. Each saved place and bookmark remembers its file (path and size). After a
scan, BookBeam moves them with their files: when a book folder is renamed or moved, when chapters are
added or removed, or when a folder is split into separate books or merged into one. Places that match
nothing are kept as they are (for example while a network share is unmounted) and are re-linked once
their files come back. A device that is playing a book while it is moved keeps playing.

If the library folder looks empty during a scan (the disk or share is not mounted), BookBeam keeps
the library as it was and checks again within minutes. Rescanning from Settings then says so; if you
really emptied the library, choose **Rescan anyway**.

## Configuration

| Flag | Environment | Default | Description |
|---|---|---|---|
| `-addr` | `BOOKBEAM_ADDR` | `:8080` | Listen address |
| `-data` | | `/data` | Audiobook library (can be read-only if `-state` is elsewhere) |
| `-state` | `BOOKBEAM_STATE` | `<data>/.bookbeam` | Where BookBeam keeps its own files |
| `-u user:pass` | `BOOKBEAM_USERS` | | Logins (repeatable; env takes `a:x, b:y`). Use `user:sha256:<hex>` to avoid plain-text passwords |
| `-base-path` | `BOOKBEAM_BASE_PATH` | | URL prefix if your proxy does **not** strip it, e.g. `/books` |
| `-scan-interval` | `BOOKBEAM_SCAN_INTERVAL` | `30m` | How often to look for new or changed files |
| `-trust-proxy` | `BOOKBEAM_TRUST_PROXY` | `auto` | Honour `X-Forwarded-For/Proto/Prefix`. `auto` trusts them only from loopback and private-network addresses (a proxy on the same host, in Docker or on your LAN). `true` trusts every peer and `false` none |
| `-ffprobe` | `BOOKBEAM_FFPROBE` | `auto` | Use `ffprobe` (if installed) as a fallback for unusual files; `off` to disable |
| | `COOKIE_SECURE=1` | | Force `Secure` cookies (automatic when the request arrives over HTTPS) |
| | `LOG_LEVEL`, `LOG_JSON=1` | `info` | Logging |

To hash a password for `user:sha256:<hex>`, run `printf '%s' 'the-password' | sha256sum`.

### Behind a reverse proxy (sub-path)

BookBeam uses only relative URLs, so it can live under any path. With nginx stripping the prefix:

```nginx
location /books/ {
    proxy_pass http://127.0.0.1:8180/;
    proxy_set_header X-Forwarded-Prefix /books;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_buffering off;              # live sync uses Server-Sent Events
    proxy_read_timeout 1h;
}
```

If your proxy does not strip the prefix, run BookBeam with `-base-path /books` instead. The app stays
reachable without the prefix too, for example at `http://nas:8180/` on your LAN.

With the default `-trust-proxy auto`, the forwarded headers are believed only when the proxy connects
from loopback or a private address, which covers the usual setups. Headers sent directly by clients on
the internet are ignored, so they cannot fake their IP to dodge the sign-in rate limits. If your
proxy reaches BookBeam from a public address, set `-trust-proxy true`.

The web app's files are served under versioned URLs (`assets-<hash>/…`) that browsers cache for a year.
After an upgrade, the new `index.html` points at new URLs, so nobody is left with stale files. Proxies
should pass `Cache-Control` through unchanged.

## Using it in a Tesla

1. On the car's browser, open your BookBeam address. The sign-in screen shows a code and a QR code.
2. Scan the QR with your phone, where you are already signed in, or open **Settings → Devices → Link a
   device** and type the code. Then tap **Allow**.
3. The car signs in and stays signed in. Car mode turns on automatically and can be changed in
   Settings → Appearance.

Tip: bookmark the page in the Tesla browser so it opens with one tap.

**Several people in one car.** Add each person once: **Settings → Listeners on this device → Add a
listener**, then pair with their phone (or type their password). After that, tap the avatar to switch
between them. Each person gets their own books, places and stats. Signing one person out hands the car
to the next listener, so the car stays usable.

## Data and backups

Everything BookBeam writes lives in the state directory (`<library>/.bookbeam` by default):

| File | Contents |
|---|---|
| `secret.key` | Key that signs session cookies. Delete it to sign everyone out. |
| `users/<name>.json` | Progress, bookmarks, settings and stats for each person |
| `sessions.json` | Signed-in devices (`sessions.json.bak` holds the previous version) |
| `library.json`, `covers/` | Library index and cover cache (safe to delete; they are rebuilt) |

Back up `users/` and you have backed up everything that matters.

If `sessions.json` is ever damaged, for example by a power cut on a NAS share, BookBeam moves it aside
(`sessions.json.corrupt-<time>`) and starts from `sessions.json.bak`. If both are unreadable, it starts
with an empty list and logs an error. Devices stay signed in, but a device that was signed out shortly
before might be able to sign back in. To sign out every device, stop BookBeam, delete `secret.key` and
start it again.

**Upgrading from BookBeam 1.x:** existing sign-ins keep working, because the old `session_secret` is
reused. Each person's last position and listened books are migrated from `state/<name>.json`
automatically the first time they open the new app. Old files are left untouched.

## Development

```sh
scripts/make-sample-library.sh /tmp/books          # small realistic library (needs ffmpeg)
cd server
BOOKBEAM_WEB_DIR=$PWD/web/public go run . -data /tmp/books -state /tmp/bb-state -u dev:dev
go test -race ./...
```

`BOOKBEAM_WEB_DIR` serves the web app from disk, so edits show up on reload. The app is plain ES
modules with no build step. See [AGENTS.md](AGENTS.md) for the architecture.

## License

Apache 2.0. See [LICENSE](LICENSE).
