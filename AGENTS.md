# BookBeam — Project Context

BookBeam is a self-hosted audiobook server and web app for a family. It scans a folder of audiobooks,
streams them with HTTP Range support, and keeps each person's place in every book on the server. The
primary clients are the **Tesla in-car browser** (landscape, touch, used while driving) and **phones**
(iOS Safari, Android Chrome). Desktop browsers are also supported.

## Architecture

One Go binary with the web app embedded (`server/web/public` via `embed`). There is no database:
state is JSON files written atomically. The only third-party dependency is `rsc.io/qr`.

```
server/
  main.go                 flags/env, wiring, graceful shutdown
  internal/media/         pure-Go probing: tags, duration, chapters, cover art; legacy
                          code-page detection (Windows-1251 Cyrillic vs 1252) for mislabelled tags
                          (MP3/ID3, MP4/M4B, FLAC, Ogg Vorbis/Opus, WAV, AAC; optional ffprobe fallback)
  internal/library/       scanner: walk, book grouping, metadata, covers, probe cache, natural sort
  internal/store/         per-user data: progress, bookmarks, settings, stats, legacy v1 migration
  internal/auth/          users, v1-compatible HMAC tokens, session registry, rate limits, device pairing
  internal/server/        HTTP routes, middleware (prefix, proxy trust, CSRF, gzip, security headers),
                          SSE hub, static files (versioned assets)
  internal/fsutil/        atomic file writes
  web/public/             the web app: vanilla ES modules, no build step, hash routing
scripts/make-sample-library.sh   realistic dev/test library (needs ffmpeg)
```

### Web app (`server/web/public`)

`assets/js/main.js` boots it. `player.js` owns the single `<audio>` element: position, chapters,
speed, smart rewind, network-retry. `sync.js` and `positions.js` handle progress reporting, the
offline queue, the stale-device guard and SSE. `store.js` holds in-memory state. Views live in
`assets/js/views/`. Styles are in `assets/app.css`. Fonts (Fraunces and Atkinson Hyperlegible Next)
are self-hosted.

Constraints:
- **Browser floor: Chromium 80 / Safari 14.** Avoid newer syntax, APIs and CSS, or provide fallbacks.
- **CSP forbids inline scripts and `on*=` attributes.**
- **All URLs are relative**, so the app works under a sub-path.
- Every mutating API call sends `X-BookBeam: 1` (CSRF guard).
- Untrusted text (tags, filenames) must never reach `innerHTML`.

### Library model

- A directory of audio files is a book, with tracks in natural order.
- When a directory holds two or more `.m4b` files, or every file in it has embedded chapters, each
  file is its own book.
- `CD 1` / `Disc 2` / `Part 3` subfolders are merged into their parent book.
- Loose files at the library root are single-file books.
- Book id = `b_` + 12 hex chars of sha1(rel path). Ids and track indexes change when files are
  added, renamed or regrouped, so they are never a place's identity (see the sync model).
- Chapters come from the embedded chapters when a track has two or more; otherwise each track is a
  chapter.
- The index plus probe cache (keyed by path+size+mtime) persists in `library.json`, so restarts are
  instant. Rescans run in the background (periodic and manual) and push an SSE `library` event.

### Sync model

- Clients `PUT api/progress/{bookId}` every 15 s while playing, and immediately on
  play/pause/seek/track/speed/ended.
- The server stamps `updatedAt` and broadcasts SSE events to the user's other devices.
- A `play` event makes that client the user's active player. Other devices pause and show "Now
  playing on …".
- Before playing, a client re-checks the server copy, so a stale device never overwrites newer
  progress.
- **A place is a file plus a position.** Progress and bookmarks store `trackPath` and `trackSize`;
  `trackIndex`, `bookPosition` and even `bookId` are derived. The store re-links them against each new
  index (`internal/store/reconcile.go`). It runs lazily per user when the index version changes, and
  eagerly for loaded users after every scan. A place whose track index now names another file is
  re-pointed to its file. A place whose book vanished follows its file (by exact path, else by a
  unique name+size match) to the new book; when both books have progress, the newer `updatedAt`
  wins. Unmatched entries are kept, never deleted. Re-linking does not touch `updatedAt`, and it
  pushes SSE `progress`/`bookmarks` events; an entry that moved to another book arrives as
  `progress {bookId: <old>, progress: null, movedTo: <new>}` before the new book's event. A device
  that has the old book loaded carries on with the same file at the same second under the new id
  (`player.relocate`). `PUT api/progress` with a `trackPath` of the book wins over `trackIndex`.
  Clients resolve saved places by `trackPath` first.

## Directory contracts

- `-data` (default `/data`): the library. BookBeam never writes to it.
- `-state` (default `<data>/.bookbeam`):
  - `secret.key` (HMAC key)
  - `sessions.json` (+ `sessions.json.bak`, the previous version: a damaged registry is moved aside
    and the backup used; with neither readable the server starts empty and logs an ERROR. It never
    rotates the key on its own.)
  - `users/<name>.json`
  - `library.json`
  - `covers/`
- Legacy v1 files under `/data` (`session_secret`, `state/<user>.json`, `audiobooks.json`) are
  read-only inputs:
  - `session_secret` is adopted on first start, so old cookies stay valid.
  - Old per-user state is migrated once.

## API

See [README.md](README.md) for configuration. The routes are registered in
`server/internal/server/server.go`. All of them are relative to the app root:
- `POST login`; `api/logout`, `api/me`.
- Listeners on a shared device: the `ab_device` cookie (HttpOnly, 10 years) is set at sign-in and
  pairing. Sessions record their `device` and token `exp`, and tokens are deterministic, so a session
  can be re-minted. Signing in on a signed-in device adds a listener; it does not replace the one
  there. `GET api/device/accounts` lists the users signed in on this device. `POST api/device/switch
  {username}` makes one of them current. `POST api/logout` revokes only the current session and
  answers `{next}`: the device switches to that listener, or `""` means it is now signed out.
  `api/me` re-sends both cookies, because browsers cap cookie lifetimes at about 400 days.
- Pairing: `api/pair/start`, `api/pair/poll`, `api/pair/{code}` (plus `/approve`, `/deny`); `pair-qr.svg`.
- `api/sessions`.
- Library: `api/library`, `api/books/{id}` (plus `/cover`, `/tracks/{n}/audio`, `/bookmarks`);
  `api/library/rescan` (optional body `{"force":true}`). A scan that finds no audio at all while the
  index has books (an unmounted share) is refused and the index kept; for a requested rescan the
  SSE `library` event then carries `refused:"empty"`, and only a forced rescan publishes an empty
  library. The `api/library` ETag describes the whole body (version, scan time,
  scanning), and clients echo the one they received. A track's `url` carries `?v=<fingerprint>` of
  path, size and mtime; clients use it verbatim.
- State: `api/state`, `api/progress/{id}`, `api/settings`, `api/stats`.
- `api/events` (SSE).

### Caching

- Audio is cached with `private, max-age=31536000, immutable` only when `?v=` matches the indexed
  file and the file on disk still matches the index. Otherwise it gets `private, no-cache` (ETag from
  size and mtime). Covers use the same scheme with their own `?v=`.
- `index.html` is served with its `assets/…` references rewritten to `assets-<hash>/…`, where the hash
  covers every file under `public/assets`. Those URLs are `public, max-age=31536000, immutable`.
  Plain `assets/…` and other versions are `no-cache` with an ETag. JS modules must import each other
  relatively (`./x.js`) so they inherit the versioned prefix. With `BOOKBEAM_WEB_DIR`, the hash is
  recomputed on every index request and nothing is cached for good.

### Security notes

- `-trust-proxy auto` (the default) honours `X-Forwarded-*` only from loopback and private
  (RFC 1918, ULA, link-local) peers.
- The audio and cover handlers resolve the real path at serve time. They refuse anything inside the
  state dir or v1's `session_secret`/`state`/`audiobooks.json`; extracted covers must resolve inside
  `covers/`. This holds even if a library symlink is swapped after a scan.
- A pairing request's display name comes from its User-Agent. A `deviceName` sent by the client is
  ignored; the approver can rename the device.
- `-base-path` scopes cookies to the prefix only when the request path carries it. Without the
  prefix (for example on the LAN URL), the app and its cookies live at `/`.

## Development

```sh
scripts/make-sample-library.sh /tmp/books
cd server
BOOKBEAM_WEB_DIR=$PWD/web/public go run . -data /tmp/books -state /tmp/bb-state -u dev:dev
go vet ./... && go test -race ./...
```

Media tests generate fixtures with ffmpeg when it is installed and skip those cases otherwise.
