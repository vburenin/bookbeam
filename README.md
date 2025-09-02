# BookBeam

BookBeam is a small, password‑protected web server that indexes a local audiobook library, serves a mobile/car‑friendly player UI, remembers your listening state on the server, and ensures only one page plays audio at a time. It supports running under a sub‑path (e.g., https://example.com/mybooks/).

## Features

- Auth via CLI flags: `-u user:pass` (repeat for multiple users) and/or `BOOKBEAM_USERS` env var. No DB.
- Long‑lived session: HMAC‑signed cookie (10 years) with a secret persisted at `/data/session_secret`.
- Server‑side state per user: stores current track/time, speed, listened list, folder expansion, scroll, volume/mute at `/data/state/<username>.json`.
- Bundled UI: the server always serves the built‑in single‑page UI and injects small scripts for state sync, single‑owner playback, and a top‑right Logout link.
- Single active player: Only one tab/device plays at a time. Others auto‑pause (SSE + heartbeat lease).
- Library indexing & cache:
  - On startup, the server rebuilds the index by scanning `/data` and writes `/data/audiobooks.json`.
  - An efficient hourly check compares a fast signature (paths/sizes/mtimes) and refreshes the cache only if changed.
- Streaming with HTTP Range: play files via `/media/<relative-path>` or directly by their relative path (direct file URLs under your deployed sub‑path are supported).
- Reverse‑proxy friendly: honors `X-Forwarded-Prefix`; cookies and links are scoped to a sub‑path (e.g., `/mybooks`).
- iOS and password‑manager friendly login form (LastPass, etc.).

## Quick Start (Go)

Run the server directly with Go (no Docker required):

```
# From repo root
go run ./server -addr :8080 -data /path/to/audiobooks -u user:password -u foo:pass456
```

Or build a binary:

```
cd server
go build -o bookbeam
./bookbeam -addr :8080 -data /path/to/audiobooks -u user:password
```

Environment options:
- `BOOKBEAM_USERS` (comma/space/semicolon‑separated `user:pass` pairs)
- `COOKIE_SECURE=1` when served via HTTPS to mark the cookie Secure

## Run With Docker (optional)

Docker and docker‑compose files are provided purely as a convenience; Docker is not part of the engine.

### Docker CLI

```
docker build -t bookbeam .
docker run -p 8180:8180 \
  -e BOOKBEAM_USERS="user:password,foo:pass456" \
  -e COOKIE_SECURE=0 \
  -v "$PWD:/data" \
  bookbeam \
  -addr :8180
```

### Docker Compose

1) Copy and edit the env file:

```
cp .env.bookbeam.example .env.bookbeam
# edit .env.bookbeam and set BOOKBEAM_USERS and BOOKBEAM_DATA
```

2) Build and run using the provided `docker-compose.yml`:

```
docker compose up -d --build
```

3) Open http://localhost:8180 and log in.

## Data Directory Contract (`/data`)

- Audio library: your folders/files. The server scans these.
- `/data/audiobooks.json`: cached tree written by the server (rebuilt on startup; refreshed hourly if the library changes).
- `/data/state/<username>.json`: per‑user state files.
- `/data/session_secret`: HMAC secret used to sign cookies (created on first run).

Ensure the process has write access so it can create/update these files.

## Login & Sessions

- Provide users with repeated `-u user:pass` flags or via `BOOKBEAM_USERS`.
- Cookies last ~10 years and are scoped to the app path (root or sub‑path via `X-Forwarded-Prefix`).
- Set `COOKIE_SECURE=1` when serving via HTTPS so cookies are Secure.

## Player UI

- The bundled UI at `server/web/index.html` is always served.
- The server injects at runtime:
  - a tiny Logout link (top‑right),
  - a state mirror to load/save state server‑side,
  - and a single‑owner coordinator to prevent concurrent playback.

### State Sync details

- Owner only writes: only the page that currently owns the playback lease syncs state to the server.
- During playback: state is posted at most once a minute.
- Immediate posts on: pause/end, seek, speed change, listened updates, and when a page becomes owner.

### Single‑owner playback

- When a page hits Play, it acquires a per‑user lease (random `client_id`). Others receive an SSE event (or heartbeat/poll fallback) and pause.
- Heartbeat runs every ~5s while playing; the server expires leases after ~90s of silence.

## CLI Flags & Env

- `-addr`: listen address (default `:8080`, compose uses `:8180`).
- `-data`: data directory mount (default `/data`).
- `-u user:pass`: add a login (repeatable).
- `COOKIE_SECURE=1`: mark cookie as Secure (HTTPS only).
 - `BOOKBEAM_USERS`: alternative to repeated `-u` flags.

## API (all routes require auth unless noted)

- `GET /login` (no auth): HTML login form.
- `POST /login` (no auth): accepts JSON `{username,password}` or form fields; sets cookie.
- `POST /logout`: clears cookie.
- `GET /healthz` (no auth): basic health.
- `GET /api/me`: `{username}`.
- `GET /audiobooks.json`: cached tree (served from in‑memory cache; also written to `/data/audiobooks.json`).
- `GET /api/books`: in‑memory cached tree.
- `GET /api/state`: returns per‑user JSON state.
- `POST /api/state`: stores arbitrary JSON as user state.
- `GET /media/<path>`: streams file under `/data/<path>` with Range.
- Playback lease:
  - `POST /api/lease/acquire` body `{client_id}` → makes caller owner.
  - `POST /api/lease/heartbeat` body `{client_id}` → returns `{client_id, expires, owner}`.
  - `POST /api/lease/release` body `{client_id}` → relinquish.
  - `GET  /api/lease/current` → `{client_id, expires}` of current holder (if any).
  - `GET  /api/lease/stream` → SSE broadcasts lease changes.

## Troubleshooting

- Session not restored across browsers: cookies are per host/path. Use the same domain and sub‑path; confirm `ab_session` cookie exists and that `/data/session_secret` persists across restarts.
- Both tabs play: ensure your reverse proxy does not buffer Server‑Sent Events (SSE); heartbeat fallback pauses within 5 seconds.
- State not saving: only the owner tab syncs. Hit Play in the page you want to control state.
- Library not updating: hourly reindex compares a signature; to force rebuild, restart the server (it always rebuilds on startup).
- Files not visible: confirm your host path is correctly mounted to `/data` and the container has read/write permissions.

## Project Files

- `server/main.go` — Go server (auth, API, indexing, streaming, path‑prefix support).
- `server/web/index.html` — bundled UI.
- `server/web/login.html` — login form (LastPass/iOS friendly).
- `server/web/static/mirror.js` — mirrors localStorage ⇄ server state (owner‑gated).
- `server/web/static/solo.js` — single‑owner playback coordinator.
- `Dockerfile`, `docker-compose.yml` — optional containerization helpers.
- `AGENTS.md` — project context/architecture notes.

---

If you want a manual “Reindex now” endpoint, faster heartbeat, or a magic‑link device login, open an issue/ask and I’ll add it.
