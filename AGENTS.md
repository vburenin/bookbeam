# BookBeam — Project Context

BookBeam serves a car‑friendly audiobook web UI with a Go backend. It scans an on‑disk library, exposes a simple API, streams audio with HTTP range support, and persists user playback state on the server. Access is protected by username/password passed via CLI flags.

## Overview

- Backend: Go HTTP server (no external DB) with HMAC‑signed cookies for sessions.
- Auth: Provide users via repeated `-u user:pass` CLI flags. No registration.
- Session: Long‑lived cookie (10 years). Secret is persisted under `/data/session_secret` so sessions survive restarts.
- Library: Host machine directory is mounted into the container at `/data`.
- Indexing/Cache: On startup, server loads `/data/audiobooks.json` if present; otherwise indexes `/data` and writes it. A background refresh updates the cache after the server starts.
- State: Per‑user playback state (current track/time, speed, UI tree expansion, listened list, etc.) is stored on the server in `/data/state/<username>.json`.
- Web UI: Minimal single‑page app served by the backend (mobile/car friendly). It calls the API for state and reads the cached `audiobooks.json`.

## API Sketch

- `POST /login` → body: `{username, password}` → sets cookie.
- `POST /logout` → clears cookie.
- `GET /api/me` → `{username}`.
- `GET /audiobooks.json` → cached library tree (served from `/data/audiobooks.json`).
- `GET /api/state` → per‑user JSON state.
- `POST /api/state` → upsert per‑user state.
- `GET /media/<path>` → streams audio files from `/data/<path>` with Range support.

## Directory Contracts

- `/data` — mounted audiobooks library on the host.
- `/data/audiobooks.json` — cached directory tree produced by the server.
- `/data/session_secret` — HMAC key used to sign cookies.
- `/data/state/<username>.json` — per‑user state files.

## Deployment (Docker)

Example build/run (adjust paths/users as needed):

```
docker build -t bookbeam .
docker run -p 8080:8080 \
  -v "$PWD:/data" \
  bookbeam \
  -addr :8080 \
  -u user:password -u foo:pass456
```

Then open http://localhost:8080 and log in.

## Notes

- The server avoids heavy dependencies and keeps state as JSON files under `/data`.
- If the CLI user list changes, previously issued cookies become invalid only if the username is removed; otherwise they remain valid (passwords are checked only at login time). To invalidate all sessions, delete `/data/session_secret` and restart the server.
