# syntax=docker/dockerfile:1

# ---- Build stage: a single static binary with the web app embedded ----
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY server/go.mod server/go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY server/ ./
ARG VERSION=dev
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/bookbeam .

# ---- Runtime stage ----
FROM alpine:3.22
# ffprobe is optional: the built-in pure-Go prober handles mp3/m4a/m4b/flac/ogg/opus/wav/aac.
# Build with --build-arg WITH_FFPROBE=1 to add it as a fallback for exotic files.
ARG WITH_FFPROBE=0
RUN apk add --no-cache ca-certificates tzdata \
    && if [ "$WITH_FFPROBE" = "1" ]; then apk add --no-cache ffmpeg; fi
COPY --from=build /out/bookbeam /usr/local/bin/bookbeam

# /data is the audiobook library. BookBeam writes its own state to /data/.bookbeam
# unless -state (or BOOKBEAM_STATE) points elsewhere, e.g. a separate /config volume.
VOLUME ["/data"]
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/bookbeam"]
CMD ["-addr", ":8080", "-data", "/data"]
