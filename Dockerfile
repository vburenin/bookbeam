# Build stage
FROM golang:1.25-alpine AS build
WORKDIR /app
COPY server/ /app/
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go build -o /app/bookbeam-server .

# Runtime
FROM alpine:3.20
WORKDIR /app
COPY --from=build /app/bookbeam-server /app/bookbeam-server
COPY --from=build /app/web /app/web

# Data directory is mounted from host as /data
VOLUME ["/data"]

EXPOSE 8080
ENTRYPOINT ["/app/bookbeam-server"]
CMD ["-addr", ":8080", "-data", "/data"]
