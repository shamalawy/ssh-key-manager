# Build the Angular application.
FROM node:20-alpine AS frontend
WORKDIR /build

COPY frontend/package.json frontend/package-lock.json* ./
RUN npm ci --no-audit --no-fund 2>/dev/null || npm install --no-audit --no-fund

COPY frontend/ ./
RUN npm run build -- --configuration production


# Build the Go binaries with the frontend embedded.
FROM golang:1.26-alpine AS backend
WORKDIR /build

RUN apk add --no-cache git

COPY backend/go.mod backend/go.sum ./
RUN go mod download

COPY backend/ ./
# The Angular build lands where internal/web embeds from.
COPY --from=frontend /build/dist/skm/browser/ ./internal/web/dist/

# Static, stripped binaries so the final image needs no libc.
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/skm-server ./cmd/skm-server \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/skmctl    ./cmd/skmctl

# The runtime image has no shell, so the one writable directory has to be
# created here. Docker seeds a new named volume from the image's directory,
# including its ownership — without this the volume arrives root-owned and the
# non-root server cannot write a backup into it.
RUN mkdir -p /out/skm/backups && chown -R 65532:65532 /out/skm


# Minimal runtime: no shell, no package manager, non-root.
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=backend /out/skm-server /usr/local/bin/skm-server
COPY --from=backend /out/skmctl     /usr/local/bin/skmctl
COPY --from=backend --chown=65532:65532 /out/skm /var/lib/skm

USER nonroot:nonroot
EXPOSE 8080

# The binary answers its own health check, so the image needs no curl.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/usr/local/bin/skmctl", "health"]

ENTRYPOINT ["/usr/local/bin/skm-server"]
