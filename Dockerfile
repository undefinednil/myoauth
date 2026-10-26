# syntax=docker/dockerfile:1

# =============================================================================
# Stage A - build the React SPA (Vite)
# =============================================================================
FROM node:22-alpine AS frontend
WORKDIR /app

# Install dependencies from the lockfile for reproducible builds.
COPY frontend/package.json frontend/package-lock.json ./frontend/
RUN cd frontend && npm ci

# Copy the rest of the frontend sources (node_modules is excluded by
# .dockerignore, so this does not clobber the install above).
COPY frontend/ ./frontend/

# vite.config.ts sets `outDir: "../web/dist"` relative to the Vite project root.
# The frontend lives in /app/frontend (mirroring the repo layout), so running
# the build there writes to /app/web/dist. mkdir -p guards the outDir.
RUN cd frontend \
    && mkdir -p /app/web \
    && npm run build \
    && test -f /app/web/dist/index.html

# =============================================================================
# Stage B - build the Go binary with the SPA embedded
# =============================================================================
FROM golang:1.26-alpine AS backend
WORKDIR /src

# Cache module downloads separately from the sources.
COPY go.mod go.sum ./
RUN go mod download

# Copy the Go sources (never the built assets from the build context).
COPY main.go ./
COPY dal ./dal
COPY handler ./handler
COPY service ./service
COPY token ./token
COPY util ./util
COPY web ./web

# The SPA build output from stage A is the only web/dist the embed sees; it is
# intentionally not provided via the build context (see .dockerignore).
COPY --from=frontend /app/web/dist ./web/dist

# SQLite is pure Go (github.com/glebarez/go-sqlite), so CGO can stay disabled.
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/myoauth .

# =============================================================================
# Stage C - minimal runtime
# =============================================================================
# alpine instead of distroless: the HEALTHCHECK below needs a shell and an HTTP
# client (wget, provided by busybox), which distroless images do not ship.
FROM alpine:3.22 AS runtime

# The runtime user is pinned to uid 100 / gid 101 so that host bind mounts can
# be chowned deterministically (e.g. `chown -R 100:101 data`).
RUN apk add --no-cache ca-certificates \
    && addgroup -S -g 101 myoauth \
    && adduser -S -u 100 -G myoauth myoauth \
    && mkdir -p /data \
    && chown -R myoauth:myoauth /data

COPY --from=backend /out/myoauth /usr/local/bin/myoauth

# Container defaults. `.env` (or `docker compose` `environment`) only needs the
# per-deployment values (e.g. MYOAUTH_OIDC_ISSUER and MYOAUTH_ADMIN_PASSWORD);
# everything else falls back to these. The RSA signing key is auto-generated in
# /data on first boot unless MYOAUTH_RSA_PRIVATE_KEY_PATH points elsewhere.
ENV MYOAUTH_HTTP_ADDRESS=0.0.0.0:20476 \
    MYOAUTH_DB_PATH=/data/myoauth.db \
    MYOAUTH_LOG_FILE_PATH=/data/my-oauth.log \
    MYOAUTH_RSA_PRIVATE_KEY_PATH=/data/oauth.private.pem \
    MYOAUTH_SECURE_COOKIES=true \
    MYOAUTH_TRUST_PROXY=true

# Writable directory for the SQLite database, log file and auto-generated key
# (mount a volume here so they survive container upgrades).
WORKDIR /data
EXPOSE 20476

# Runs as uid:gid 100:101 (non-root). Host-mounted files the container reads or
# writes must be owned by / writable to 100:101 (see docker-compose.yml).
USER myoauth

# Configuration comes exclusively from the environment (see the ENV block
# above); there is no config-file argument.
ENTRYPOINT ["myoauth"]

# NOTE: this healthcheck port (20476) is coupled to MYOAUTH_HTTP_ADDRESS;
# changing one requires changing the other.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget -q -O- http://127.0.0.1:20476/health || exit 1
