# MyOAuth

Self-contained OIDC / OAuth 2.0 provider with a hosted login SPA, an admin
console, and built-in forward auth for nginx.

- Authorization Code + PKCE (`S256`) OIDC provider: discovery, JWKS, UserInfo.
- Hosted login SPA and a small admin console, both embedded in the Go binary.
- Refresh tokens with per-device rotation; refresh-token revocation (RFC 7009)
  and introspection (RFC 7662). Reusing an already-rotated refresh token is
  detected as replay and revokes the whole token chain (the user must log in
  again).
- RP-initiated logout (`/logout`).
- Built-in OIDC **forward auth** for nginx `auth_request`, replacing
  `oauth2-proxy`.
- Per-IP rate limiting on the login, token, registration, revocation,
  introspection, and admin-login endpoints.
- SQLite storage; configuration comes exclusively from environment variables.

Deployment is Docker-only: the supported way to run MyOAuth is `docker compose`.
There is no native-binary or systemd run path.

## Quick start (Docker)

```bash
# 1. Create the env file, then edit the three required values:
#    MYOAUTH_OIDC_ISSUER, MYOAUTH_ADMIN_PASSWORD, MYOAUTH_INVITATION_CODE.
#    Generate the admin hash first with: ./scripts/gen_bcrypt.sh
cp .env.example .env

# 2. Create the data dir and hand it to the container user (uid 100 / gid 101).
mkdir -p data
chown -R 100:101 data

# 3. Build and start the stack.
docker compose up -d --build
```

At minimum, `.env` must contain an **absolute `http(s)` issuer URL**, a valid
**bcrypt** admin hash (generate it with `./scripts/gen_bcrypt.sh`; the
placeholder from `.env.example` does not boot), and an invitation code of at
least 16 characters (the literal `change-me` is rejected). MyOAuth validates
all of this at boot and refuses to start with a clear error otherwise.

The container process listens on `0.0.0.0:20476` **inside** the container;
`docker compose` publishes that to the **host loopback** only
(`127.0.0.1:20476`), so it is not reachable from other hosts by default. Open
`http://127.0.0.1:20476/` to reach the admin console, and put a reverse proxy in
front for external access (see [Reverse proxy / TLS](#reverse-proxy--tls)).

The RSA signing key is generated automatically at `/data/oauth.private.pem` on
first boot and persists in the `./data` volume, so no key-generation step is
required. To manage the key explicitly instead, run
`bash scripts/gen_keys.sh oauth.private.pem` (optional; it reads no config file)
and point `MYOAUTH_RSA_PRIVATE_KEY_PATH` at the file.

## Admin & users

- **Admin:** open the issuer URL (in the container,
  `http://127.0.0.1:20476/`); the admin console at `/` prompts for the admin
  password (the plaintext matching the bcrypt hash in `MYOAUTH_ADMIN_PASSWORD`).
  From there you can create, edit, and delete OIDC clients and revoke user
  sessions (per client or all). Admin console sessions are server-side random
  IDs held **in memory**: restarting the server logs every admin out (users'
  refresh tokens and forward-auth sessions are in SQLite and survive).
- **Users:** self-service signup is only via
  `/register?invitationCode=<MYOAUTH_INVITATION_CODE>`, where the invitation
  code must match. The hosted login page for the OIDC flow is `/login`.

## Configuration (`.env`)

Configuration is env-only: MyOAuth reads **every** setting from `MYOAUTH_*`
environment variables. There is no configuration file. `docker compose` loads
`.env` into the container through the optional `env_file` entry (its
`required: false` long syntax needs **Docker Compose >= 2.24**; on older Compose
drop that block or upgrade). Unset or empty variables fall back to the defaults
below, so set only what you need.

Protect the env file: **`chmod 600 .env`** — it contains the admin bcrypt hash,
the invitation code, and any forward-auth secrets.

The three **required** variables below are validated at boot, not just checked
for emptiness:

- `MYOAUTH_OIDC_ISSUER` must be an absolute `http(s)` URL.
- `MYOAUTH_ADMIN_PASSWORD` must be a valid bcrypt hash; the `.env.example`
  placeholder (and any plaintext) fails the boot — generate a hash with
  `./scripts/gen_bcrypt.sh`.
- `MYOAUTH_INVITATION_CODE` must be at least 16 characters, and the literal
  `change-me` is rejected.

Two more values are range/format-checked: `MYOAUTH_PASSWORD_MIN_LENGTH` must be
`1..72` (the bcrypt input limit), and every `MYOAUTH_ALLOWED_ORIGINS` entry must
be a well-formed origin. Boolean variables accept
`true`/`false`/`1`/`0`/`yes`/`no` case-insensitively, and a malformed value
aborts the boot with a clear error; integer variables must parse.

| Variable | Default | Notes |
| --- | --- | --- |
| **Required** | | |
| `MYOAUTH_OIDC_ISSUER` | – | Public issuer URL (no trailing slash); must be an absolute `http(s)` URL or the boot fails. Used in discovery and the JWT `iss` claim; also the default forward-auth origin. |
| `MYOAUTH_ADMIN_PASSWORD` | – | **bcrypt hash** (cost 12), never plaintext; must parse as a bcrypt hash or the boot fails. Generate with `scripts/gen_bcrypt.sh` (see below). |
| `MYOAUTH_INVITATION_CODE` | – | Shared secret accepted by `/setup/register`, the only self-service signup path. At least 16 characters; `change-me` is rejected at boot. |
| **Core** | | |
| `MYOAUTH_HTTP_ADDRESS` | `0.0.0.0:20476` | Listen address. |
| `MYOAUTH_OIDC_LOGIN_URL` | `<issuer>/login` | Hosted login page URL used by `/authorize`. |
| `MYOAUTH_SECURE_COOKIES` | `true` | Set the `Secure` flag on cookies (bool). Keep `true` behind TLS; set `false` only for plain-HTTP local development (browsers drop Secure cookies over HTTP). |
| `MYOAUTH_TRUST_PROXY` | `false` | Trust `X-Real-Ip` / `X-Forwarded-For` for the client IP, and honor `X-Forwarded-Host`/`X-Forwarded-Proto` for forward-auth origin derivation (bool). |
| `MYOAUTH_ALLOWED_ORIGINS` | – | Comma-separated CORS origins allowed to call the API. Every entry is validated at boot; malformed entries abort the start. |
| `MYOAUTH_PASSWORD_MIN_LENGTH` | `8` | Minimum user password length (int, `1..72`; out-of-range fails the boot). |
| `MYOAUTH_AUTHORIZATION_CODE_LENGTH` | `128` | Authorization code length (int). |
| `MYOAUTH_REFRESH_TOKEN_LENGTH` | `128` | Refresh token length (int). |
| **Storage** | | |
| `MYOAUTH_DB_PATH` | `myoauth.db` | SQLite database path (file created `0600`). |
| `MYOAUTH_LOG_FILE_PATH` | `myoauth.log` | Log file path (created `0600`), or `stdout` / `-` to log to stdout instead of a file. |
| `MYOAUTH_RSA_PRIVATE_KEY_PATH` | `oauth.private.pem` | RSA signing key; auto-generated if absent. A missing parent directory is a hard error. |
| **Rate limit** | | |
| `MYOAUTH_RATE_LIMIT_ENABLED` | `true` | Enable the per-IP limiter (bool). |
| `MYOAUTH_RATE_LIMIT_REQUESTS_PER_MINUTE` | `30` | Token refill rate per client IP (int). |
| `MYOAUTH_RATE_LIMIT_BURST` | `10` | Maximum bucket size, i.e. allowed burst (int). |
| `MYOAUTH_RATE_LIMIT_MAX_KEYS` | `100000` | Hard cap on tracked keys; new keys are denied once full (int). |
| **Forward auth** | | |
| `MYOAUTH_FORWARD_AUTH_ENABLED` | `false` | Turn the whole feature on (bool). |
| `MYOAUTH_FORWARD_AUTH_CLIENT_ID` | `proxy` | OIDC client used by the proxy; created automatically if absent. |
| `MYOAUTH_FORWARD_AUTH_CLIENT_SECRET` | – | Required when enabled. |
| `MYOAUTH_FORWARD_AUTH_COOKIE_SECRET` | – | Required when enabled; at least 32 characters. |
| `MYOAUTH_FORWARD_AUTH_COOKIE_NAME` | `_myoauth_proxy` | Session cookie name (carries only the opaque session id). |
| `MYOAUTH_FORWARD_AUTH_COOKIE_DOMAIN` | – | Optional cookie `Domain`; leave empty for host-only cookies. |
| `MYOAUTH_FORWARD_AUTH_COOKIE_SECURE` | `true` | Set `Secure` on the cookies (bool). Keep `true` behind TLS; set `false` only for plain-HTTP local development. |
| `MYOAUTH_FORWARD_AUTH_SESSION_TTL_SECONDS` | `0` | Session lifetime in seconds; `0` derives it from the proxy client's refresh-token age. |
| `MYOAUTH_FORWARD_AUTH_ALLOWED_CALLBACK_ORIGINS` | – | Comma-separated exact origins allowed to run the login flow. Malformed entries fail the boot. |
| `MYOAUTH_FORWARD_AUTH_ALLOWED_REDIRECT_DOMAINS` | – | Extra hosts accepted for an absolute `rd` return URL (comma-separated). |

The table lists the built-in defaults; the Docker image additionally sets the
deployment paths and the trust-proxy flag, which is why those differ:
`MYOAUTH_HTTP_ADDRESS=0.0.0.0:20476`, `MYOAUTH_DB_PATH=/data/myoauth.db`,
`MYOAUTH_LOG_FILE_PATH=/data/myoauth.log`,
`MYOAUTH_RSA_PRIVATE_KEY_PATH=/data/oauth.private.pem`,
`MYOAUTH_TRUST_PROXY=true` (it also pins `MYOAUTH_SECURE_COOKIES=true`, which is
the built-in default anyway). Override one in `.env` only if you need to.

Generating the secrets:

```bash
# Admin password -> bcrypt hash (cost 12). Prompts for a hidden password, or
# accepts it on stdin / as an argument:
./scripts/gen_bcrypt.sh

# Invitation code for MYOAUTH_INVITATION_CODE (>= 16 characters):
openssl rand -hex 24

# Forward-auth client secret and cookie secret (>= 32 chars each):
openssl rand -hex 32
```

The script uses the project's own bcrypt implementation, so the hash format and
cost always match the server. A bcrypt hash contains `$`; if your Compose
version warns about interpolation, escape each `$` as `$$` in `.env`.

## OIDC endpoints

All OIDC paths are relative to `MYOAUTH_OIDC_ISSUER`.

- Discovery: `/.well-known/openid-configuration`
- JWKS: `/.well-known/jwks.json`
- Authorization: `/authorize` (Authorization Code + PKCE `S256`; accepts `nonce`)
- Token: `/token` (`authorization_code` and `refresh_token` grants;
  `client_secret_post` and `client_secret_basic`)
- UserInfo: `/userinfo`
- Hosted login submit: `/auth/login`
- RP-initiated logout: `/logout`
- Token revocation: `/revoke` (RFC 7009)
- Token introspection: `/introspect` (RFC 7662)

Discovery advertises the issuer, every endpoint URL, `RS256` signing, the `code`
response type, `openid`/`profile` scopes, the grants above, and the `S256`
challenge method. JWKS responses are cacheable (`Cache-Control:
public, max-age=86400`).

The rate limiter applies to `/auth/login`, `/token`, `/setup/admin-login`,
`/setup/register`, `/introspect`, and `/revoke`, each with its own per-IP
bucket. Failed authentication on the token-family endpoints returns `401`/`400`
(never a `200` with an error body), and security-relevant events — logins,
failed logins, and admin actions — are written to the log with timestamps.

## Forward auth (replaces oauth2-proxy)

MyOAuth can act as the forward-auth backend for nginx's `auth_request`
directive, replacing `oauth2-proxy`. nginx makes an internal subrequest to
`/oauth2/auth` for each protected request:

- **202** – allow; the identity is exposed through response headers
  (`X-Auth-Request-User`, `X-Auth-Request-Preferred-Username`,
  `X-Auth-Request-Access-Token`) that nginx forwards to the upstream.
- **401** – deny; nginx sends the browser into the login flow
  (`/oauth2/start?rd=<original URI>`).

MyOAuth is an OIDC Relying Party of *its own provider*, running in the same
process: it performs the normal login → authorization-code + PKCE → token
exchange, then stores the OAuth tokens **server-side in SQLite**
(`proxy_sessions`). Apart from the short-lived encrypted state cookie used
during login, the browser only receives an **opaque, high-entropy, HttpOnly
session-id cookie** — the tokens never leave the server.

This design is required by `auth_request`: nginx never forwards a subrequest's
`Set-Cookie` to the browser, so a refresh that rotates tokens during the auth
subrequest could not update the browser cookie. With a server-side session,
`/oauth2/auth` rewrites the stored tokens in place and the *same* cookie keeps
working for the whole session lifetime.

- `/oauth2/callback` creates a `proxy_sessions` row (user UUID, display name,
  access token, refresh token, access/absolute expiry) and sets the cookie to
  the row's random id.
- `/oauth2/auth` looks the session up by cookie; a missing/expired session is a
  `401`. If the access token has expired it refreshes it, updates the row, and
  allows the request — no `Set-Cookie` needed. An expired access token **with no
  refresh token** is a `401`, never a `202` with a dead token. Concurrent
  subrequests for the same session are serialised so exactly one refreshes.
- `/oauth2/sign_out` is **POST-only** (a GET returns `405 Method Not Allowed`,
  because a plain logout link would be a cross-site logout / CSRF vector): it
  deletes the session row, revokes its refresh token and outstanding access
  tokens, clears the cookie, and redirects to a validated `rd`.

The login/callback/auth/sign-out paths are fixed (`/oauth2/start`,
`/oauth2/callback`, `/oauth2/auth`, `/oauth2/sign_out`) and are not configurable
through the environment. Any other `/oauth2/*` path (and the bare `/oauth2`)
returns a JSON 404, so the reserved namespace never falls through to the SPA.

Enable it from `.env` by setting `MYOAUTH_FORWARD_AUTH_ENABLED=true` together
with the two required secrets (`MYOAUTH_FORWARD_AUTH_CLIENT_SECRET` and a
`MYOAUTH_FORWARD_AUTH_COOKIE_SECRET` of at least 32 characters). The
cross-host flow additionally requires `MYOAUTH_TRUST_PROXY=true` (the image
default) so the `X-Forwarded-*` origin headers below are honored. The shipped
`.env.example` leaves `MYOAUTH_FORWARD_AUTH_ENABLED` commented out so a copied
file never enables the feature by accident; with it off (the default), `/oauth2/*`
returns a JSON 404 and the server behaves exactly as before. See
`nginx.forward-auth.example.conf` for a complete, hardened location block
(including WebSocket pass-through for the protected upstream).

### Host-aware flow (cross-host deployments)

The `/oauth2/*` endpoints are **host-aware**. By default (no
`MYOAUTH_FORWARD_AUTH_ALLOWED_CALLBACK_ORIGINS`) the single-host deployment is
preserved and the callback URI is the issuer origin plus the callback path
(`<issuer>/oauth2/callback`). When allowed callback
origins are set, the protected app may live on a *different* host than the
issuer (e.g. app `nas.example.com`, issuer `auth.example.com`): nginx on the app
host proxies `/oauth2/*` to this service, and `/oauth2/start`, `/oauth2/callback`
and the session all live on the **app's own origin**.

- `/oauth2/start` derives the request origin from `X-Forwarded-Host` (falling
  back to `Host`) and `X-Forwarded-Proto` (falling back to the connection's
  scheme), **but only when `MYOAUTH_TRUST_PROXY=true`** (the image default).
  With the flag `false` both forwarded headers are ignored entirely and the
  request's own `Host` / connection scheme are used. If the derived origin is
  not in the allowlist it responds `400 invalid_request` — there is no silent
  fallback, so a misconfigured host is obvious. A spoofed header can only
  select another allowlisted origin, so it cannot create an open redirect.
- The chosen `redirect_uri` (`<origin><callbackPath>`) is stored in the state
  cookie and reused verbatim by `/oauth2/callback`, so no scheme/host
  re-derivation can drift between the two requests.
- Because the OAuth dance stays on the app host, the session cookie is
  **host-only** (no `Domain`), so a `__Host-`-prefixed `cookieName` works and a
  **relative** `rd` is all you need. `MYOAUTH_FORWARD_AUTH_COOKIE_DOMAIN` remains
  an opt-in override for shared-domain setups.
- The managed proxy client's allowed redirects are unioned with
  `<origin><callbackPath>` for every effective origin; existing/manually-added
  redirects and the client's secret/ages are never changed.

Relative `rd` is the recommended path for cross-host; `safeReturnURL` and
`MYOAUTH_FORWARD_AUTH_ALLOWED_REDIRECT_DOMAINS` still govern absolute `rd` URLs.

> **Fail-closed upgrade note.** Enabling the host-aware flow makes
> `/oauth2/start` require the derived request origin to **exactly** match an
> effective origin — the allowed callback origins when set, otherwise the
> **issuer origin** (`MYOAUTH_OIDC_ISSUER`) by default. A reverse proxy that
> forwards a `Host`/`X-Forwarded-Host` different from the issuer, without listing
> that origin, now receives a `400 invalid_request` (previously the callback URI
> was simply the issuer origin). This is an intentional security change:
> configure the app origin(s), or align the forwarded `Host` with the issuer.

### Security notes

The state value is compared in constant time, the callback requires the
encrypted state cookie to match, PKCE (`S256`) is always used, the ID token is
fully verified (signature, issuer, audience, expiry), and the `rd` return URL is
validated against open redirects (exact host / default-port match against
`MYOAUTH_FORWARD_AUTH_ALLOWED_REDIRECT_DOMAINS`, userinfo rejected, control
characters and percent-encoded path separators rejected in relative paths).
Usernames containing control characters are rejected at registration, and header
values are sanitized before they are returned. Client-supplied `X-Forwarded-*`
headers are never trusted for identity; `X-Forwarded-Host`/`X-Forwarded-Proto`
are only honored when `MYOAUTH_TRUST_PROXY=true` and used solely to derive the
request origin, which must match the allowlist (or the issuer origin by
default), so they cannot introduce an open redirect.

**Header authorization:** upstreams must authorize on `X-Auth-Request-User`, the
immutable user UUID. `X-Auth-Request-Preferred-Username` is a mutable display
name and must not be used for access decisions. The nginx example blanks every
other `X-Auth-Request-*` header so clients cannot spoof identity.

If the feature is enabled but its cookie codec cannot be built (e.g. a too-short
`MYOAUTH_FORWARD_AUTH_COOKIE_SECRET`), the server refuses to start rather than
silently disabling the protection.

## Backup and restore

Everything stateful lives in the `/data` volume:

- `myoauth.db` — users, clients, refresh/access tokens, and forward-auth
  sessions (SQLite also keeps `-wal` / `-shm` sidecar files while running).
- `oauth.private.pem` — the RSA signing key. Without it every outstanding token
  is invalid after a restore (see [Upgrades and rollback](#upgrades-and-rollback)).
- `myoauth.log` — optional, only if `MYOAUTH_LOG_FILE_PATH` points at a file.

**Live backup (WAL-safe).** With the server running, use SQLite's online backup
API; it produces a consistent snapshot without stopping the container:

```bash
sqlite3 data/myoauth.db ".backup 'backup.db'"   # -wal/-shm are folded in
chmod 600 backup.db
```

**Offline copy.** To copy files instead, stop the container first so the WAL is
checkpointed, then copy the database (including sidecars) and the key:

```bash
docker compose stop
cp -a data/myoauth.db data/myoauth.db-wal data/myoauth.db-shm /backup/ 2>/dev/null || true
cp -a data/oauth.private.pem /backup/
docker compose start
```

**Restore:**

1. `docker compose down` — never replace files under a running server.
2. Put the backup in place: replace `data/myoauth.db` (plus `-wal`/`-shm` from
   the *same* snapshot; delete stale ones that do not match), and restore
   `oauth.private.pem` if you want the same signing key back.
3. Keep the container ownership: `chown -R 100:101 data` (the process runs as
   uid 100 / gid 101).
4. `docker compose up -d` and verify with
   `curl -fsS http://127.0.0.1:20476/health` — a `200` means the DB opened; the
   endpoint returns `503` when it cannot.

Backups contain password hashes, live refresh/access tokens, and forward-auth
session ids: store them `chmod 600` and treat them like the original `/data`
volume.

## Upgrades and rollback

**Schema migrations are automatic.** On boot MyOAuth runs idempotent migrations
tracked with SQLite `PRAGMA user_version` (it also sets `busy_timeout` and
enables `foreign_keys` per connection, and checkpoints the WAL on graceful
shutdown). There is no separate migration command.

Upgrade procedure:

1. **Back up first** — see [Backup and restore](#backup-and-restore).
   Migrations are forward-only, so a rollback needs a pre-upgrade DB copy.
2. Pull the new image (or rebuild) and `docker compose up -d`.
3. Watch `docker compose logs -f` and `curl http://127.0.0.1:20476/health`.

**Rollback.** Pin production to a versioned image tag instead of `latest`
(e.g. `image: myoauth:1.4.0` in `docker-compose.yml`; the compose file builds
`myoauth:latest` by default, so tag what you build). Then:

1. Stop the stack.
2. Restore the pre-upgrade database backup (the newer schema may not be
   readable by the old binary).
3. Point `image:` back at the previous tag and start.

**RSA key rotation.** Replace the key file (`/data/oauth.private.pem`, or the
path in `MYOAUTH_RSA_PRIVATE_KEY_PATH`) and restart. Consequences:

- All outstanding ID/access/refresh tokens signed with the old key are
  invalidated — sessions fail closed.
- Relying parties pick up the new public key from `/.well-known/jwks.json`,
  but that response is cached for up to **86400 seconds**
  (`Cache-Control: public, max-age=86400`), so allow up to a day for aggressive
  caches to converge.
- Keep the old private key until you are sure you no longer need to validate
  its tokens.

## Operations

### Logs

- `MYOAUTH_LOG_FILE_PATH=/data/myoauth.log` (the image default) writes to a
  file created mode **`0600`**, with timestamps. Follow it with
  `docker compose exec myoauth tail -f /data/myoauth.log`.
- `MYOAUTH_LOG_FILE_PATH=stdout` (or `-`) logs to stdout instead — pair this
  with `docker compose logs -f`.
- Docker's default `json-file` log driver grows without bound. Add rotation to
  the service (or in `daemon.json`):

  ```yaml
  logging:
    driver: json-file
    options:
      max-size: "10m"
      max-file: "5"
  ```

- Security events — logins, failed logins, and admin actions — are logged with
  timestamps.

### Health and metrics

- `GET /health` is **DB-aware**: it pings SQLite and returns `200` when the
  database answers, `503` after a DB failure. Both the image `HEALTHCHECK` and
  the compose healthcheck rely on it.
- `GET /metrics` exposes runtime/process counters in expvar JSON format. Like
  `/health` it is unauthenticated, so keep it on the internal network or
  restrict it at the reverse proxy instead of exposing it publicly.
- Monitor free disk space on the `/data` volume: SQLite grows with users,
  tokens, and forward-auth sessions, and a full disk means failing writes.
  Alert well before the volume fills.

### Restarts and in-memory state

- The per-IP **rate limiter is in memory**: a restart resets all buckets.
- **Admin console sessions are in memory** as well: restarting the server
  invalidates every admin session (admins must log in again). This is by
  design — there is no admin session store to leak, and no session survives a
  crash.
- Persistent state (users, clients, refresh tokens, forward-auth sessions, RSA
  key) lives in `/data` and survives restarts.

## Development

The SPA is served same-origin from the Go server, so no backend URL is
configured in production (the frontend `BASE` is `""`). The `/api/*` prefix is
used only in local development, where Vite proxies it to the backend.

The built frontend is embedded into the Go server (see `web/embed.go`), so the
container image ships a single self-contained binary. Build the SPA into
`web/dist`, which is what `go:embed` picks up:

```bash
npm --prefix frontend ci
npm --prefix frontend run build
```

Run the checks:

```bash
go build ./...
go vet ./...
go test ./... -count=1
```

For local development, run `npm --prefix frontend run dev`. Vite proxies `/api/*`
to the backend, which defaults to `http://localhost:20476`. Override the target
with the **shell environment variable** `VITE_DEV_PROXY_TARGET` (no env file is
involved):

```bash
VITE_DEV_PROXY_TARGET=http://127.0.0.1:9999 npm --prefix frontend run dev
```

## Reverse proxy / TLS

Run MyOAuth behind a TLS-terminating reverse proxy (nginx, Cloudflare, ...).
`MYOAUTH_SECURE_COOKIES` defaults to `true`, and the image also sets
`MYOAUTH_TRUST_PROXY=true`, so the deployable defaults are already the safe
ones.

Keep `MYOAUTH_TRUST_PROXY=true` only when the proxy overwrites `X-Real-IP` with
the real client address (the shipped nginx does); otherwise the rate limiter
would trust attacker-controlled forwarding headers — and
`X-Forwarded-Host`/`X-Forwarded-Proto` would be accepted for forward-auth origin
derivation as well. When it is `false`, the socket peer and the request's own
`Host` / connection scheme are used instead.

Two supported nginx deployments:

1. **Serve the provider/SPA** — proxy the issuer host to `127.0.0.1:20476`
   (see `nginx.conf`). The shipped file sets `server_tokens off`, logs the
   method and URI **without the query string** (so `/authorize?code=...` and
   `/logout?id_token_hint=...` secrets never land in access logs), and includes
   a commented HTTPS server block with an HTTP→HTTPS redirect and HSTS
   (`Strict-Transport-Security "max-age=63072000; includeSubDomains" always`).
   Enable it once certificates are installed.
2. **Gate an app via forward auth** — see
   `nginx.forward-auth.example.conf` (includes WebSocket pass-through and
   requires `MYOAUTH_TRUST_PROXY=true` for the cross-host origin derivation).

## License

MIT. See [LICENSE](LICENSE).
