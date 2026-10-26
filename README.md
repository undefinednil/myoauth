# MyOAuth

Self-contained OIDC / OAuth 2.0 provider with a hosted login SPA, an admin
console, and built-in forward auth for nginx.

- Authorization Code + PKCE (`S256`) OIDC provider: discovery, JWKS, UserInfo.
- Hosted login SPA and a small admin console, both embedded in the Go binary.
- Refresh tokens with per-device rotation; refresh-token revocation (RFC 7009)
  and introspection (RFC 7662).
- RP-initiated logout (`/logout`).
- Built-in OIDC **forward auth** for nginx `auth_request`, replacing
  `oauth2-proxy`.
- Per-IP rate limiting on the login, token, and admin-login endpoints.
- SQLite storage; configuration comes exclusively from environment variables.

Deployment is Docker-only: the supported way to run MyOAuth is `docker compose`.
There is no native-binary or systemd run path.

## Quick start (Docker)

```bash
# 1. Create the env file, then edit the three required values:
#    MYOAUTH_OIDC_ISSUER, MYOAUTH_ADMIN_PASSWORD, MYOAUTH_INVITATION_CODE.
cp .env.example .env

# 2. Create the data dir and hand it to the container user (uid 100 / gid 101).
mkdir -p data
chown -R 100:101 data

# 3. Build and start the stack.
docker compose up -d --build
```

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
  sessions (per client or all).
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

The three **required** variables below fail the boot when blank. Boolean
variables accept `true`/`false`/`1`/`0`/`yes`/`no` case-insensitively, and a
malformed value aborts the boot with a clear error; integer variables must parse.

| Variable | Default | Notes |
| --- | --- | --- |
| **Required** | | |
| `MYOAUTH_OIDC_ISSUER` | – | Public issuer URL (no trailing slash). Used in discovery and the JWT `iss` claim; also the default forward-auth origin. |
| `MYOAUTH_ADMIN_PASSWORD` | – | **bcrypt hash**, never plaintext. |
| `MYOAUTH_INVITATION_CODE` | – | Shared secret accepted by `/setup/register`, the only self-service signup path. |
| **Core** | | |
| `MYOAUTH_HTTP_ADDRESS` | `0.0.0.0:20476` | Listen address. |
| `MYOAUTH_OIDC_LOGIN_URL` | `<issuer>/login` | Hosted login page URL used by `/authorize`. |
| `MYOAUTH_SECURE_COOKIES` | `false` | Set the `Secure` flag on cookies (bool). |
| `MYOAUTH_TRUST_PROXY` | `false` | Trust `X-Real-Ip` / `X-Forwarded-For` for the client IP (bool). |
| `MYOAUTH_ALLOWED_ORIGINS` | – | Comma-separated CORS origins allowed to call the API. |
| `MYOAUTH_PASSWORD_MIN_LENGTH` | `8` | Minimum user password length (int). |
| `MYOAUTH_AUTHORIZATION_CODE_LENGTH` | `128` | Authorization code length (int). |
| `MYOAUTH_REFRESH_TOKEN_LENGTH` | `128` | Refresh token length (int). |
| **Storage** | | |
| `MYOAUTH_DB_PATH` | `myoauth.db` | SQLite database path. |
| `MYOAUTH_LOG_FILE_PATH` | `my-oauth.log` | Log file path. |
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
| `MYOAUTH_FORWARD_AUTH_COOKIE_SECURE` | `false` | Set `Secure` on the cookies (bool). |
| `MYOAUTH_FORWARD_AUTH_SESSION_TTL_SECONDS` | `0` | Session lifetime in seconds; `0` derives it from the proxy client's refresh-token age. |
| `MYOAUTH_FORWARD_AUTH_ALLOWED_CALLBACK_ORIGINS` | – | Comma-separated exact origins allowed to run the login flow. Malformed entries fail the boot. |
| `MYOAUTH_FORWARD_AUTH_ALLOWED_REDIRECT_DOMAINS` | – | Extra hosts accepted for an absolute `rd` return URL (comma-separated). |

The table lists the built-in defaults; the Docker image additionally sets ENV
defaults for the deployment paths, cookie flags, and the trust-proxy flag, which
is why those differ:
`MYOAUTH_HTTP_ADDRESS=0.0.0.0:20476`, `MYOAUTH_DB_PATH=/data/myoauth.db`,
`MYOAUTH_LOG_FILE_PATH=/data/my-oauth.log`,
`MYOAUTH_RSA_PRIVATE_KEY_PATH=/data/oauth.private.pem`,
`MYOAUTH_SECURE_COOKIES=true`, `MYOAUTH_TRUST_PROXY=true`. Override one in
`.env` only if you need to.

Generating the two secrets:

```bash
# Admin password -> bcrypt hash (cost 12). The hash contains `$`; if your
# Compose version warns about interpolation, escape each `$` as `$$` in `.env`.
htpasswd -bnBC 12 "" 'YourStrongPassword' | tr -d ':\n'
# (or use the project's own util.BCryptPassword helper; see .env.example)

# Forward-auth client secret and cookie secret (>= 32 chars each):
openssl rand -hex 32
```

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

The rate limiter applies to `/auth/login`, `/token`, and `/setup/admin-login`,
each with its own per-IP bucket.

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
- `/oauth2/sign_out` deletes the session row, revokes its refresh token and
  outstanding access tokens, clears the cookie, and redirects to a validated
  `rd`.

The login/callback/auth/sign-out paths are fixed (`/oauth2/start`,
`/oauth2/callback`, `/oauth2/auth`, `/oauth2/sign_out`) and are not configurable
through the environment. Any other `/oauth2/*` path (and the bare `/oauth2`)
returns a JSON 404, so the reserved namespace never falls through to the SPA.

Enable it from `.env` by setting `MYOAUTH_FORWARD_AUTH_ENABLED=true` together
with the two required secrets (`MYOAUTH_FORWARD_AUTH_CLIENT_SECRET` and a
`MYOAUTH_FORWARD_AUTH_COOKIE_SECRET` of at least 32 characters). The shipped
`.env.example` leaves `MYOAUTH_FORWARD_AUTH_ENABLED` commented out so a copied
file never enables the feature by accident; with it off (the default), `/oauth2/*`
returns a JSON 404 and the server behaves exactly as before. See
`nginx.forward-auth.example.conf` for a complete, hardened location block.

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
  scheme). If that origin is not in the allowlist it responds
  `400 invalid_request` — there is no silent fallback, so a misconfigured host
  is obvious. A spoofed header can only select another allowlisted origin, so it
  cannot create an open redirect.
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
are only used to derive the request origin, which must match the allowlist (or
the issuer origin by default), so they cannot introduce an open redirect.

**Header authorization:** upstreams must authorize on `X-Auth-Request-User`, the
immutable user UUID. `X-Auth-Request-Preferred-Username` is a mutable display
name and must not be used for access decisions. The nginx example blanks every
other `X-Auth-Request-*` header so clients cannot spoof identity.

If the feature is enabled but its cookie codec cannot be built (e.g. a too-short
`MYOAUTH_FORWARD_AUTH_COOKIE_SECRET`), the server refuses to start rather than
silently disabling the protection.

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

Run MyOAuth behind a TLS-terminating reverse proxy (nginx, Cloudflare, ...) and
set `MYOAUTH_SECURE_COOKIES=true` and `MYOAUTH_TRUST_PROXY=true`. The image
already defaults both to `true`, so this is the deployed default.

Keep `MYOAUTH_TRUST_PROXY=true` only when the proxy overwrites `X-Real-IP` with
the real client address (the shipped nginx does); otherwise the rate limiter
would trust attacker-controlled forwarding headers. When it is `false`, the
socket peer is used instead.

Two supported nginx deployments:

1. **Serve the provider/SPA** — proxy the issuer host to `127.0.0.1:20476`
   (see `nginx.conf`).
2. **Gate an app via forward auth** — see
   `nginx.forward-auth.example.conf`.

## License

MIT. See [LICENSE](LICENSE).
