# MyOAuth

Minimal OAuth 2.0/OIDC provider, OAuth 2.0 proxy.

Deployment is Docker-only: the supported way to run MyOAuth is `docker compose`
(see [Docker](#docker)). There is no native-binary or systemd run path.

## Development

The SPA is served same-origin from the Go server: it calls the API at the same
origin (`BASE` is `""` in production) and the server responds directly, so no
backend URL needs to be configured. The `/api/*` prefix is used only in local
development, where Vite proxies it to the backend (see below).

The built frontend is embedded into the Go server (see `web/embed.go`), so the
container image ships a single self-contained binary. Build the SPA into
`web/dist`, which is what `go:embed` picks up:

```shell
npm --prefix frontend ci
npm --prefix frontend run build
```

Run the checks:

```shell
go build ./...
go vet ./...
go test ./... -count=1
```

For local development, run `npm --prefix frontend run dev`. Vite proxies
`/api/*` to the backend, which defaults to `http://localhost:20476`. Override the
target with the **shell environment variable** `VITE_DEV_PROXY_TARGET` (no env
file is involved):

```shell
VITE_DEV_PROXY_TARGET=http://127.0.0.1:9999 npm --prefix frontend run dev
```

## Docker

The `Dockerfile` builds the SPA with Vite, compiles the Go server with the
assets embedded, and ships a small `alpine` runtime as a non-root user. The
runtime user is pinned to **uid 100 / gid 101**, so host files that the
container reads or writes must be owned by / writable to `100:101`. The SQLite
database and log file live outside the image and must be mounted as a volume so
data survives container upgrades.

The container publishes its port on the **loopback interface** only
(`127.0.0.1:20476`), so it is not reachable from other hosts by default; put a
reverse proxy (or the
[forward-auth](#forward-auth-replaces-oauth2-proxy) setup) in front of it for
external access.

### First run with Docker Compose

`docker-compose.yml` and a repo-root `.env.example` are provided. The whole
configuration is a handful of `.env` values plus a one-time key generation:

```shell
# 1. Create the env file from the example, then edit the values you need.
cp .env.example .env

# 2. Create the config from the Docker-ready example, then edit it if needed.
cp conf.example.json conf.json

# 3. Generate the RSA key (run via bash so it works on clones without +x).
bash scripts/gen_keys.sh oauth.private.pem

# 4. Create the data dir and hand both it and the key to the container user.
mkdir -p data
chown -R 100:101 data
chown 100:101 oauth.private.pem && chmod 640 oauth.private.pem

# 5. Start the stack.
docker compose up -d --build
```

The stack mounts (see `docker-compose.yml`):

- `./data:/data` – persistent SQLite database and log file
- `./conf.json:/config/conf.json:ro` – read-only configuration
- `./oauth.private.pem:/config/oauth.private.pem:ro` – read-only RSA key

The server listens on `http://127.0.0.1:20476`; a `HEALTHCHECK` polls `/health`.
The healthcheck port is coupled to `httpAddress` in `conf.json` — if you change
one, change the other.

### Configuration: `.env` overrides

`conf.example.json` is Docker-ready: container paths, `secureCookies: true`,
`trustProxy: true`, `allowedOrigins: []` and a disabled `forwardAuth` block are
already set. The values that differ per deployment are supplied through `.env`,
which `docker compose` loads into the container (see the `env_file` entry in
`docker-compose.yml`; the file is optional). The optional `env_file` long syntax
(`required: false`) needs **Docker Compose >= 2.24**; on older Compose drop the
`env_file` block (or upgrade Compose).

**Environment variables win over `conf.json`; an empty or unset variable leaves
the JSON value untouched**, so you only set what you need to change. Supported
variables (also listed, with notes, in `.env.example`):

| Variable | Overrides |
| --- | --- |
| `MYOAUTH_HTTP_ADDRESS` | `httpAddress` |
| `MYOAUTH_OIDC_ISSUER` | `oidcIssuer` |
| `MYOAUTH_OIDC_LOGIN_URL` | `oidcLoginUrl` |
| `MYOAUTH_INVITATION_CODE` | `invitationCode` |
| `MYOAUTH_ADMIN_PASSWORD` | `adminPassword` (bcrypt hash) |
| `MYOAUTH_SECURE_COOKIES` | `secureCookies` (bool) |
| `MYOAUTH_TRUST_PROXY` | `trustProxy` (bool) |
| `MYOAUTH_DB_PATH` | `dbPath` |
| `MYOAUTH_LOG_FILE_PATH` | `logFilePath` |
| `MYOAUTH_RSA_PRIVATE_KEY_PATH` | `rsaPrivateKeyPath` |
| `MYOAUTH_ALLOWED_ORIGINS` | `allowedOrigins` (comma-separated) |
| `MYOAUTH_PASSWORD_MIN_LENGTH` | `passwordMinLength` (int) |
| `MYOAUTH_FORWARD_AUTH_ENABLED` | `forwardAuth.enabled` (bool) |
| `MYOAUTH_FORWARD_AUTH_CLIENT_ID` | `forwardAuth.clientId` |
| `MYOAUTH_FORWARD_AUTH_CLIENT_SECRET` | `forwardAuth.clientSecret` |
| `MYOAUTH_FORWARD_AUTH_COOKIE_SECRET` | `forwardAuth.cookieSecret` |
| `MYOAUTH_FORWARD_AUTH_COOKIE_NAME` | `forwardAuth.cookieName` |
| `MYOAUTH_FORWARD_AUTH_COOKIE_DOMAIN` | `forwardAuth.cookieDomain` |
| `MYOAUTH_FORWARD_AUTH_COOKIE_SECURE` | `forwardAuth.cookieSecure` (bool) |
| `MYOAUTH_FORWARD_AUTH_ALLOWED_CALLBACK_ORIGINS` | `forwardAuth.allowedCallbackOrigins` (comma-separated) |
| `MYOAUTH_FORWARD_AUTH_ALLOWED_REDIRECT_DOMAINS` | `forwardAuth.allowedRedirectDomains` (comma-separated) |

Boolean variables accept `true/false/1/0/yes/no` case-insensitively; a malformed
value aborts the boot with a clear error.

The minimal edit for a typical deployment is `.env`:

- **`MYOAUTH_OIDC_ISSUER`** – public issuer URL used in discovery / the JWT
  `iss` claim, and the default forward-auth origin.
- **`MYOAUTH_OIDC_LOGIN_URL`** – hosted login page URL used by `/authorize`.
- **`MYOAUTH_ADMIN_PASSWORD`** – a **bcrypt hash**, not plaintext. `conf.json`
  ships with the literal placeholder `REPLACE_ME_WITH_A_BCRYPT_HASH`; the server
  only refuses an *empty* value, so replace it (or set this variable) before
  starting. Generate a hash with one of:

  ```shell
  # htpasswd (from apache2-utils / httpd-tools), cost 12:
  htpasswd -bnBC 12 "" 'YourStrongPassword' | tr -d ':\n'

  # or with the project's own helper:
  cat > /tmp/bcrypt.go <<'EOF'
  package main

  import (
      "fmt"
      "os"

      "github.com/zenpk/my-oauth/util"
  )

  func main() {
      hash, err := util.BCryptPassword(os.Args[1])
      if err != nil {
          panic(err)
      }
      fmt.Println(hash)
  }
  EOF
  go run /tmp/bcrypt.go 'YourStrongPassword'
  ```

- **`MYOAUTH_INVITATION_CODE`** – change the placeholder before going live.

`conf.example.json` already sets `secureCookies: true` (correct whenever the
server is served over HTTPS) and points `dbPath`/`logFilePath` under `/data` and
`rsaPrivateKeyPath` at `/config/oauth.private.pem`. No secrets are baked into the
image; the config and keys are supplied at runtime.

To use a different config path, override `command:` in `docker-compose.yml`. The
image's default `CMD` passes `-conf /config/conf.json`, and that flag takes
precedence over the optional `MYOAUTH_CONF` environment variable (see
`main.go`), so setting `MYOAUTH_CONF` alone has no effect.

> Building the image directly (`docker build -t myoauth:latest .`) also works,
> but Compose is the supported deployment path.

## OIDC Endpoints

- Discovery: `/.well-known/openid-configuration`
- JWKS: `/.well-known/jwks.json`
- Authorization endpoint: `/authorize` (Authorization Code + PKCE S256)
- Token endpoint: `/token` (`authorization_code` and `refresh_token` grants)
- UserInfo endpoint: `/userinfo`
- Login submit endpoint for hosted login page: `/auth/login`
- End session (RP-initiated logout) endpoint: `/logout`
- Token revocation endpoint: `/revoke` (RFC 7009)
- Token introspection endpoint: `/introspect` (RFC 7662)

`conf.json` supports these OIDC-related fields:

- `oidcIssuer`: issuer used in discovery + JWT issuer claim
- `oidcLoginUrl`: hosted login page URL used by `/authorize`

Rate limiting (applied to `/auth/login`, `/token`, and `/setup/admin-login`,
each with its own per-IP bucket) is controlled by:

- `rateLimitEnabled`: whether the limiter is active (default `true`)
- `rateLimitRequestsPerMinute`: token refill rate per client IP (default `30`)
- `rateLimitBurst`: maximum bucket size, i.e. allowed burst (default `10`)
- `rateLimitMaxKeys`: hard cap on tracked keys; new keys are denied once full
  (default `100000`), so memory cannot grow unbounded
- `trustProxy`: when `true`, the limiter trusts `X-Real-Ip` (preferred) or the
  right-most `X-Forwarded-For` entry to identify the client (default `false`).
  When `false`, forwarding headers are ignored and the socket peer is used, so a
  spoofed `X-Forwarded-For` cannot bypass the limiter. Set this to `true` only
  when running behind the bundled nginx, which overwrites `X-Real-IP` with
  `$remote_addr`.

A missing value keeps the default, so older `conf.json` files keep working.

`adminPassword` must be non-empty; the server refuses to start otherwise (an
empty value would make the admin session HMAC key empty).

## Forward auth (replaces oauth2-proxy)

MyOAuth can act as the forward-auth backend for nginx's `auth_request`
directive, replacing `oauth2-proxy`. nginx makes an internal subrequest to
`/oauth2/auth` for each protected request:

- **2xx (202)** – the request is allowed and the identity is exposed through
  response headers (`X-Auth-Request-User`, `X-Auth-Request-Preferred-Username`,
  `X-Auth-Request-Access-Token`) that nginx forwards to the upstream.
- **401** – the request is denied and nginx redirects the browser into the
  login flow (`/oauth2/start?rd=<original URI>`).

MyOAuth is an OIDC Relying Party of *its own provider*, running in the same
process. It performs the normal login → authorization-code + PKCE → token
exchange, then stores the OAuth tokens **server-side in SQLite** (`proxy_sessions`
table). The browser only ever receives an **opaque, high-entropy, HttpOnly session
id cookie** — the tokens never leave the server.

This design is required by `auth_request`: nginx never forwards a subrequest's
`Set-Cookie` to the browser, so a refresh that rotates tokens during the auth
subrequest could not update the browser cookie. With a server-side session the
`/oauth2/auth` subrequest rewrites the stored tokens in place and the *same*
cookie keeps working for the whole session lifetime.

- `/oauth2/callback` creates a `proxy_sessions` row (user UUID, display name,
  access token, refresh token, access expiry, absolute expiry) and sets the
  cookie to the row's random id.
- `/oauth2/auth` looks the session up by cookie; a missing/expired session is a
  `401`. If the access token has expired it refreshes it, updates the row, and
  allows the request — no `Set-Cookie` needed. An expired access token **with no
  refresh token** is a `401`, never a `202` with a dead token. Concurrent
  subrequests for the same session are serialised so exactly one refreshes and
  the rest reuse the refreshed token.
- `/oauth2/sign_out` deletes the session row, revokes its refresh token
  (`RevokeUserSessions`) and its outstanding access tokens
  (`TokenStore.RevokeAccessTokensByUserAndClient`), clears the cookie and
  redirects to a validated `rd`.

This is the second supported nginx deployment (the first is serving the OIDC
provider/SPA itself); see `nginx.forward-auth.example.conf` for a complete,
hardened location block.

### Host-aware flow (cross-host deployments)

The `/oauth2/*` endpoints are **host-aware**. By default (no
`allowedCallbackOrigins`) the single-host deployment is preserved and the
callback URI is the issuer origin. When `allowedCallbackOrigins` is set, the
protected app may live on a *different* host than the issuer (e.g. app
`nas.example.com`, issuer `auth.example.com`): nginx on the app host proxies
`/oauth2/*` to this service, and `/oauth2/start`, `/oauth2/callback` and the
session all live on the **app's own origin**.

- `/oauth2/start` derives the request origin from `X-Forwarded-Host` (falling
  back to `Host`) and `X-Forwarded-Proto` (falling back to the connection's
  scheme). If that origin is not in `allowedCallbackOrigins` it responds
  `400 invalid_request` — there is no silent fallback, so a misconfigured host
  is obvious. A spoofed header can only select another allowlisted origin, so
  it cannot create an open redirect.
- The chosen `redirect_uri` (`<origin><callbackPath>`) is stored in the state
  cookie and reused verbatim by `/oauth2/callback`, so no scheme/host
  re-derivation can drift between the two requests.
- Because the OAuth dance stays on the app host, the session cookie is
  **host-only** (no `Domain`), so a `__Host-`-prefixed `cookieName` works and a
  **relative** `rd` is all you need. `cookieDomain` remains an opt-in override
  for shared-domain setups.
- The managed proxy client's allowed redirects are unioned with
  `<origin><callbackPath>` for every effective origin (existing/manually-added
  redirects and the client's secret/ages are never changed).

Relative `rd` is the recommended path for cross-host; `safeReturnURL` and
`allowedRedirectDomains` still govern absolute `rd` URLs.

> **Fail-closed upgrade note.** Enabling the host-aware flow makes
> `/oauth2/start` require the derived request origin to **exactly** match an
> effective origin — `allowedCallbackOrigins` when set, otherwise the
> **issuer origin** (`oidcIssuer`) by default. A reverse proxy that forwards a
> `Host`/`X-Forwarded-Host` different from `oidcIssuer`, without listing that
> origin in `allowedCallbackOrigins`, will now receive a `400 invalid_request`
> (previously the callback URI was simply the issuer origin). This is an
> intentional security change: configure `allowedCallbackOrigins` with the app
> origin(s), or align the forwarded `Host` with `oidcIssuer`.

Enable it from `.env`: set `MYOAUTH_FORWARD_AUTH_ENABLED=true` together with the
required secrets (`MYOAUTH_FORWARD_AUTH_CLIENT_SECRET` and a
`MYOAUTH_FORWARD_AUTH_COOKIE_SECRET` of at least 32 characters). The shipped
`.env.example` leaves `MYOAUTH_FORWARD_AUTH_ENABLED` **commented out** so the
file never silently overrides `conf.json`. When you are **not** using `.env`,
enable the feature by setting the `forwardAuth` object in `conf.json` instead.
Either way the feature is disabled by default, so existing configs keep working
unchanged:

| Field | Default | Meaning |
| --- | --- | --- |
| `enabled` | `false` | Turns the whole feature on. When `false`, `/oauth2/*` returns a JSON 404 and the server behaves exactly as before. |
| `clientId` | `"proxy"` | The OIDC client used by the proxy. If no active client with this id exists, one is created automatically on startup. |
| `clientSecret` | – | **Required** when enabled. Secret for the proxy client. |
| `cookieSecret` | – | **Required** and at least 32 characters when enabled. Derives the AES-256-GCM key for the short-lived encrypted **state** cookie (`/oauth2/start` → `/oauth2/callback` CSRF + PKCE). Generate with `openssl rand -hex 32`. |
| `cookieName` | `"_myoauth_proxy"` | Session cookie name (carries only the opaque session id). The short-lived state cookie is `<cookieName>_state`. |
| `cookieDomain` | `""` | Optional cookie `Domain` attribute (opt-in override for shared-domain setups). Leave empty for **host-only** cookies, which is required for a `__Host-` cookieName. |
| `cookieSecure` | `false` | Sets `Secure` on the cookies. **Required (set `true`) whenever the flow is served over HTTPS** — without it the session/state cookies are sent over plain HTTP too. |
| `sessionTtlSeconds` | `0` | Session lifetime. `0` derives it from the proxy client's refresh-token age. |
| `loginPath` | `"/oauth2/start"` | Starts the login flow (`rd` = return URL). |
| `callbackPath` | `"/oauth2/callback"` | OIDC redirect URI suffix; `<origin><callbackPath>` is registered as an allowed redirect on the proxy client for every effective origin. |
| `authPath` | `"/oauth2/auth"` | `auth_request` subrequest target (GET/HEAD). |
| `signOutPath` | `"/oauth2/sign_out"` | Clears the session and redirects to a validated `rd`. |
| `allowedRedirectDomains` | `[]` | Extra hosts accepted for an absolute `rd` return URL. `rd` may always be a relative path (e.g. `/app`); anything else falls back to `/`. |
| `allowedCallbackOrigins` | `[]` | Exact origins (`scheme://host[:port]`, e.g. `"https://nas.example.com"`) allowed to run the login flow. Each origin's `<origin><callbackPath>` becomes an allowed redirect on the proxy client. Empty preserves the single-host default (the issuer origin). Malformed entries fail the boot. |

All `/oauth2/*` subpaths other than the configured endpoints return a JSON 404,
so the reserved namespace never falls through to the SPA.

Security notes: the state value is compared in constant time, the callback
requires the encrypted state cookie to match, PKCE (`S256`) is always used, the
ID token is fully verified (signature, issuer, audience, expiry), and the `rd`
return URL is validated against open redirects (exact host / default-port match
against `allowedRedirectDomains`, userinfo rejected, control characters and
percent-encoded path separators rejected in relative paths). Usernames
containing control characters are rejected at registration, and header values
are sanitized before they are returned. Client-supplied `X-Forwarded-*` headers
are never trusted for identity. `X-Forwarded-Host`/`X-Forwarded-Proto` are only
used to derive the request origin, which must match `allowedCallbackOrigins`
(or the issuer origin in the single-host default), so they cannot introduce an
open redirect.

**Header authorization:** upstreams must authorize on `X-Auth-Request-User`, the
immutable user UUID. `X-Auth-Request-Preferred-Username` is a mutable display
name and must not be used for access decisions. The nginx example blanks every
other `X-Auth-Request-*` header so clients cannot spoof identity.

If the forward-auth feature is enabled but its cookie codec cannot be built, the
server refuses to start rather than silently disabling the protection. The bare
`/oauth2` path returns a JSON 404 instead of redirecting to `/oauth2/`.
