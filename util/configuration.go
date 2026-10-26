package util

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
)

// Configuration holds the runtime configuration. It is populated exclusively
// from MYOAUTH_* environment variables (see applyEnvOverrides) plus the
// built-in defaults (see applyDefaults) — there is no configuration file.
type Configuration struct {
	HttpAddress                string
	AllowedOrigins             []string
	SecureCookies              bool
	OidcIssuer                 string
	OidcLoginUrl               string
	InvitationCode             string
	AdminPassword              string
	AuthorizationCodeLength    int
	RefreshTokenLength         int
	PasswordMinLength          int
	DbPath                     string
	LogFilePath                string
	RsaPrivateKeyPath          string
	RateLimitEnabled           *bool
	RateLimitRequestsPerMinute int
	RateLimitBurst             int
	RateLimitMaxKeys           int
	TrustProxy                 bool
	ForwardAuth                *ForwardAuthConfig
}

// ForwardAuthConfig configures the built-in OIDC forward-auth service that
// replaces oauth2-proxy's `auth_request` role. The whole feature is opt-in: a
// nil value (or enabled=false) keeps the server behaving exactly as before.
type ForwardAuthConfig struct {
	Enabled                bool
	ClientId               string
	ClientSecret           string
	CookieSecret           string
	CookieName             string
	CookieDomain           string
	CookieSecure           bool
	SessionTtlSeconds      int
	LoginPath              string
	CallbackPath           string
	AuthPath               string
	SignOutPath            string
	AllowedRedirectDomains []string
	// AllowedCallbackOrigins lists the exact origins (scheme + host[:port],
	// e.g. "https://nas.example.com") of the protected applications whose host
	// may complete the forward-auth login flow. This makes `/oauth2/*`
	// host-aware: the login/callback/session all live on the app's own origin,
	// so a `__Host-`-prefixed cookieName works and a relative `rd` needs no
	// cookieDomain. Each origin's `<origin><callbackPath>` is registered as an
	// allowed redirect_uri on the managed proxy client. When empty, the issuer
	// origin is used, preserving the single-host deployment.
	AllowedCallbackOrigins []string
}

// Init builds the effective configuration from the environment only:
// MYOAUTH_* variables are applied on top of the zero value, then the required
// fields are checked and the defaults/validation run. There is no config file
// argument and no file is read.
func (c *Configuration) Init() error {
	if err := c.applyEnvOverrides(); err != nil {
		return err
	}
	if strings.TrimSpace(c.OidcIssuer) == "" {
		return errors.New("oidcIssuer is required")
	}
	// An empty admin password makes the admin session HMAC key empty, allowing
	// forged admin sessions and defeating CSRF (FIX F6).
	if strings.TrimSpace(c.AdminPassword) == "" {
		return errors.New("adminPassword is required")
	}
	// An empty invitation code makes /setup/register (the only self-service
	// signup path) accept an empty code, i.e. open registration. Require it.
	if strings.TrimSpace(c.InvitationCode) == "" {
		return errors.New("invitationCode is required")
	}
	c.OidcIssuer = strings.TrimSuffix(strings.TrimSpace(c.OidcIssuer), "/")
	c.applyDefaults()
	if err := c.validateForwardAuth(); err != nil {
		return err
	}
	return nil
}

func (c *Configuration) applyDefaults() {
	if strings.TrimSpace(c.HttpAddress) == "" {
		c.HttpAddress = "0.0.0.0:20476"
	}
	if strings.TrimSpace(c.DbPath) == "" {
		c.DbPath = "myoauth.db"
	}
	if strings.TrimSpace(c.LogFilePath) == "" {
		c.LogFilePath = "my-oauth.log"
	}
	if strings.TrimSpace(c.RsaPrivateKeyPath) == "" {
		c.RsaPrivateKeyPath = "oauth.private.pem"
	}
	if c.AuthorizationCodeLength <= 0 {
		c.AuthorizationCodeLength = 128
	}
	if c.RefreshTokenLength <= 0 {
		c.RefreshTokenLength = 128
	}
	if c.PasswordMinLength <= 0 {
		c.PasswordMinLength = 8
	}
	if c.RateLimitEnabled == nil {
		enabled := true
		c.RateLimitEnabled = &enabled
	}
	if c.RateLimitRequestsPerMinute <= 0 {
		c.RateLimitRequestsPerMinute = 30
	}
	if c.RateLimitBurst <= 0 {
		c.RateLimitBurst = 10
	}
	if c.RateLimitMaxKeys <= 0 {
		c.RateLimitMaxKeys = 100000
	}
	if c.ForwardAuth != nil {
		fa := c.ForwardAuth
		if strings.TrimSpace(fa.ClientId) == "" {
			fa.ClientId = "proxy"
		}
		if strings.TrimSpace(fa.CookieName) == "" {
			fa.CookieName = "_myoauth_proxy"
		}
		if strings.TrimSpace(fa.LoginPath) == "" {
			fa.LoginPath = "/oauth2/start"
		}
		if strings.TrimSpace(fa.CallbackPath) == "" {
			fa.CallbackPath = "/oauth2/callback"
		}
		if strings.TrimSpace(fa.AuthPath) == "" {
			fa.AuthPath = "/oauth2/auth"
		}
		if strings.TrimSpace(fa.SignOutPath) == "" {
			fa.SignOutPath = "/oauth2/sign_out"
		}
	}
}

func (c *Configuration) validateForwardAuth() error {
	fa := c.ForwardAuth
	if fa == nil || !fa.Enabled {
		return nil
	}
	if strings.TrimSpace(fa.ClientSecret) == "" {
		return errors.New("forwardAuth.clientSecret is required when forwardAuth is enabled")
	}
	if strings.TrimSpace(fa.CookieSecret) == "" {
		return errors.New("forwardAuth.cookieSecret is required when forwardAuth is enabled")
	}
	// A short cookie secret would weaken AES-256-GCM, whose key is derived from
	// it, so refuse to boot (FIX-style fail fast).
	if len(fa.CookieSecret) < 32 {
		return errors.New("forwardAuth.cookieSecret must be at least 32 characters")
	}
	// Normalise and validate allowedCallbackOrigins so a malformed entry fails
	// fast at boot rather than producing a broken redirect_uri at request time.
	for i, raw := range fa.AllowedCallbackOrigins {
		origin, err := normalizeCallbackOrigin(raw)
		if err != nil {
			return err
		}
		fa.AllowedCallbackOrigins[i] = origin
	}
	return nil
}

// normalizeCallbackOrigin trims an allowedCallbackOrigins entry, verifies it is
// a bare origin (http/https scheme plus a non-empty host and optional port, no
// userinfo, path, query or fragment) and returns it with any trailing slash
// removed so `<origin><callbackPath>` never doubles the separator.
func normalizeCallbackOrigin(raw string) (string, error) {
	entry := strings.TrimSpace(raw)
	if entry == "" {
		return "", errors.New("forwardAuth.allowedCallbackOrigins entries must not be empty")
	}
	u, err := url.Parse(entry)
	if err != nil {
		return "", fmt.Errorf("forwardAuth.allowedCallbackOrigins entry %q is not a valid origin: %w", entry, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("forwardAuth.allowedCallbackOrigins entry %q must use the http or https scheme", entry)
	}
	if u.Host == "" {
		return "", fmt.Errorf("forwardAuth.allowedCallbackOrigins entry %q must include a host", entry)
	}
	if u.User != nil {
		return "", fmt.Errorf("forwardAuth.allowedCallbackOrigins entry %q must not contain userinfo", entry)
	}
	if (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("forwardAuth.allowedCallbackOrigins entry %q must be a bare origin (no path, query or fragment)", entry)
	}
	// Reject host spellings that would break the comma-joined redirect CSV or
	// parse ambiguously: a comma would split one entry into two, and a
	// backslash/userinfo/path/query marker or whitespace has no business in a
	// host and could smuggle a different authority. Bracketed IPv6 (`[::1]`,
	// optionally with a port) contains none of these and is still accepted.
	if strings.ContainsAny(u.Host, ",\\@?#/") || strings.ContainsAny(u.Host, " \t\r\n\v\f") {
		return "", fmt.Errorf("forwardAuth.allowedCallbackOrigins entry %q contains an invalid character in its host", entry)
	}
	// A trailing dot ("nas.example.com.") is a distinct, ambiguous spelling of
	// an otherwise identical host; reject it so the allowlist cannot be dodged
	// by a host that compares differently.
	if strings.HasSuffix(u.Hostname(), ".") {
		return "", fmt.Errorf("forwardAuth.allowedCallbackOrigins entry %q must not have a trailing dot in its host", entry)
	}
	return u.Scheme + "://" + u.Host, nil
}

// RateLimitingEnabled reports whether the request rate limiter is active. A
// missing config value defaults to enabled.
func (c *Configuration) RateLimitingEnabled() bool {
	return c.RateLimitEnabled == nil || *c.RateLimitEnabled
}

// envString returns the value of an environment variable and true when it is set
// and not blank. A blank value is treated as "unset" so a stray empty `.env`
// entry leaves the built-in default in place.
func envString(key string) (string, bool) {
	value, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(value) == "" {
		return "", false
	}
	return value, true
}

// parseEnvBool accepts true/false/1/0/yes/no case-insensitively. A malformed
// value fails fast rather than being silently ignored.
func parseEnvBool(value string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "true", "1", "yes":
		return true, nil
	case "false", "0", "no":
		return false, nil
	default:
		return false, fmt.Errorf("invalid boolean value %q (want true/false/1/0/yes/no)", value)
	}
}

// splitEnvCSV splits a comma-separated override into trimmed, non-empty entries.
func splitEnvCSV(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

// forwardAuthEnvKeys are the MYOAUTH_FORWARD_AUTH_* variables that, when any one
// is set, require the ForwardAuth struct to exist so the override can be applied
// (an otherwise env-only configuration without forward auth still works).
var forwardAuthEnvKeys = []string{
	"MYOAUTH_FORWARD_AUTH_ENABLED",
	"MYOAUTH_FORWARD_AUTH_CLIENT_ID",
	"MYOAUTH_FORWARD_AUTH_CLIENT_SECRET",
	"MYOAUTH_FORWARD_AUTH_COOKIE_SECRET",
	"MYOAUTH_FORWARD_AUTH_COOKIE_NAME",
	"MYOAUTH_FORWARD_AUTH_COOKIE_DOMAIN",
	"MYOAUTH_FORWARD_AUTH_COOKIE_SECURE",
	"MYOAUTH_FORWARD_AUTH_SESSION_TTL_SECONDS",
	"MYOAUTH_FORWARD_AUTH_ALLOWED_CALLBACK_ORIGINS",
	"MYOAUTH_FORWARD_AUTH_ALLOWED_REDIRECT_DOMAINS",
}

// applyEnvOverrides layers every accepted MYOAUTH_* environment variable on top
// of the current (initially zero) configuration. It is intentionally separate
// from validation/defaults so the existing checks still run afterwards on the
// effective values.
func (c *Configuration) applyEnvOverrides() error {
	if v, ok := envString("MYOAUTH_HTTP_ADDRESS"); ok {
		c.HttpAddress = v
	}
	if v, ok := envString("MYOAUTH_OIDC_ISSUER"); ok {
		c.OidcIssuer = v
	}
	if v, ok := envString("MYOAUTH_OIDC_LOGIN_URL"); ok {
		c.OidcLoginUrl = v
	}
	if v, ok := envString("MYOAUTH_INVITATION_CODE"); ok {
		c.InvitationCode = v
	}
	if v, ok := envString("MYOAUTH_ADMIN_PASSWORD"); ok {
		c.AdminPassword = v
	}
	if v, ok := envString("MYOAUTH_DB_PATH"); ok {
		c.DbPath = v
	}
	if v, ok := envString("MYOAUTH_LOG_FILE_PATH"); ok {
		c.LogFilePath = v
	}
	if v, ok := envString("MYOAUTH_RSA_PRIVATE_KEY_PATH"); ok {
		c.RsaPrivateKeyPath = v
	}
	if v, ok := envString("MYOAUTH_ALLOWED_ORIGINS"); ok {
		c.AllowedOrigins = splitEnvCSV(v)
	}
	if v, ok := envString("MYOAUTH_SECURE_COOKIES"); ok {
		b, err := parseEnvBool(v)
		if err != nil {
			return fmt.Errorf("MYOAUTH_SECURE_COOKIES: %w", err)
		}
		c.SecureCookies = b
	}
	if v, ok := envString("MYOAUTH_TRUST_PROXY"); ok {
		b, err := parseEnvBool(v)
		if err != nil {
			return fmt.Errorf("MYOAUTH_TRUST_PROXY: %w", err)
		}
		c.TrustProxy = b
	}
	if v, ok := envString("MYOAUTH_PASSWORD_MIN_LENGTH"); ok {
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil {
			return fmt.Errorf("MYOAUTH_PASSWORD_MIN_LENGTH: invalid integer %q", v)
		}
		c.PasswordMinLength = n
	}
	if v, ok := envString("MYOAUTH_AUTHORIZATION_CODE_LENGTH"); ok {
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil {
			return fmt.Errorf("MYOAUTH_AUTHORIZATION_CODE_LENGTH: invalid integer %q", v)
		}
		c.AuthorizationCodeLength = n
	}
	if v, ok := envString("MYOAUTH_REFRESH_TOKEN_LENGTH"); ok {
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil {
			return fmt.Errorf("MYOAUTH_REFRESH_TOKEN_LENGTH: invalid integer %q", v)
		}
		c.RefreshTokenLength = n
	}
	if v, ok := envString("MYOAUTH_RATE_LIMIT_ENABLED"); ok {
		b, err := parseEnvBool(v)
		if err != nil {
			return fmt.Errorf("MYOAUTH_RATE_LIMIT_ENABLED: %w", err)
		}
		c.RateLimitEnabled = &b
	}
	if v, ok := envString("MYOAUTH_RATE_LIMIT_REQUESTS_PER_MINUTE"); ok {
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil {
			return fmt.Errorf("MYOAUTH_RATE_LIMIT_REQUESTS_PER_MINUTE: invalid integer %q", v)
		}
		c.RateLimitRequestsPerMinute = n
	}
	if v, ok := envString("MYOAUTH_RATE_LIMIT_BURST"); ok {
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil {
			return fmt.Errorf("MYOAUTH_RATE_LIMIT_BURST: invalid integer %q", v)
		}
		c.RateLimitBurst = n
	}
	if v, ok := envString("MYOAUTH_RATE_LIMIT_MAX_KEYS"); ok {
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil {
			return fmt.Errorf("MYOAUTH_RATE_LIMIT_MAX_KEYS: invalid integer %q", v)
		}
		c.RateLimitMaxKeys = n
	}
	return c.applyForwardAuthEnvOverrides()
}

// applyForwardAuthEnvOverrides applies MYOAUTH_FORWARD_AUTH_* overrides, creating
// the ForwardAuth struct first when any of those variables is set.
func (c *Configuration) applyForwardAuthEnvOverrides() error {
	anySet := false
	for _, key := range forwardAuthEnvKeys {
		if _, ok := envString(key); ok {
			anySet = true
			break
		}
	}
	if !anySet {
		return nil
	}
	if c.ForwardAuth == nil {
		c.ForwardAuth = &ForwardAuthConfig{}
	}
	fa := c.ForwardAuth
	if v, ok := envString("MYOAUTH_FORWARD_AUTH_ENABLED"); ok {
		b, err := parseEnvBool(v)
		if err != nil {
			return fmt.Errorf("MYOAUTH_FORWARD_AUTH_ENABLED: %w", err)
		}
		fa.Enabled = b
	}
	if v, ok := envString("MYOAUTH_FORWARD_AUTH_CLIENT_ID"); ok {
		fa.ClientId = v
	}
	if v, ok := envString("MYOAUTH_FORWARD_AUTH_CLIENT_SECRET"); ok {
		fa.ClientSecret = v
	}
	if v, ok := envString("MYOAUTH_FORWARD_AUTH_COOKIE_SECRET"); ok {
		fa.CookieSecret = v
	}
	if v, ok := envString("MYOAUTH_FORWARD_AUTH_COOKIE_NAME"); ok {
		fa.CookieName = v
	}
	if v, ok := envString("MYOAUTH_FORWARD_AUTH_COOKIE_DOMAIN"); ok {
		fa.CookieDomain = v
	}
	if v, ok := envString("MYOAUTH_FORWARD_AUTH_COOKIE_SECURE"); ok {
		b, err := parseEnvBool(v)
		if err != nil {
			return fmt.Errorf("MYOAUTH_FORWARD_AUTH_COOKIE_SECURE: %w", err)
		}
		fa.CookieSecure = b
	}
	if v, ok := envString("MYOAUTH_FORWARD_AUTH_SESSION_TTL_SECONDS"); ok {
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil {
			return fmt.Errorf("MYOAUTH_FORWARD_AUTH_SESSION_TTL_SECONDS: invalid integer %q", v)
		}
		fa.SessionTtlSeconds = n
	}
	if v, ok := envString("MYOAUTH_FORWARD_AUTH_ALLOWED_CALLBACK_ORIGINS"); ok {
		fa.AllowedCallbackOrigins = splitEnvCSV(v)
	}
	if v, ok := envString("MYOAUTH_FORWARD_AUTH_ALLOWED_REDIRECT_DOMAINS"); ok {
		fa.AllowedRedirectDomains = splitEnvCSV(v)
	}
	return nil
}
