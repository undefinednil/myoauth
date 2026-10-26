package util

import (
	"path/filepath"
	"strings"
	"testing"
)

// configEnvKeys lists every MYOAUTH_* variable Configuration.Init reads. The
// test helpers blank them all (an empty value means "unset") so an ambient
// variable cannot leak into a test; t.Setenv restores the originals afterwards.
var configEnvKeys = append([]string{
	"MYOAUTH_HTTP_ADDRESS",
	"MYOAUTH_OIDC_ISSUER",
	"MYOAUTH_OIDC_LOGIN_URL",
	"MYOAUTH_INVITATION_CODE",
	"MYOAUTH_ADMIN_PASSWORD",
	"MYOAUTH_DB_PATH",
	"MYOAUTH_LOG_FILE_PATH",
	"MYOAUTH_RSA_PRIVATE_KEY_PATH",
	"MYOAUTH_ALLOWED_ORIGINS",
	"MYOAUTH_SECURE_COOKIES",
	"MYOAUTH_TRUST_PROXY",
	"MYOAUTH_PASSWORD_MIN_LENGTH",
	"MYOAUTH_AUTHORIZATION_CODE_LENGTH",
	"MYOAUTH_REFRESH_TOKEN_LENGTH",
	"MYOAUTH_RATE_LIMIT_ENABLED",
	"MYOAUTH_RATE_LIMIT_REQUESTS_PER_MINUTE",
	"MYOAUTH_RATE_LIMIT_BURST",
	"MYOAUTH_RATE_LIMIT_MAX_KEYS",
}, forwardAuthEnvKeys...)

// clearOverrideEnv blanks every supported override so a variable from the
// surrounding shell cannot leak into a test. t.Setenv restores the original
// values automatically.
func clearOverrideEnv(t *testing.T) {
	t.Helper()
	for _, key := range configEnvKeys {
		t.Setenv(key, "")
	}
}

// setRequiredEnv blanks every override and then sets only the required values,
// so the test observes the built-in defaults for everything else.
func setRequiredEnv(t *testing.T) {
	t.Helper()
	clearOverrideEnv(t)
	t.Setenv("MYOAUTH_OIDC_ISSUER", "https://issuer.example.com")
	t.Setenv("MYOAUTH_ADMIN_PASSWORD", "x")
	t.Setenv("MYOAUTH_INVITATION_CODE", "test-invite")
}

// setTestBaseEnv is setRequiredEnv plus the per-test temp paths a full boot
// needs. It is the baseline for tests that also set individual overrides.
func setTestBaseEnv(t *testing.T) {
	t.Helper()
	setRequiredEnv(t)
	dir := t.TempDir()
	t.Setenv("MYOAUTH_DB_PATH", filepath.Join(dir, "test.db"))
	t.Setenv("MYOAUTH_LOG_FILE_PATH", filepath.Join(dir, "test.log"))
	t.Setenv("MYOAUTH_RSA_PRIVATE_KEY_PATH", filepath.Join(dir, "key.pem"))
}

// TestInitRequiredOnlyBootsWithDefaults proves that an env-only configuration
// with just the two required values boots and receives every built-in default.
func TestInitRequiredOnlyBootsWithDefaults(t *testing.T) {
	setRequiredEnv(t)
	conf := new(Configuration)
	if err := conf.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if conf.HttpAddress != "0.0.0.0:20476" {
		t.Errorf("HttpAddress = %q, want the default", conf.HttpAddress)
	}
	if conf.DbPath != "myoauth.db" {
		t.Errorf("DbPath = %q, want myoauth.db", conf.DbPath)
	}
	if conf.LogFilePath != "my-oauth.log" {
		t.Errorf("LogFilePath = %q, want my-oauth.log", conf.LogFilePath)
	}
	if conf.RsaPrivateKeyPath != "oauth.private.pem" {
		t.Errorf("RsaPrivateKeyPath = %q, want oauth.private.pem", conf.RsaPrivateKeyPath)
	}
	if conf.AuthorizationCodeLength != 128 {
		t.Errorf("AuthorizationCodeLength = %d, want 128", conf.AuthorizationCodeLength)
	}
	if conf.RefreshTokenLength != 128 {
		t.Errorf("RefreshTokenLength = %d, want 128", conf.RefreshTokenLength)
	}
	if conf.PasswordMinLength != 8 {
		t.Errorf("PasswordMinLength = %d, want 8", conf.PasswordMinLength)
	}
	if !conf.RateLimitingEnabled() {
		t.Error("RateLimitingEnabled = false, want true by default")
	}
	if conf.RateLimitRequestsPerMinute != 30 {
		t.Errorf("RateLimitRequestsPerMinute = %d, want 30", conf.RateLimitRequestsPerMinute)
	}
	if conf.RateLimitBurst != 10 {
		t.Errorf("RateLimitBurst = %d, want 10", conf.RateLimitBurst)
	}
	if conf.RateLimitMaxKeys != 100000 {
		t.Errorf("RateLimitMaxKeys = %d, want 100000", conf.RateLimitMaxKeys)
	}
	if conf.ForwardAuth != nil {
		t.Errorf("ForwardAuth = %+v, want nil when unset", conf.ForwardAuth)
	}
}

// With no issuer the boot must fail fast with a clear message.
func TestInitNoEnvFailsFast(t *testing.T) {
	clearOverrideEnv(t)
	conf := new(Configuration)
	err := conf.Init()
	if err == nil || !strings.Contains(err.Error(), "oidcIssuer is required") {
		t.Fatalf("error = %v, want the oidcIssuer requirement", err)
	}
}

// An empty admin password must fail even when the issuer is set.
func TestInitRequiresAdminPassword(t *testing.T) {
	clearOverrideEnv(t)
	t.Setenv("MYOAUTH_OIDC_ISSUER", "https://issuer.example.com")
	conf := new(Configuration)
	err := conf.Init()
	if err == nil || !strings.Contains(err.Error(), "adminPassword is required") {
		t.Fatalf("error = %v, want the adminPassword requirement", err)
	}
}

// An empty invitation code would make /setup/register accept a blank code
// (open registration), so it must fail fast like the other required values.
func TestInitRequiresInvitationCode(t *testing.T) {
	clearOverrideEnv(t)
	t.Setenv("MYOAUTH_OIDC_ISSUER", "https://issuer.example.com")
	t.Setenv("MYOAUTH_ADMIN_PASSWORD", "x")
	conf := new(Configuration)
	err := conf.Init()
	if err == nil || !strings.Contains(err.Error(), "invitationCode is required") {
		t.Fatalf("error = %v, want the invitationCode requirement", err)
	}
}

// Every supported variable must override the default, and the issuer is still
// normalized (trailing slash removed).
func TestEnvOverridesDefaults(t *testing.T) {
	setTestBaseEnv(t)
	t.Setenv("MYOAUTH_HTTP_ADDRESS", "127.0.0.1:1234")
	t.Setenv("MYOAUTH_OIDC_ISSUER", "https://env.example.com/")
	t.Setenv("MYOAUTH_OIDC_LOGIN_URL", "https://env.example.com/login")
	t.Setenv("MYOAUTH_INVITATION_CODE", "env-invite")
	t.Setenv("MYOAUTH_ADMIN_PASSWORD", "env-admin")
	t.Setenv("MYOAUTH_SECURE_COOKIES", "yes")
	t.Setenv("MYOAUTH_TRUST_PROXY", "1")
	t.Setenv("MYOAUTH_PASSWORD_MIN_LENGTH", "12")
	t.Setenv("MYOAUTH_AUTHORIZATION_CODE_LENGTH", "64")
	t.Setenv("MYOAUTH_REFRESH_TOKEN_LENGTH", "96")
	t.Setenv("MYOAUTH_RATE_LIMIT_ENABLED", "false")
	t.Setenv("MYOAUTH_RATE_LIMIT_REQUESTS_PER_MINUTE", "120")
	t.Setenv("MYOAUTH_RATE_LIMIT_BURST", "25")
	t.Setenv("MYOAUTH_RATE_LIMIT_MAX_KEYS", "5000")
	t.Setenv("MYOAUTH_ALLOWED_ORIGINS", "https://a.example.com, https://b.example.com ,")

	conf := new(Configuration)
	if err := conf.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if conf.HttpAddress != "127.0.0.1:1234" {
		t.Errorf("HttpAddress = %q, want 127.0.0.1:1234", conf.HttpAddress)
	}
	if conf.OidcIssuer != "https://env.example.com" {
		t.Errorf("OidcIssuer = %q, want https://env.example.com", conf.OidcIssuer)
	}
	if conf.OidcLoginUrl != "https://env.example.com/login" {
		t.Errorf("OidcLoginUrl = %q, want the env value", conf.OidcLoginUrl)
	}
	if conf.InvitationCode != "env-invite" {
		t.Errorf("InvitationCode = %q, want env-invite", conf.InvitationCode)
	}
	if conf.AdminPassword != "env-admin" {
		t.Errorf("AdminPassword = %q, want env-admin", conf.AdminPassword)
	}
	if !conf.SecureCookies {
		t.Errorf("SecureCookies = false, want true (from env)")
	}
	if !conf.TrustProxy {
		t.Errorf("TrustProxy = false, want true (from env)")
	}
	if conf.PasswordMinLength != 12 {
		t.Errorf("PasswordMinLength = %d, want 12", conf.PasswordMinLength)
	}
	if conf.AuthorizationCodeLength != 64 {
		t.Errorf("AuthorizationCodeLength = %d, want 64", conf.AuthorizationCodeLength)
	}
	if conf.RefreshTokenLength != 96 {
		t.Errorf("RefreshTokenLength = %d, want 96", conf.RefreshTokenLength)
	}
	if conf.RateLimitingEnabled() {
		t.Error("RateLimitingEnabled = true, want false (from env)")
	}
	if conf.RateLimitRequestsPerMinute != 120 {
		t.Errorf("RateLimitRequestsPerMinute = %d, want 120", conf.RateLimitRequestsPerMinute)
	}
	if conf.RateLimitBurst != 25 {
		t.Errorf("RateLimitBurst = %d, want 25", conf.RateLimitBurst)
	}
	if conf.RateLimitMaxKeys != 5000 {
		t.Errorf("RateLimitMaxKeys = %d, want 5000", conf.RateLimitMaxKeys)
	}
	wantOrigins := []string{"https://a.example.com", "https://b.example.com"}
	if len(conf.AllowedOrigins) != len(wantOrigins) {
		t.Fatalf("AllowedOrigins = %v, want %v", conf.AllowedOrigins, wantOrigins)
	}
	for i := range wantOrigins {
		if conf.AllowedOrigins[i] != wantOrigins[i] {
			t.Errorf("AllowedOrigins[%d] = %q, want %q", i, conf.AllowedOrigins[i], wantOrigins[i])
		}
	}
}

func TestEnvBoolParsing(t *testing.T) {
	cases := []struct {
		value   string
		want    bool
		wantErr bool
	}{
		{value: "true", want: true},
		{value: "True", want: true},
		{value: "1", want: true},
		{value: "YES", want: true},
		{value: "false", want: false},
		{value: "FALSE", want: false},
		{value: "0", want: false},
		{value: "No", want: false},
		{value: "maybe", wantErr: true},
		{value: "2", wantErr: true},
		// An empty value means "no change", so the default (false) stays.
		{value: "", want: false},
	}
	for _, tc := range cases {
		t.Run(tc.value, func(t *testing.T) {
			setTestBaseEnv(t)
			t.Setenv("MYOAUTH_SECURE_COOKIES", tc.value)
			conf := new(Configuration)
			err := conf.Init()
			if tc.wantErr {
				if err == nil || !strings.Contains(err.Error(), "MYOAUTH_SECURE_COOKIES") {
					t.Fatalf("error = %v, want a MYOAUTH_SECURE_COOKIES failure", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Init: %v", err)
			}
			if conf.SecureCookies != tc.want {
				t.Fatalf("SecureCookies = %v, want %v", conf.SecureCookies, tc.want)
			}
		})
	}
}

func TestEnvMalformedBoolFailsFast(t *testing.T) {
	setTestBaseEnv(t)
	t.Setenv("MYOAUTH_SECURE_COOKIES", "maybe")
	conf := new(Configuration)
	err := conf.Init()
	if err == nil {
		t.Fatal("Init succeeded, want a malformed-bool error")
	}
	if !strings.Contains(err.Error(), "MYOAUTH_SECURE_COOKIES") || !strings.Contains(err.Error(), "maybe") {
		t.Fatalf("error = %v, want it to name MYOAUTH_SECURE_COOKIES and the value", err)
	}
}

func TestEnvMalformedIntFailsFast(t *testing.T) {
	cases := []struct {
		key   string
		value string
	}{
		{"MYOAUTH_PASSWORD_MIN_LENGTH", "abc"},
		{"MYOAUTH_AUTHORIZATION_CODE_LENGTH", "abc"},
		{"MYOAUTH_REFRESH_TOKEN_LENGTH", "abc"},
		{"MYOAUTH_RATE_LIMIT_REQUESTS_PER_MINUTE", "abc"},
		{"MYOAUTH_RATE_LIMIT_BURST", "abc"},
		{"MYOAUTH_RATE_LIMIT_MAX_KEYS", "abc"},
		{"MYOAUTH_FORWARD_AUTH_SESSION_TTL_SECONDS", "abc"},
	}
	for _, tc := range cases {
		t.Run(tc.key, func(t *testing.T) {
			setTestBaseEnv(t)
			t.Setenv(tc.key, tc.value)
			conf := new(Configuration)
			err := conf.Init()
			if err == nil || !strings.Contains(err.Error(), tc.key) {
				t.Fatalf("error = %v, want a %s failure", err, tc.key)
			}
		})
	}
}

// A configuration with no forwardAuth variables must leave ForwardAuth nil, but
// setting any MYOAUTH_FORWARD_AUTH_* variable creates it, and the usual
// defaults/validation must still apply afterwards.
func TestEnvForwardAuthStructCreatedFromEnv(t *testing.T) {
	setTestBaseEnv(t)
	t.Setenv("MYOAUTH_FORWARD_AUTH_ENABLED", "true")
	t.Setenv("MYOAUTH_FORWARD_AUTH_CLIENT_SECRET", "s")
	t.Setenv("MYOAUTH_FORWARD_AUTH_COOKIE_SECRET", strings.Repeat("k", 32))
	t.Setenv("MYOAUTH_FORWARD_AUTH_COOKIE_SECURE", "true")
	t.Setenv("MYOAUTH_FORWARD_AUTH_ALLOWED_CALLBACK_ORIGINS", "https://app.example.com/")

	conf := new(Configuration)
	if err := conf.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	fa := conf.ForwardAuth
	if fa == nil {
		t.Fatal("ForwardAuth = nil, want it created from env")
	}
	if !fa.Enabled {
		t.Error("Enabled = false, want true")
	}
	if fa.ClientSecret != "s" {
		t.Errorf("ClientSecret = %q, want s", fa.ClientSecret)
	}
	if fa.CookieSecret != strings.Repeat("k", 32) {
		t.Errorf("CookieSecret = %q, want the env value", fa.CookieSecret)
	}
	if !fa.CookieSecure {
		t.Error("CookieSecure = false, want true")
	}
	// The origin is normalized by validateForwardAuth (trailing slash removed).
	if len(fa.AllowedCallbackOrigins) != 1 || fa.AllowedCallbackOrigins[0] != "https://app.example.com" {
		t.Errorf("AllowedCallbackOrigins = %v, want [https://app.example.com]", fa.AllowedCallbackOrigins)
	}
	// Defaults still run after the override.
	if fa.ClientId != "proxy" {
		t.Errorf("ClientId = %q, want proxy", fa.ClientId)
	}
	if fa.CookieName != "_myoauth_proxy" {
		t.Errorf("CookieName = %q, want _myoauth_proxy", fa.CookieName)
	}
}

// Enabling forwardAuth via env without secrets must fail validation, proving the
// existing checks run after the overrides.
func TestEnvForwardAuthValidationRunsAfterOverrides(t *testing.T) {
	setTestBaseEnv(t)
	t.Setenv("MYOAUTH_FORWARD_AUTH_ENABLED", "true")
	conf := new(Configuration)
	err := conf.Init()
	if err == nil || !strings.Contains(err.Error(), "clientSecret") {
		t.Fatalf("error = %v, want the clientSecret requirement to fire", err)
	}
}

// A single MYOAUTH_FORWARD_AUTH_* variable (no forwardAuth otherwise) creates
// the struct; unset sub-fields then receive their defaults, and no leftover
// values leak between tests.
func TestEnvForwardAuthDefaultsAfterSingleOverride(t *testing.T) {
	setTestBaseEnv(t)
	t.Setenv("MYOAUTH_FORWARD_AUTH_CLIENT_ID", "env-proxy")
	conf := new(Configuration)
	if err := conf.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if conf.ForwardAuth == nil {
		t.Fatal("ForwardAuth = nil")
	}
	if conf.ForwardAuth.ClientId != "env-proxy" {
		t.Errorf("ClientId = %q, want env-proxy", conf.ForwardAuth.ClientId)
	}
	if conf.ForwardAuth.CookieName != "_myoauth_proxy" {
		t.Errorf("CookieName = %q, want the default", conf.ForwardAuth.CookieName)
	}
	if conf.ForwardAuth.Enabled {
		t.Error("Enabled = true, want the default false")
	}
}

// MYOAUTH_FORWARD_AUTH_SESSION_TTL_SECONDS is the only env var for the session
// TTL: setting it alone must both create the struct and apply the value.
func TestEnvForwardAuthSessionTtlSeconds(t *testing.T) {
	setTestBaseEnv(t)
	t.Setenv("MYOAUTH_FORWARD_AUTH_SESSION_TTL_SECONDS", "3600")
	conf := new(Configuration)
	if err := conf.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if conf.ForwardAuth == nil {
		t.Fatal("ForwardAuth = nil, want the struct created by the session TTL var")
	}
	if conf.ForwardAuth.SessionTtlSeconds != 3600 {
		t.Errorf("SessionTtlSeconds = %d, want 3600", conf.ForwardAuth.SessionTtlSeconds)
	}
}
