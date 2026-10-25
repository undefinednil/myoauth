package util

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeEnvConf writes a minimal, valid conf.json (no forwardAuth block) plus an
// optional JSON fragment for extra fields.
func writeEnvConf(t *testing.T, extra string) string {
	t.Helper()
	dir := t.TempDir()
	conf := `{
  "httpAddress": "127.0.0.1:0",
  "oidcIssuer": "https://json.example.com",
  "adminPassword": "json-admin",
  "dbPath": "` + filepath.ToSlash(filepath.Join(dir, "test.db")) + `",
  "logFilePath": "` + filepath.ToSlash(filepath.Join(dir, "test.log")) + `",
  "rsaPrivateKeyPath": "` + filepath.ToSlash(filepath.Join(dir, "key.pem")) + `"` + extra + `
}`
	path := filepath.Join(dir, "conf.json")
	if err := os.WriteFile(path, []byte(conf), 0o600); err != nil {
		t.Fatalf("write conf: %v", err)
	}
	return path
}

// clearOverrideEnv blanks every supported override (an empty value means "leave
// the JSON value") so a variable from the surrounding shell cannot leak into a
// test. t.Setenv restores the original values automatically.
func clearOverrideEnv(t *testing.T) {
	t.Helper()
	keys := append([]string{
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
	}, forwardAuthEnvKeys...)
	for _, key := range keys {
		t.Setenv(key, "")
	}
}

func TestEnvOverridesWinOverJSON(t *testing.T) {
	clearOverrideEnv(t)
	t.Setenv("MYOAUTH_HTTP_ADDRESS", "127.0.0.1:1234")
	t.Setenv("MYOAUTH_OIDC_ISSUER", "https://env.example.com/")
	t.Setenv("MYOAUTH_INVITATION_CODE", "env-invite")
	t.Setenv("MYOAUTH_ADMIN_PASSWORD", "env-admin")
	t.Setenv("MYOAUTH_SECURE_COOKIES", "yes")
	t.Setenv("MYOAUTH_TRUST_PROXY", "1")
	t.Setenv("MYOAUTH_PASSWORD_MIN_LENGTH", "12")
	t.Setenv("MYOAUTH_ALLOWED_ORIGINS", "https://a.example.com, https://b.example.com ,")

	conf := new(Configuration)
	if err := conf.Init(writeEnvConf(t, "")); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if conf.HttpAddress != "127.0.0.1:1234" {
		t.Errorf("HttpAddress = %q, want 127.0.0.1:1234", conf.HttpAddress)
	}
	// Env wins and the issuer is still normalized (trailing slash removed).
	if conf.OidcIssuer != "https://env.example.com" {
		t.Errorf("OidcIssuer = %q, want https://env.example.com", conf.OidcIssuer)
	}
	if conf.InvitationCode != "env-invite" {
		t.Errorf("InvitationCode = %q, want env-invite", conf.InvitationCode)
	}
	if conf.AdminPassword != "env-admin" {
		t.Errorf("AdminPassword = %q, want env-admin", conf.AdminPassword)
	}
	if !conf.SecureCookies {
		t.Errorf("SecureCookies = false, want true (from env")
	}
	if !conf.TrustProxy {
		t.Errorf("TrustProxy = false, want true (from env)")
	}
	if conf.PasswordMinLength != 12 {
		t.Errorf("PasswordMinLength = %d, want 12", conf.PasswordMinLength)
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
		// An empty value means "no change", so the JSON default (false) stays.
		{value: "", want: false},
	}
	for _, tc := range cases {
		t.Run(tc.value, func(t *testing.T) {
			clearOverrideEnv(t)
			t.Setenv("MYOAUTH_SECURE_COOKIES", tc.value)
			conf := new(Configuration)
			err := conf.Init(writeEnvConf(t, ""))
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
	clearOverrideEnv(t)
	t.Setenv("MYOAUTH_SECURE_COOKIES", "maybe")
	conf := new(Configuration)
	err := conf.Init(writeEnvConf(t, ""))
	if err == nil {
		t.Fatal("Init succeeded, want a malformed-bool error")
	}
	if !strings.Contains(err.Error(), "MYOAUTH_SECURE_COOKIES") || !strings.Contains(err.Error(), "maybe") {
		t.Fatalf("error = %v, want it to name MYOAUTH_SECURE_COOKIES and the value", err)
	}
}

func TestEnvMalformedIntFailsFast(t *testing.T) {
	clearOverrideEnv(t)
	t.Setenv("MYOAUTH_PASSWORD_MIN_LENGTH", "abc")
	conf := new(Configuration)
	err := conf.Init(writeEnvConf(t, ""))
	if err == nil || !strings.Contains(err.Error(), "MYOAUTH_PASSWORD_MIN_LENGTH") {
		t.Fatalf("error = %v, want a MYOAUTH_PASSWORD_MIN_LENGTH failure", err)
	}
}

// A minimal conf.json with no forwardAuth block must still get one created when
// any MYOAUTH_FORWARD_AUTH_* variable is set, and the usual defaults/validation
// must still apply afterwards.
func TestEnvForwardAuthStructCreatedFromEnv(t *testing.T) {
	clearOverrideEnv(t)
	t.Setenv("MYOAUTH_FORWARD_AUTH_ENABLED", "true")
	t.Setenv("MYOAUTH_FORWARD_AUTH_CLIENT_SECRET", "s")
	t.Setenv("MYOAUTH_FORWARD_AUTH_COOKIE_SECRET", strings.Repeat("k", 32))
	t.Setenv("MYOAUTH_FORWARD_AUTH_COOKIE_SECURE", "true")
	t.Setenv("MYOAUTH_FORWARD_AUTH_ALLOWED_CALLBACK_ORIGINS", "https://app.example.com/")

	conf := new(Configuration)
	if err := conf.Init(writeEnvConf(t, "")); err != nil {
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
	clearOverrideEnv(t)
	t.Setenv("MYOAUTH_FORWARD_AUTH_ENABLED", "true")
	conf := new(Configuration)
	err := conf.Init(writeEnvConf(t, ""))
	if err == nil || !strings.Contains(err.Error(), "clientSecret") {
		t.Fatalf("error = %v, want the clientSecret requirement to fire", err)
	}
}

// Env wins over values already present in the JSON forwardAuth block.
func TestEnvForwardAuthWinsOverJSON(t *testing.T) {
	clearOverrideEnv(t)
	t.Setenv("MYOAUTH_FORWARD_AUTH_CLIENT_ID", "env-proxy")
	t.Setenv("MYOAUTH_FORWARD_AUTH_COOKIE_NAME", "_env_cookie")
	conf := new(Configuration)
	if err := conf.Init(writeEnvConf(t, `,
  "forwardAuth": { "enabled": false, "clientId": "json-proxy", "cookieName": "_json_cookie" }`)); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if conf.ForwardAuth == nil {
		t.Fatal("ForwardAuth = nil")
	}
	if conf.ForwardAuth.ClientId != "env-proxy" {
		t.Errorf("ClientId = %q, want env-proxy", conf.ForwardAuth.ClientId)
	}
	if conf.ForwardAuth.CookieName != "_env_cookie" {
		t.Errorf("CookieName = %q, want _env_cookie", conf.ForwardAuth.CookieName)
	}
}

// With every override blank, the JSON values must be left exactly as written.
func TestEnvUnsetLeavesJSONIntact(t *testing.T) {
	clearOverrideEnv(t)
	conf := new(Configuration)
	if err := conf.Init(writeEnvConf(t, `,
  "forwardAuth": { "enabled": false, "clientId": "json-proxy" }`)); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if conf.OidcIssuer != "https://json.example.com" {
		t.Errorf("OidcIssuer = %q, want the JSON value", conf.OidcIssuer)
	}
	if conf.AdminPassword != "json-admin" {
		t.Errorf("AdminPassword = %q, want the JSON value", conf.AdminPassword)
	}
	if conf.SecureCookies {
		t.Error("SecureCookies = true, want the JSON default false")
	}
	if conf.ForwardAuth == nil || conf.ForwardAuth.ClientId != "json-proxy" {
		t.Errorf("ForwardAuth = %+v, want the JSON clientId json-proxy", conf.ForwardAuth)
	}
}
