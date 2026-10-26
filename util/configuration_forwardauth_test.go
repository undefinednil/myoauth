package util

import (
	"strings"
	"testing"
)

func TestForwardAuthConfigValidation(t *testing.T) {
	cases := []struct {
		name    string
		env     map[string]string
		wantErr string
	}{
		{
			name: "disabled needs no secrets",
			// No MYOAUTH_FORWARD_AUTH_* variables: ForwardAuth stays nil.
		},
		{
			name: "enabled missing clientSecret",
			env: map[string]string{
				"MYOAUTH_FORWARD_AUTH_ENABLED":       "true",
				"MYOAUTH_FORWARD_AUTH_COOKIE_SECRET": strings.Repeat("k", 32),
			},
			wantErr: "clientSecret",
		},
		{
			name: "enabled missing cookieSecret",
			env: map[string]string{
				"MYOAUTH_FORWARD_AUTH_ENABLED":       "true",
				"MYOAUTH_FORWARD_AUTH_CLIENT_SECRET": "s",
			},
			wantErr: "cookieSecret",
		},
		{
			name: "enabled short cookieSecret",
			env: map[string]string{
				"MYOAUTH_FORWARD_AUTH_ENABLED":       "true",
				"MYOAUTH_FORWARD_AUTH_CLIENT_SECRET": "s",
				"MYOAUTH_FORWARD_AUTH_COOKIE_SECRET": "too-short",
			},
			wantErr: "at least 32",
		},
		{
			name: "enabled valid",
			env: map[string]string{
				"MYOAUTH_FORWARD_AUTH_ENABLED":       "true",
				"MYOAUTH_FORWARD_AUTH_CLIENT_SECRET": "s",
				"MYOAUTH_FORWARD_AUTH_COOKIE_SECRET": strings.Repeat("k", 32),
			},
		},
		{
			name: "valid allowedCallbackOrigins",
			env: map[string]string{
				"MYOAUTH_FORWARD_AUTH_ENABLED":                  "true",
				"MYOAUTH_FORWARD_AUTH_CLIENT_SECRET":            "s",
				"MYOAUTH_FORWARD_AUTH_COOKIE_SECRET":            strings.Repeat("k", 32),
				"MYOAUTH_FORWARD_AUTH_ALLOWED_CALLBACK_ORIGINS": "https://nas.example.com,http://localhost:8080",
			},
		},
		{
			name: "allowedCallbackOrigins missing scheme",
			env: map[string]string{
				"MYOAUTH_FORWARD_AUTH_ENABLED":                  "true",
				"MYOAUTH_FORWARD_AUTH_CLIENT_SECRET":            "s",
				"MYOAUTH_FORWARD_AUTH_COOKIE_SECRET":            strings.Repeat("k", 32),
				"MYOAUTH_FORWARD_AUTH_ALLOWED_CALLBACK_ORIGINS": "nas.example.com",
			},
			wantErr: "http or https",
		},
		{
			name: "allowedCallbackOrigins bad scheme",
			env: map[string]string{
				"MYOAUTH_FORWARD_AUTH_ENABLED":                  "true",
				"MYOAUTH_FORWARD_AUTH_CLIENT_SECRET":            "s",
				"MYOAUTH_FORWARD_AUTH_COOKIE_SECRET":            strings.Repeat("k", 32),
				"MYOAUTH_FORWARD_AUTH_ALLOWED_CALLBACK_ORIGINS": "ftp://nas.example.com",
			},
			wantErr: "http or https",
		},
		{
			name: "allowedCallbackOrigins missing host",
			env: map[string]string{
				"MYOAUTH_FORWARD_AUTH_ENABLED":                  "true",
				"MYOAUTH_FORWARD_AUTH_CLIENT_SECRET":            "s",
				"MYOAUTH_FORWARD_AUTH_COOKIE_SECRET":            strings.Repeat("k", 32),
				"MYOAUTH_FORWARD_AUTH_ALLOWED_CALLBACK_ORIGINS": "https://",
			},
			wantErr: "host",
		},
		{
			name: "allowedCallbackOrigins with path",
			env: map[string]string{
				"MYOAUTH_FORWARD_AUTH_ENABLED":                  "true",
				"MYOAUTH_FORWARD_AUTH_CLIENT_SECRET":            "s",
				"MYOAUTH_FORWARD_AUTH_COOKIE_SECRET":            strings.Repeat("k", 32),
				"MYOAUTH_FORWARD_AUTH_ALLOWED_CALLBACK_ORIGINS": "https://nas.example.com/app",
			},
			wantErr: "bare origin",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setTestBaseEnv(t)
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			conf := new(Configuration)
			err := conf.Init()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want containing %q", err, tc.wantErr)
			}
		})
	}
}

// normalizeCallbackOrigin must reject host spellings that would break the
// comma-joined redirect CSV or parse ambiguously, while still accepting normal
// DNS names, localhost and bracketed IPv6 (with an optional port).
func TestNormalizeCallbackOriginHostValidation(t *testing.T) {
	cases := []struct {
		name    string
		entry   string
		want    string
		wantErr string
	}{
		{name: "plain dns", entry: "https://nas.example.com", want: "https://nas.example.com"},
		{name: "localhost with port", entry: "http://localhost:8080", want: "http://localhost:8080"},
		{name: "ipv4 with port", entry: "https://192.168.1.10:8443", want: "https://192.168.1.10:8443"},
		{name: "bracketed ipv6", entry: "https://[2001:db8::1]", want: "https://[2001:db8::1]"},
		{name: "bracketed ipv6 with port", entry: "https://[::1]:8443", want: "https://[::1]:8443"},
		{name: "comma in host", entry: "https://a,b.example.com", wantErr: "invalid character"},
		{name: "backslash in host", entry: `https://a\b.example.com`, wantErr: "not a valid origin"},
		{name: "trailing dot in host", entry: "https://nas.example.com.", wantErr: "trailing dot"},
		// splitEnvCSV drops these before validation, but the function itself
		// must still reject them (defence in depth).
		{name: "empty entry", entry: "", wantErr: "must not be empty"},
		{name: "whitespace entry", entry: "   ", wantErr: "must not be empty"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := normalizeCallbackOrigin(tc.entry)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("normalizeCallbackOrigin(%q) error = %v, want containing %q", tc.entry, err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("normalizeCallbackOrigin(%q) unexpected error: %v", tc.entry, err)
			}
			if got != tc.want {
				t.Fatalf("normalizeCallbackOrigin(%q) = %q, want %q", tc.entry, got, tc.want)
			}
		})
	}
}

func TestForwardAuthConfigDefaults(t *testing.T) {
	setTestBaseEnv(t)
	t.Setenv("MYOAUTH_FORWARD_AUTH_ENABLED", "true")
	t.Setenv("MYOAUTH_FORWARD_AUTH_CLIENT_SECRET", "s")
	t.Setenv("MYOAUTH_FORWARD_AUTH_COOKIE_SECRET", strings.Repeat("k", 32))
	conf := new(Configuration)
	if err := conf.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	fa := conf.ForwardAuth
	if fa.ClientId != "proxy" {
		t.Errorf("clientId = %q, want proxy", fa.ClientId)
	}
	if fa.CookieName != "_myoauth_proxy" {
		t.Errorf("cookieName = %q, want _myoauth_proxy", fa.CookieName)
	}
	if fa.LoginPath != "/oauth2/start" || fa.CallbackPath != "/oauth2/callback" ||
		fa.AuthPath != "/oauth2/auth" || fa.SignOutPath != "/oauth2/sign_out" {
		t.Errorf("path defaults not applied: %+v", fa)
	}
}

// allowedCallbackOrigins entries are normalised to a bare origin (trailing
// slash removed) so <origin><callbackPath> never doubles the separator.
func TestForwardAuthAllowedCallbackOriginsNormalized(t *testing.T) {
	setTestBaseEnv(t)
	t.Setenv("MYOAUTH_FORWARD_AUTH_ENABLED", "true")
	t.Setenv("MYOAUTH_FORWARD_AUTH_CLIENT_SECRET", "s")
	t.Setenv("MYOAUTH_FORWARD_AUTH_COOKIE_SECRET", strings.Repeat("k", 32))
	t.Setenv("MYOAUTH_FORWARD_AUTH_ALLOWED_CALLBACK_ORIGINS", "https://nas.example.com/,  http://localhost:8080  ")
	conf := new(Configuration)
	if err := conf.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	got := conf.ForwardAuth.AllowedCallbackOrigins
	want := []string{"https://nas.example.com", "http://localhost:8080"}
	if len(got) != len(want) {
		t.Fatalf("allowedCallbackOrigins = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("allowedCallbackOrigins[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// The validator runs even when the malformed entry would only be reached at
// request time, so a typo fails the boot.
func TestForwardAuthAllowedCallbackOriginsDisabledIsNotValidated(t *testing.T) {
	setTestBaseEnv(t)
	// Disabled: malformed entries are ignored, matching every other
	// forwardAuth field.
	t.Setenv("MYOAUTH_FORWARD_AUTH_ENABLED", "false")
	t.Setenv("MYOAUTH_FORWARD_AUTH_ALLOWED_CALLBACK_ORIGINS", "not-an-origin")
	conf := new(Configuration)
	if err := conf.Init(); err != nil {
		t.Fatalf("disabled config must not validate allowedCallbackOrigins: %v", err)
	}
}
