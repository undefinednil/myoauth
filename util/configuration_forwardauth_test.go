package util

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeConf(t *testing.T, forwardAuthJSON string) string {
	t.Helper()
	dir := t.TempDir()
	conf := `{
  "httpAddress": "127.0.0.1:0",
  "oidcIssuer": "https://issuer.example.com",
  "adminPassword": "x",
  "dbPath": "` + filepath.ToSlash(filepath.Join(dir, "test.db")) + `",
  "logFilePath": "` + filepath.ToSlash(filepath.Join(dir, "test.log")) + `",
  "rsaPrivateKeyPath": "` + filepath.ToSlash(filepath.Join(dir, "key.pem")) + `"` + forwardAuthJSON + `
}`
	path := filepath.Join(dir, "conf.json")
	if err := os.WriteFile(path, []byte(conf), 0o600); err != nil {
		t.Fatalf("write conf: %v", err)
	}
	return path
}

func TestForwardAuthConfigValidation(t *testing.T) {
	cases := []struct {
		name        string
		forwardAuth string
		wantErr     string
	}{
		{
			name: "disabled needs no secrets",
			forwardAuth: `,
  "forwardAuth": { "enabled": false }`,
		},
		{
			name: "enabled missing clientSecret",
			forwardAuth: `,
  "forwardAuth": { "enabled": true, "cookieSecret": "` + strings.Repeat("k", 32) + `" }`,
			wantErr: "clientSecret",
		},
		{
			name: "enabled missing cookieSecret",
			forwardAuth: `,
  "forwardAuth": { "enabled": true, "clientSecret": "s" }`,
			wantErr: "cookieSecret",
		},
		{
			name: "enabled short cookieSecret",
			forwardAuth: `,
  "forwardAuth": { "enabled": true, "clientSecret": "s", "cookieSecret": "too-short" }`,
			wantErr: "at least 32",
		},
		{
			name: "enabled valid",
			forwardAuth: `,
  "forwardAuth": { "enabled": true, "clientSecret": "s", "cookieSecret": "` + strings.Repeat("k", 32) + `" }`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			conf := new(Configuration)
			err := conf.Init(writeConf(t, tc.forwardAuth))
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

func TestForwardAuthConfigDefaults(t *testing.T) {
	conf := new(Configuration)
	if err := conf.Init(writeConf(t, `,
  "forwardAuth": { "enabled": true, "clientSecret": "s", "cookieSecret": "`+strings.Repeat("k", 32)+`" }`)); err != nil {
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
