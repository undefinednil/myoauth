package util

import (
	"strings"
	"testing"
)

func TestAllowedScopes(t *testing.T) {
	got := AllowedScopes()
	want := []string{"openid", "profile"}
	if len(got) != len(want) {
		t.Fatalf("AllowedScopes() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("AllowedScopes()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// The returned slice must be a copy: mutating it must not shrink or change the
// provider's supported set for later callers.
func TestAllowedScopesReturnsCopy(t *testing.T) {
	got := AllowedScopes()
	if len(got) == 0 {
		t.Fatal("AllowedScopes() returned an empty slice")
	}
	got[0] = "tampered"
	got = append(got, "extra")
	if len(got) != 3 {
		t.Fatalf("append to the returned slice lost data: %v", got)
	}

	again := AllowedScopes()
	want := []string{"openid", "profile"}
	if len(again) != len(want) {
		t.Fatalf("AllowedScopes() after mutation = %v, want %v", again, want)
	}
	for i := range want {
		if again[i] != want[i] {
			t.Errorf("AllowedScopes()[%d] = %q, want %q", i, again[i], want[i])
		}
	}
}

func TestValidateScopes(t *testing.T) {
	cases := []struct {
		name    string
		scopes  []string
		wantErr string
	}{
		{name: "nil", scopes: nil},
		{name: "empty", scopes: []string{}},
		{name: "openid", scopes: []string{"openid"}},
		{name: "profile", scopes: []string{"profile"}},
		{name: "both", scopes: []string{"openid", "profile"}},
		{name: "duplicates", scopes: []string{"openid", "openid", "profile"}},
		{name: "surrounding whitespace", scopes: []string{" openid ", "profile\t"}},
		{name: "unsupported email", scopes: []string{"openid", "email"}, wantErr: "email"},
		{name: "unsupported upstream", scopes: []string{"upstream:groups"}, wantErr: "upstream:groups"},
		{name: "case sensitive", scopes: []string{"OpenID"}, wantErr: "OpenID"},
		{name: "empty entry", scopes: []string{""}, wantErr: "unsupported scope"},
		{name: "embedded space", scopes: []string{"openid profile"}, wantErr: "openid profile"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateScopes(tc.scopes)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("ValidateScopes(%v) = %v, want nil", tc.scopes, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("ValidateScopes(%v) error = %v, want containing %q", tc.scopes, err, tc.wantErr)
			}
		})
	}
}

// The error must not only signal failure but name the offending scope so an
// operator can see which requested scope was dropped.
func TestValidateScopesErrorMessageNamesScope(t *testing.T) {
	err := ValidateScopes([]string{"openid", "offline_access"})
	if err == nil {
		t.Fatal("ValidateScopes returned nil, want an error")
	}
	if !strings.Contains(err.Error(), "offline_access") || !strings.Contains(err.Error(), "unsupported scope") {
		t.Fatalf("error = %v, want it to name the unsupported scope", err)
	}
}
