package util

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

const testVerifier = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"

func challengeFor(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func newTestStore() *AuthorizationCodeStore {
	return NewAuthorizationCodeStore(&Configuration{AuthorizationCodeLength: 48})
}

func TestAuthorizationCodeGenerateVerify(t *testing.T) {
	store := newTestStore()
	code, err := store.Generate(AuthorizationInfo{
		ClientId:      7,
		UserId:        9,
		RedirectUri:   "https://app.example.com/callback",
		Scope:         "openid profile",
		State:         "xyz",
		CodeChallenge: challengeFor(testVerifier),
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if code == "" {
		t.Fatal("Generate returned an empty code")
	}

	info, err := store.Verify(code, testVerifier)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if info.ClientId != 7 || info.UserId != 9 {
		t.Fatalf("unexpected info: %+v", info)
	}
	if info.CreatedAt.IsZero() {
		t.Fatal("Generate must record CreatedAt for auth_time")
	}
}

func TestAuthorizationCodeSingleUse(t *testing.T) {
	store := newTestStore()
	code, err := store.Generate(AuthorizationInfo{CodeChallenge: challengeFor(testVerifier)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Verify(code, testVerifier); err != nil {
		t.Fatalf("first Verify: %v", err)
	}
	if _, err := store.Verify(code, testVerifier); err == nil {
		t.Fatal("a code must not be usable twice")
	}
}

func TestAuthorizationCodeWrongVerifier(t *testing.T) {
	store := newTestStore()
	code, err := store.Generate(AuthorizationInfo{CodeChallenge: challengeFor(testVerifier)})
	if err != nil {
		t.Fatal(err)
	}
	wrong := strings.Repeat("z", len(testVerifier))
	if _, err := store.Verify(code, wrong); err == nil {
		t.Fatal("wrong code_verifier must be rejected")
	}
}

func TestAuthorizationCodeExpiry(t *testing.T) {
	store := newTestStore()
	code, err := store.Generate(AuthorizationInfo{CodeChallenge: challengeFor(testVerifier)})
	if err != nil {
		t.Fatal(err)
	}

	store.mu.Lock()
	entry := store.codes[code]
	entry.expiresAt = time.Now().Add(-time.Minute)
	store.codes[code] = entry
	store.mu.Unlock()

	if _, err := store.Verify(code, testVerifier); err == nil {
		t.Fatal("an expired code must be rejected")
	}
}
