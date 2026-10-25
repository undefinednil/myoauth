package token

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"path/filepath"
	"testing"
	"time"

	"github.com/cristalhq/jwt/v5"
	"github.com/zenpk/my-oauth/util"
)

func newTestLogger(t *testing.T) *util.Logger {
	t.Helper()
	logger := new(util.Logger)
	if err := logger.Init(&util.Configuration{LogFilePath: filepath.Join(t.TempDir(), "token.log")}); err != nil {
		t.Fatalf("logger.Init: %v", err)
	}
	t.Cleanup(func() { _ = logger.Close() })
	return logger
}

func newTestToken(t *testing.T, issuer string, key *rsa.PrivateKey) *Token {
	t.Helper()
	return &Token{
		conf:          &util.Configuration{OidcIssuer: issuer},
		logger:        newTestLogger(t),
		rsaPrivateKey: key,
	}
}

func testClaims(issuer string, expiresAt time.Time, audience string) *AccessTokenClaims {
	return &AccessTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   "user-uuid",
			Audience:  jwt.Audience{audience},
			ExpiresAt: &jwt.NumericDate{Time: expiresAt},
			IssuedAt:  &jwt.NumericDate{Time: time.Now()},
			ID:        "jti-1",
		},
		Scope: "openid profile",
	}
}

func TestJwtGenerateAndVerify(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tk := newTestToken(t, "https://issuer.example.com", key)

	raw, err := tk.GenJwt(testClaims("https://issuer.example.com", time.Now().Add(time.Hour), "client-a"))
	if err != nil {
		t.Fatalf("GenJwt: %v", err)
	}
	claims, ok, err := tk.ParseAndVerifyJwt(raw, "client-a")
	if err != nil {
		t.Fatalf("ParseAndVerifyJwt: %v", err)
	}
	if !ok {
		t.Fatal("expected token to verify")
	}
	if claims.ID != "jti-1" || claims.Scope != "openid profile" {
		t.Fatalf("unexpected claims: %+v", claims)
	}
}

func TestJwtIssuerMismatch(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer := newTestToken(t, "https://issuer.example.com", key)
	verifier := newTestToken(t, "https://other.example.com", key)

	raw, err := signer.GenJwt(testClaims("https://issuer.example.com", time.Now().Add(time.Hour), "client-a"))
	if err != nil {
		t.Fatal(err)
	}
	_, ok, err := verifier.ParseAndVerifyJwt(raw, "client-a")
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("a token with a different issuer must not verify")
	}
}

func TestJwtExpiry(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tk := newTestToken(t, "https://issuer.example.com", key)

	raw, err := tk.GenJwt(testClaims("https://issuer.example.com", time.Now().Add(-time.Minute), "client-a"))
	if err != nil {
		t.Fatal(err)
	}
	_, ok, err := tk.ParseAndVerifyJwt(raw, "client-a")
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("an expired token must not verify")
	}
}

func TestJwtAudienceMismatch(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tk := newTestToken(t, "https://issuer.example.com", key)

	raw, err := tk.GenJwt(testClaims("https://issuer.example.com", time.Now().Add(time.Hour), "client-a"))
	if err != nil {
		t.Fatal(err)
	}
	_, ok, err := tk.ParseAndVerifyJwt(raw, "client-b")
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("a token for another audience must not verify")
	}
}

func TestJwtTokenUseEnforced(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tk := newTestToken(t, "https://issuer.example.com", key)
	issuer := "https://issuer.example.com"

	accessClaims := testClaims(issuer, time.Now().Add(time.Hour), "client-a")
	accessClaims.TokenUse = TokenUseAccess
	rawAccess, err := tk.GenJwt(accessClaims)
	if err != nil {
		t.Fatal(err)
	}
	idClaims := &IDTokenClaims{
		TokenUse: TokenUseID,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   "user-uuid",
			Audience:  jwt.Audience{"client-a"},
			ExpiresAt: &jwt.NumericDate{Time: time.Now().Add(time.Hour)},
			IssuedAt:  &jwt.NumericDate{Time: time.Now()},
			ID:        "jti-2",
		},
	}
	rawID, err := tk.GenIDToken(idClaims)
	if err != nil {
		t.Fatal(err)
	}

	if _, ok, err := tk.ParseAndVerifyAccessJwt(rawAccess, "client-a"); err != nil || !ok {
		t.Fatalf("access token must verify as access (ok=%v err=%v)", ok, err)
	}
	if _, ok, err := tk.ParseAndVerifyAccessJwt(rawID, "client-a"); err != nil || ok {
		t.Fatalf("id token must NOT verify as access (ok=%v err=%v)", ok, err)
	}
	if _, ok, err := tk.ParseAndVerifyIDJwt(rawID, "client-a"); err != nil || !ok {
		t.Fatalf("id token must verify as id (ok=%v err=%v)", ok, err)
	}
	if _, ok, err := tk.ParseAndVerifyIDJwt(rawAccess, "client-a"); err != nil || ok {
		t.Fatalf("access token must NOT verify as id (ok=%v err=%v)", ok, err)
	}
}

func TestJwtIDAllowExpired(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	issuer := "https://issuer.example.com"
	tk := newTestToken(t, issuer, key)

	expiredID := &IDTokenClaims{
		TokenUse: TokenUseID,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   "user-uuid",
			Audience:  jwt.Audience{"client-a"},
			ExpiresAt: &jwt.NumericDate{Time: time.Now().Add(-time.Hour)},
			IssuedAt:  &jwt.NumericDate{Time: time.Now().Add(-2 * time.Hour)},
			ID:        "jti-exp",
		},
	}
	raw, err := tk.GenIDToken(expiredID)
	if err != nil {
		t.Fatal(err)
	}

	if _, ok, err := tk.ParseAndVerifyIDJwt(raw, "client-a"); err != nil || ok {
		t.Fatalf("expired id token must not verify normally (ok=%v err=%v)", ok, err)
	}
	if _, ok, err := tk.ParseAndVerifyIDJwtAllowExpired(raw, "client-a"); err != nil || !ok {
		t.Fatalf("expired id token must verify with allow-expired (ok=%v err=%v)", ok, err)
	}
	// Wrong audience is still rejected even when expiry is skipped.
	if _, ok, err := tk.ParseAndVerifyIDJwtAllowExpired(raw, "client-b"); err != nil || ok {
		t.Fatalf("wrong audience must not verify with allow-expired (ok=%v err=%v)", ok, err)
	}
	// An expired access token must never verify as an ID token.
	expiredAccess := testClaims(issuer, time.Now().Add(-time.Hour), "client-a")
	expiredAccess.TokenUse = TokenUseAccess
	rawAccess, err := tk.GenJwt(expiredAccess)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, err := tk.ParseAndVerifyIDJwtAllowExpired(rawAccess, "client-a"); err != nil || ok {
		t.Fatalf("access token must not verify as id with allow-expired (ok=%v err=%v)", ok, err)
	}
}

func TestOIDCHash(t *testing.T) {
	// at_hash example from the OpenID/JWT specifications.
	want := "77QmUPtjPfzWtF2AnpK9RQ"
	if got := OIDCHash("jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y"); got != want {
		t.Fatalf("OIDCHash = %q, want %q", got, want)
	}

	// Independently recompute the left-half truncation for an arbitrary value.
	sum := sha256.Sum256([]byte("hello"))
	expected := base64.RawURLEncoding.EncodeToString(sum[:len(sum)/2])
	if got := OIDCHash("hello"); got != expected {
		t.Fatalf("OIDCHash = %q, want %q", got, expected)
	}
	if got := OIDCHash("hello"); got != "LPJNul-wow4m6Dsqxbning" {
		t.Fatalf("OIDCHash = %q, want known vector", got)
	}
}
