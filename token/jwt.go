package token

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/cristalhq/jwt/v5"
	"github.com/zenpk/my-oauth/util"
)

// Token use values distinguishing access tokens from ID tokens. Without this
// claim both token kinds are indistinguishable (same signing key, same
// audience), so an ID token would be accepted where an access token is
// required (FIX F3).
const (
	TokenUseAccess = "access"
	TokenUseID     = "id"
)

type AccessTokenClaims struct {
	jwt.RegisteredClaims
	TokenUse string `json:"token_use,omitempty"`
	Scope    string `json:"scope,omitempty"`
}

type IDTokenClaims struct {
	jwt.RegisteredClaims
	TokenUse string `json:"token_use,omitempty"`
	Nonce    string `json:"nonce,omitempty"`
	Name     string `json:"name,omitempty"`
	AuthTime int64  `json:"auth_time,omitempty"`
	AtHash   string `json:"at_hash,omitempty"`
	CHash    string `json:"c_hash,omitempty"`
}

// OIDCHash computes the at_hash/c_hash claim value for OIDC: the SHA-256 digest
// of the value, truncated to its left half (128 bits), base64url without padding.
func OIDCHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return base64.RawURLEncoding.EncodeToString(sum[:len(sum)/2])
}

func (t *Token) Init(conf *util.Configuration, logger *util.Logger) error {
	t.conf = conf
	t.logger = logger
	// parse private key
	keyPath := t.conf.RsaPrivateKeyPath
	pemData, err := t.readOrGeneratePrivateKey(keyPath)
	if err != nil {
		return err
	}
	privateKeyBlock, _ := pem.Decode(pemData)
	if privateKeyBlock == nil {
		return fmt.Errorf("read RSA private key %q: not a PEM block", keyPath)
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(privateKeyBlock.Bytes)
	if err != nil {
		// if it's not a PKCS#1 private key, try to parse it as a PKCS#8 key
		privateKeyInterface, err2 := x509.ParsePKCS8PrivateKey(privateKeyBlock.Bytes)
		if err2 != nil {
			return fmt.Errorf("parse RSA private key %q: %w", keyPath, err2)
		}
		var ok bool
		privateKey, ok = privateKeyInterface.(*rsa.PrivateKey)
		if !ok {
			return fmt.Errorf("parse RSA private key %q: not an RSA key", keyPath)
		}
	}
	t.rsaPrivateKey = privateKey
	return nil
}

// keyGenMu serialises the read/generate sequence within this process so a
// concurrent Init cannot observe a half-written key file (the O_EXCL used
// below only protects the on-disk race between separate processes).
var keyGenMu sync.Mutex

// readOrGeneratePrivateKey returns the PEM bytes at path, generating a key on
// first boot when the file is absent. The whole "absent then create" sequence
// runs under keyGenMu so two concurrent Inits in this process cannot both
// generate a key or read a partially written one.
func (t *Token) readOrGeneratePrivateKey(path string) ([]byte, error) {
	keyGenMu.Lock()
	defer keyGenMu.Unlock()

	pemData, err := os.ReadFile(path)
	if err == nil {
		return pemData, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read RSA private key %q: %w", path, err)
	}
	// No key yet: generate one so the operator does not have to manage a key
	// file (the path is typically a persistent volume). A missing or unwritable
	// parent directory is a hard error rather than a silent creation of
	// arbitrary directories.
	if err := t.generatePrivateKey(path); err != nil {
		return nil, err
	}
	return t.readKeyAfterGeneration(path)
}

// readKeyAfterGeneration reads path after generatePrivateKey reported success.
// The file may have been created by this process (already fully written and
// synced) or by another process that won the O_EXCL race; the latter may still
// be mid-write, so a short retry avoids mistaking a truncated read for a
// malformed key. A genuinely malformed file still fails (and is never
// overwritten, because generatePrivateKey only runs when the file was absent).
func (t *Token) readKeyAfterGeneration(path string) ([]byte, error) {
	const attempts = 20
	for i := 0; i < attempts; i++ {
		pemData, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read RSA private key %q: %w", path, err)
		}
		if block, _ := pem.Decode(pemData); block != nil {
			return pemData, nil
		}
		if i < attempts-1 {
			time.Sleep(25 * time.Millisecond)
		}
	}
	return nil, fmt.Errorf("read RSA private key %q: not a PEM block", path)
}

// generatePrivateKey creates a new 2048-bit RSA signing key at path and writes
// it as a PKCS#1 PEM ("RSA PRIVATE KEY", mode 0600). The parent directory must
// already exist and be writable: MyOAuth never creates arbitrary directories.
//
// It is race-safe against a concurrent first boot: the file is created with
// O_EXCL, so only one process can win; a loser never overwrites the winner's
// file. The write is followed by Sync so a crash cannot leave a silently
// truncated PEM on disk (an existing malformed file is always a hard error
// elsewhere, never overwritten).
func (t *Token) generatePrivateKey(path string) error {
	// Another process may have created the file since the caller's ReadFile.
	// If so, do nothing: the caller re-reads the existing key.
	if _, err := os.Stat(path); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("cannot generate RSA key at %q: %w", path, err)
	}

	dir := filepath.Dir(path)
	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("cannot generate RSA key at %q: directory %q is not accessible: %w", path, dir, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("cannot generate RSA key at %q: %q is not a directory", path, dir)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("generate RSA key: %w", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	// O_EXCL guarantees we never clobber an existing key. On a lost race we
	// simply leave the winner's file alone and let the caller load it.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if os.IsExist(err) {
			return nil
		}
		return fmt.Errorf("write RSA private key %q: %w", path, err)
	}
	if _, err := f.Write(pemBytes); err != nil {
		_ = f.Close()
		return fmt.Errorf("write RSA private key %q: %w", path, err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("write RSA private key %q: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("write RSA private key %q: %w", path, err)
	}
	if t.logger != nil {
		t.logger.Println(fmt.Sprintf("WARNING: generated a new RSA signing key at %s; persist this path (volume) or tokens/token validation will break on restart", path))
	}
	return nil
}

func (t *Token) GenJwt(claims *AccessTokenClaims) (string, error) {
	signer, err := jwt.NewSignerRS(jwt.RS256, t.rsaPrivateKey)
	if err != nil {
		return "", err
	}
	builder := jwt.NewBuilder(signer)
	token, err := builder.Build(claims)
	if err != nil {
		return "", err
	}
	return token.String(), nil
}

func (t *Token) GenIDToken(claims *IDTokenClaims) (string, error) {
	signer, err := jwt.NewSignerRS(jwt.RS256, t.rsaPrivateKey)
	if err != nil {
		return "", err
	}
	builder := jwt.NewBuilder(signer)
	token, err := builder.Build(claims)
	if err != nil {
		return "", err
	}
	return token.String(), nil
}

// ParseAndVerifyJwt parses and verifies a JWT without enforcing a token_use
// value. Prefer ParseAndVerifyAccessJwt / ParseAndVerifyIDJwt in security
// sensitive paths.
func (t *Token) ParseAndVerifyJwt(token string, expectedAudience ...string) (*AccessTokenClaims, bool, error) {
	return t.parseAndVerifyJwt(token, "", expectedAudience...)
}

// ParseAndVerifyAccessJwt parses and verifies an access token, rejecting any
// token whose token_use is not "access" (e.g. an ID token). This prevents
// token-type confusion at /userinfo, /introspect and /revoke (FIX F3).
func (t *Token) ParseAndVerifyAccessJwt(token string, expectedAudience ...string) (*AccessTokenClaims, bool, error) {
	return t.parseAndVerifyJwt(token, TokenUseAccess, expectedAudience...)
}

// ParseAndVerifyIDJwt parses and verifies an ID token, rejecting any token
// whose token_use is not "id".
func (t *Token) ParseAndVerifyIDJwt(token string, expectedAudience ...string) (*AccessTokenClaims, bool, error) {
	return t.parseAndVerifyJwt(token, TokenUseID, expectedAudience...)
}

// ParseAndVerifyIDJwtAllowExpired verifies an ID token's signature, issuer and
// token_use but skips the expiry check. OIDC recommends accepting an expired ID
// token as the logout id_token_hint so a user whose token has expired can still
// have the RP initiate logout. It must never be used for /userinfo,
// /introspect or /revoke.
func (t *Token) ParseAndVerifyIDJwtAllowExpired(token string, expectedAudience ...string) (*AccessTokenClaims, bool, error) {
	return t.parseAndVerifyJwtWithExpiry(token, TokenUseID, true, expectedAudience...)
}

func (t *Token) parseAndVerifyJwt(token, expectedTokenUse string, expectedAudience ...string) (*AccessTokenClaims, bool, error) {
	return t.parseAndVerifyJwtWithExpiry(token, expectedTokenUse, false, expectedAudience...)
}

func (t *Token) parseAndVerifyJwtWithExpiry(token, expectedTokenUse string, allowExpired bool, expectedAudience ...string) (*AccessTokenClaims, bool, error) {
	verifier, err := jwt.NewVerifierRS(jwt.RS256, &t.rsaPrivateKey.PublicKey)
	if err != nil {
		return nil, false, err
	}
	// parse and verify a token
	parsedToken, err := jwt.Parse([]byte(token), verifier)
	if err != nil {
		return nil, false, err
	}
	newClaims := new(AccessTokenClaims)
	if err := json.Unmarshal(parsedToken.Claims(), newClaims); err != nil {
		return nil, false, err
	}
	expectedIssuer := strings.TrimSuffix(strings.TrimSpace(t.conf.OidcIssuer), "/")
	if newClaims.Issuer != expectedIssuer {
		t.logger.Println("verify JWT error: issuer not matched")
		return nil, false, nil
	}
	if expectedTokenUse != "" && newClaims.TokenUse != expectedTokenUse {
		t.logger.Println("verify JWT error: token_use not matched")
		return nil, false, nil
	}
	if len(expectedAudience) > 0 {
		matched := false
		for _, aud := range expectedAudience {
			if aud != "" && newClaims.IsForAudience(aud) {
				matched = true
				break
			}
		}
		if !matched {
			t.logger.Println("verify JWT error: audience not matched")
			return nil, false, nil
		}
	} else if len(newClaims.Audience) == 0 {
		t.logger.Println("verify JWT error: audience missing")
		return nil, false, nil
	}
	if !allowExpired && !newClaims.IsValidAt(time.Now()) {
		t.logger.Println("verify JWT error: token expired")
		return nil, false, nil
	}
	return newClaims, true, nil
}

type Jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	E   string `json:"e"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
}

// Get converts an RSA public key in PEM format to a JWK
func (t *Token) GetJWK() (*Jwk, error) {
	// encode modulus and exponent to Base64 URL
	modulus := t.base64URLEncode(t.rsaPrivateKey.PublicKey.N)
	exponent := t.base64URLEncode(big.NewInt(int64(t.rsaPrivateKey.PublicKey.E)))
	sum := sha256.Sum256([]byte(modulus + "." + exponent))
	kid := base64.RawURLEncoding.EncodeToString(sum[:])
	return &Jwk{
		Kty: "RSA",
		Kid: kid,
		E:   exponent,
		Use: "sig",
		Alg: "RS256",
		N:   modulus,
	}, nil
}

// base64URLEncode encodes a big integer (like RSA modulus or exponent) in the Base64 URL encoding
func (t *Token) base64URLEncode(value *big.Int) string {
	// the RawURLEncoding is used to avoid padding, which is typical for URL-encoded base64 variants
	return base64.RawURLEncoding.EncodeToString(value.Bytes())
}
