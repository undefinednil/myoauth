package token

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"strings"
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
	pemData, err := os.ReadFile(t.conf.RsaPrivateKeyPath)
	if err != nil {
		return err
	}
	privateKeyBlock, _ := pem.Decode(pemData)
	if privateKeyBlock == nil {
		return errors.New("Token Init read RSA private key failed")
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(privateKeyBlock.Bytes)
	if err != nil {
		// if it's not a PKCS#1 private key, try to parse it as a PKCS#8 key
		privateKeyInterface, err2 := x509.ParsePKCS8PrivateKey(privateKeyBlock.Bytes)
		if err2 != nil {
			return err2
		}
		var ok bool
		privateKey, ok = privateKeyInterface.(*rsa.PrivateKey)
		if !ok {
			return errors.New("Token Init convert RSA private key failed")
		}
	}
	t.rsaPrivateKey = privateKey
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
