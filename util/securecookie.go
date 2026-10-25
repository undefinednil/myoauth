package util

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
)

// SecureCookieCodec encodes and decodes integrity-protected, encrypted cookie
// payloads. It uses AES-256-GCM with a key derived from the configured secret
// via SHA-256, so a cookie is both confidential (nobody can read the session
// tokens it carries) and tamper-evident (any modification fails the GCM tag).
//
// The wire format is base64url(nonce || ciphertext+tag), with no padding.
type SecureCookieCodec struct {
	aead cipher.AEAD
}

// NewSecureCookieCodec derives the AES-256 key from secret. The secret should
// be at least 32 bytes; callers validate that at configuration time.
func NewSecureCookieCodec(secret string) (*SecureCookieCodec, error) {
	key := sha256.Sum256([]byte(secret))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &SecureCookieCodec{aead: aead}, nil
}

// Encode marshals payload to JSON and returns a sealed, base64url token.
func (c *SecureCookieCodec) Encode(payload any) (string, error) {
	plain, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := c.aead.Seal(nil, nonce, plain, nil)
	out := make([]byte, 0, len(nonce)+len(sealed))
	out = append(out, nonce...)
	out = append(out, sealed...)
	return base64.RawURLEncoding.EncodeToString(out), nil
}

// Decode verifies and decrypts value into payload. It returns an error for a
// malformed token, a failed authentication tag (tampering or a wrong key) or a
// JSON payload that does not match the destination type.
func (c *SecureCookieCodec) Decode(value string, payload any) error {
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return err
	}
	nonceSize := c.aead.NonceSize()
	if len(raw) < nonceSize+c.aead.Overhead() {
		return errors.New("secure cookie is too short")
	}
	nonce, ciphertext := raw[:nonceSize], raw[nonceSize:]
	plain, err := c.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return err
	}
	return json.Unmarshal(plain, payload)
}
