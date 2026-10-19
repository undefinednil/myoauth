package util

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"math/big"
)

var letters = []rune("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func RandString(length int) (string, error) {
	b := make([]rune, length)
	for i := range b {
		randInt, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		if err != nil {
			return "", err
		}
		b[i] = letters[randInt.Int64()]
	}
	return string(b), nil
}

func RandomHex(byteLength int) (string, error) {
	b := make([]byte, byteLength)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// RandBase64URL returns byteLength cryptographically random bytes encoded as
// unpadded base64url. Used for opaque forward-auth session identifiers, whose
// entropy makes the value unguessable without MACing it (FIX A).
func RandBase64URL(byteLength int) (string, error) {
	b := make([]byte, byteLength)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
