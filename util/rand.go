package util

import (
	"crypto/rand"
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
