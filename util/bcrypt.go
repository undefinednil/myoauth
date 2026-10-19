package util

import (
	"errors"
	"golang.org/x/crypto/bcrypt"
)

func BCryptPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	return string(bytes), err
}

func BCryptHashCheck(hashed, password string) (bool, error) {
	if err := bcrypt.CompareHashAndPassword([]byte(hashed), []byte(password)); errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	return true, nil
}
