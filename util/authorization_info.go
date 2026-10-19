package util

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"sync"
	"time"
)

const authorizationCodeTTL = 5 * time.Minute
const authorizationCodeCleanupInterval = 1 * time.Minute

type AuthorizationInfo struct {
	ClientId      int64
	UserId        int64
	RedirectUri   string
	Scope         string
	State         string
	Nonce         string
	CodeChallenge string
}

type authCodeEntry struct {
	info      AuthorizationInfo
	expiresAt time.Time
}

type AuthorizationCodeStore struct {
	conf *Configuration

	mu          sync.Mutex
	codes       map[string]authCodeEntry
	lastCleanup time.Time
}

func NewAuthorizationCodeStore(conf *Configuration) *AuthorizationCodeStore {
	return &AuthorizationCodeStore{
		conf:        conf,
		codes:       make(map[string]authCodeEntry),
		lastCleanup: time.Now(),
	}
}

func (a *AuthorizationCodeStore) Generate(info AuthorizationInfo) (string, error) {
	code, err := RandString(a.conf.AuthorizationCodeLength)
	if err != nil {
		return "", err
	}

	now := time.Now()

	a.mu.Lock()
	defer a.mu.Unlock()

	a.cleanupExpiredLocked(now)

	a.codes[code] = authCodeEntry{
		info:      info,
		expiresAt: now.Add(authorizationCodeTTL),
	}

	return code, nil
}

func (a *AuthorizationCodeStore) Verify(code, codeVerifier string) (*AuthorizationInfo, error) {
	if len(codeVerifier) < 43 || len(codeVerifier) > 128 {
		return nil, errors.New("invalid code verifier")
	}

	now := time.Now()

	a.mu.Lock()
	a.cleanupExpiredLocked(now)

	entry, ok := a.codes[code]
	if !ok {
		a.mu.Unlock()
		return nil, errors.New("invalid authorization code")
	}

	// Authorization codes are single-use.
	delete(a.codes, code)
	a.mu.Unlock()

	if now.After(entry.expiresAt) {
		return nil, errors.New("authorization code expired")
	}

	checksum := sha256.Sum256([]byte(codeVerifier))
	challenge := base64.RawURLEncoding.EncodeToString(checksum[:])

	if challenge != entry.info.CodeChallenge {
		return nil, errors.New("code challenge failed")
	}

	info := entry.info
	return &info, nil
}

func (a *AuthorizationCodeStore) cleanupExpiredLocked(now time.Time) {
	if now.Sub(a.lastCleanup) < authorizationCodeCleanupInterval {
		return
	}

	for code, entry := range a.codes {
		if now.After(entry.expiresAt) {
			delete(a.codes, code)
		}
	}

	a.lastCleanup = now
}
