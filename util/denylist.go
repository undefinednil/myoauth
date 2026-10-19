package util

import (
	"sync"
	"time"
)

const denylistCleanupInterval = 1 * time.Minute

// Denylist holds revoked token identifiers (jti) until their original expiry,
// after which the entry is dropped because the token is invalid anyway.
type Denylist struct {
	mu          sync.Mutex
	entries     map[string]time.Time
	lastCleanup time.Time
}

func NewDenylist() *Denylist {
	return &Denylist{
		entries:     make(map[string]time.Time),
		lastCleanup: time.Now(),
	}
}

func (d *Denylist) Add(jti string, expiresAt time.Time) {
	if jti == "" {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.entries[jti] = expiresAt
}

func (d *Denylist) Contains(jti string) bool {
	return d.containsAt(jti, time.Now())
}

func (d *Denylist) containsAt(jti string, now time.Time) bool {
	if jti == "" {
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	d.cleanupLocked(now)

	expiresAt, ok := d.entries[jti]
	if !ok {
		return false
	}
	if now.After(expiresAt) {
		delete(d.entries, jti)
		return false
	}
	return true
}

func (d *Denylist) cleanupLocked(now time.Time) {
	if now.Sub(d.lastCleanup) < denylistCleanupInterval {
		return
	}
	for jti, expiresAt := range d.entries {
		if now.After(expiresAt) {
			delete(d.entries, jti)
		}
	}
	d.lastCleanup = now
}
