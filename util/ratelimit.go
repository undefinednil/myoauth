package util

import (
	"math"
	"sync"
	"time"
)

const (
	rateLimiterCleanupInterval = 5 * time.Minute
	rateLimiterStaleAfter      = 10 * time.Minute
	defaultRateLimiterMaxKeys  = 100000
)

// RateLimiter is a per-key token bucket. The bucket holds up to `burst` tokens
// and refills at requestsPerMinute/60 tokens per second; each allowed request
// consumes one token. Keys are per-endpoint client IPs (e.g. "login|1.2.3.4").
type RateLimiter struct {
	ratePerSecond float64
	burst         float64
	retryAfter    int
	maxKeys       int

	mu          sync.Mutex
	buckets     map[string]*rateLimiterBucket
	lastCleanup time.Time
}

type rateLimiterBucket struct {
	tokens     float64
	lastRefill time.Time
	lastSeen   time.Time
}

// NewRateLimiter builds a limiter. An optional maxKeys caps the number of
// tracked keys so memory cannot grow unbounded (FIX F11); when full, stale keys
// are cleaned and, if still full, new keys are denied deterministically.
func NewRateLimiter(requestsPerMinute, burst int, maxKeys ...int) *RateLimiter {
	if requestsPerMinute <= 0 {
		requestsPerMinute = 30
	}
	if burst <= 0 {
		burst = 10
	}
	limit := defaultRateLimiterMaxKeys
	if len(maxKeys) > 0 && maxKeys[0] > 0 {
		limit = maxKeys[0]
	}
	retryAfter := int(math.Ceil(60 / float64(requestsPerMinute)))
	if retryAfter < 1 {
		retryAfter = 1
	}
	return &RateLimiter{
		ratePerSecond: float64(requestsPerMinute) / 60,
		burst:         float64(burst),
		retryAfter:    retryAfter,
		maxKeys:       limit,
		buckets:       make(map[string]*rateLimiterBucket),
		lastCleanup:   time.Now(),
	}
}

func (l *RateLimiter) Allow(key string) bool {
	return l.allowAt(key, time.Now())
}

// RetryAfterSeconds is a conservative Retry-After hint for denied requests.
func (l *RateLimiter) RetryAfterSeconds() int {
	return l.retryAfter
}

func (l *RateLimiter) allowAt(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.cleanupLocked(now, false)

	bucket, ok := l.buckets[key]
	if !ok {
		// Enforce the key cap: force a cleanup, then deny if still full rather
		// than growing without bound (FIX F11).
		if len(l.buckets) >= l.maxKeys {
			l.cleanupLocked(now, true)
		}
		if len(l.buckets) >= l.maxKeys {
			return false
		}
		bucket = &rateLimiterBucket{tokens: l.burst, lastRefill: now}
		l.buckets[key] = bucket
	}
	if elapsed := now.Sub(bucket.lastRefill).Seconds(); elapsed > 0 {
		bucket.tokens = math.Min(l.burst, bucket.tokens+elapsed*l.ratePerSecond)
		bucket.lastRefill = now
	}
	bucket.lastSeen = now

	if bucket.tokens < 1 {
		return false
	}
	bucket.tokens--
	return true
}

func (l *RateLimiter) cleanupLocked(now time.Time, force bool) {
	if !force && now.Sub(l.lastCleanup) < rateLimiterCleanupInterval {
		return
	}
	for key, bucket := range l.buckets {
		if now.Sub(bucket.lastSeen) > rateLimiterStaleAfter {
			delete(l.buckets, key)
		}
	}
	l.lastCleanup = now
}
