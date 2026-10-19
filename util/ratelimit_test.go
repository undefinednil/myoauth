package util

import (
	"testing"
	"time"
)

func TestRateLimiterAllowAndDeny(t *testing.T) {
	limiter := NewRateLimiter(60, 2)
	now := time.Now()

	if !limiter.allowAt("a", now) {
		t.Fatal("first request should be allowed")
	}
	if !limiter.allowAt("a", now) {
		t.Fatal("second request should be allowed (burst)")
	}
	if limiter.allowAt("a", now) {
		t.Fatal("third request should be denied")
	}
	if !limiter.allowAt("b", now) {
		t.Fatal("a different key has its own bucket")
	}
}

func TestRateLimiterRefill(t *testing.T) {
	limiter := NewRateLimiter(60, 1)
	now := time.Now()

	if !limiter.allowAt("a", now) {
		t.Fatal("first request should be allowed")
	}
	if limiter.allowAt("a", now) {
		t.Fatal("immediate second request should be denied")
	}
	if !limiter.allowAt("a", now.Add(time.Second)) {
		t.Fatal("bucket should refill one token after a second")
	}
}

func TestRateLimiterDefaults(t *testing.T) {
	limiter := NewRateLimiter(0, 0)
	if limiter.burst < 1 {
		t.Fatalf("expected positive default burst, got %v", limiter.burst)
	}
	if limiter.RetryAfterSeconds() < 1 {
		t.Fatalf("expected positive retry-after, got %v", limiter.RetryAfterSeconds())
	}
}

func TestRateLimiterMaxKeys(t *testing.T) {
	limiter := NewRateLimiter(60, 1, 2)
	now := time.Now()

	if !limiter.allowAt("a", now) {
		t.Fatal("first key should be allowed")
	}
	if !limiter.allowAt("b", now) {
		t.Fatal("second key should be allowed")
	}
	if limiter.allowAt("c", now) {
		t.Fatal("a new key must be denied once the key cap is reached")
	}
	if len(limiter.buckets) > 2 {
		t.Fatalf("bucket count = %d, want <= 2", len(limiter.buckets))
	}
}
