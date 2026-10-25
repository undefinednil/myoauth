package util

import (
	"testing"
	"time"
)

func TestDenylistAddCheckExpiry(t *testing.T) {
	denylist := NewDenylist()
	now := time.Now()

	denylist.Add("jti-1", now.Add(time.Minute))
	if !denylist.containsAt("jti-1", now) {
		t.Fatal("expected jti-1 to be denied")
	}
	if denylist.containsAt("missing", now) {
		t.Fatal("unknown jti must not be denied")
	}
	if denylist.containsAt("jti-1", now.Add(2*time.Minute)) {
		t.Fatal("entry must expire with the token lifetime")
	}
}

func TestDenylistIgnoresEmptyJTI(t *testing.T) {
	denylist := NewDenylist()
	denylist.Add("", time.Now().Add(time.Hour))
	if denylist.Contains("") {
		t.Fatal("empty jti must never be denied")
	}
}
