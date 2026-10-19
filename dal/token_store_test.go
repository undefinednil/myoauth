package dal

import (
	"testing"
	"time"
)

// TestTokenStoreTrackAndRevoke covers tracking, the per-pair/client/all revoke
// paths, and the fact that an already-expired revocation is not reported.
func TestTokenStoreTrackAndRevoke(t *testing.T) {
	s := &TokenStore{db: newTestDB(t)}
	ctx := t.Context()
	exp := time.Now().Add(time.Hour)

	// An empty jti is a no-op for both tracking and revoking.
	if err := s.TrackAccessToken(ctx, "", 1, 1, exp); err != nil {
		t.Fatalf("TrackAccessToken empty: %v", err)
	}
	if err := s.Revoke(ctx, "", exp); err != nil {
		t.Fatalf("Revoke empty: %v", err)
	}
	if revoked, err := s.IsRevoked(ctx, ""); err != nil || revoked {
		t.Fatalf("IsRevoked empty = %v (err %v), want false", revoked, err)
	}

	tracked := []struct {
		jti      string
		userId   int64
		clientId int64
	}{
		{"jti-u1-c1", 1, 1},
		{"jti-u1-c2", 1, 2},
		{"jti-u2-c2", 2, 2},
	}
	for _, tok := range tracked {
		if err := s.TrackAccessToken(ctx, tok.jti, tok.userId, tok.clientId, exp); err != nil {
			t.Fatalf("TrackAccessToken %s: %v", tok.jti, err)
		}
	}
	if revoked, err := s.IsRevoked(ctx, "jti-u1-c1"); err != nil || revoked {
		t.Fatalf("tracked token IsRevoked = %v (err %v), want false", revoked, err)
	}

	// RevokeAccessTokensByUserAndClient only moves the matching pair.
	if err := s.RevokeAccessTokensByUserAndClient(ctx, 1, 1); err != nil {
		t.Fatalf("RevokeAccessTokensByUserAndClient: %v", err)
	}
	if revoked, err := s.IsRevoked(ctx, "jti-u1-c1"); err != nil || !revoked {
		t.Fatalf("pair token after revoke = %v (err %v), want true", revoked, err)
	}
	if revoked, err := s.IsRevoked(ctx, "jti-u1-c2"); err != nil || revoked {
		t.Fatalf("unrelated token after pair revoke = %v (err %v), want false", revoked, err)
	}

	// RevokeAccessTokensByClient moves the tracked tokens of that client only.
	if err := s.RevokeAccessTokensByClient(ctx, 2); err != nil {
		t.Fatalf("RevokeAccessTokensByClient(2): %v", err)
	}
	for _, jti := range []string{"jti-u1-c2", "jti-u2-c2"} {
		if revoked, err := s.IsRevoked(ctx, jti); err != nil || !revoked {
			t.Fatalf("%s after client revoke = %v (err %v), want true", jti, revoked, err)
		}
	}

	// Client id 0 revokes everything still tracked.
	if err := s.TrackAccessToken(ctx, "jti-fresh", 3, 3, exp); err != nil {
		t.Fatalf("TrackAccessToken fresh: %v", err)
	}
	if err := s.RevokeAccessTokensByClient(ctx, 0); err != nil {
		t.Fatalf("RevokeAccessTokensByClient(0): %v", err)
	}
	if revoked, err := s.IsRevoked(ctx, "jti-fresh"); err != nil || !revoked {
		t.Fatalf("fresh token after revoke-all = %v (err %v), want true", revoked, err)
	}

	// A direct revoke is idempotent and visible; an expired one is not.
	if err := s.Revoke(ctx, "manual-jti", exp); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if err := s.Revoke(ctx, "manual-jti", exp); err != nil {
		t.Fatalf("Revoke twice: %v", err)
	}
	if revoked, err := s.IsRevoked(ctx, "manual-jti"); err != nil || !revoked {
		t.Fatalf("manual jti IsRevoked = %v (err %v), want true", revoked, err)
	}
	if err := s.Revoke(ctx, "expired-jti", time.Now().Add(-time.Minute)); err != nil {
		t.Fatalf("Revoke expired: %v", err)
	}
	if revoked, err := s.IsRevoked(ctx, "expired-jti"); err != nil || revoked {
		t.Fatalf("expired jti IsRevoked = %v (err %v), want false", revoked, err)
	}
}
