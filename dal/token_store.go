package dal

import (
	"context"
	"database/sql"
	"sync"
	"time"
)

const tokenStoreCleanupInterval = 1 * time.Minute

type ITokenStore interface {
	Revoke(ctx context.Context, jti string, exp time.Time) error
	IsRevoked(ctx context.Context, jti string) (bool, error)
	TrackAccessToken(ctx context.Context, jti string, userId, clientId int64, exp time.Time) error
	RevokeAccessTokensByClient(ctx context.Context, clientId int64) error
	RevokeAccessTokensByUserAndClient(ctx context.Context, userId, clientId int64) error
}

// TokenStore keeps two durable tables: revoked_tokens holds revoked access
// token identifiers until their expiry, and access_tokens tracks issued access
// tokens so a session revoke can invalidate outstanding ones even after a
// restart (FIX F9).
type TokenStore struct {
	db            *sql.DB
	cleanupMu     sync.Mutex
	lastCleanupAt time.Time
}

func (s *TokenStore) Revoke(ctx context.Context, jti string, exp time.Time) error {
	if jti == "" {
		return nil
	}
	if err := s.cleanupExpiredIfNeeded(ctx, time.Now()); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, "INSERT OR REPLACE INTO revoked_tokens (jti, exp) VALUES (?, ?);", jti, exp.Unix())
	return err
}

func (s *TokenStore) IsRevoked(ctx context.Context, jti string) (bool, error) {
	if jti == "" {
		return false, nil
	}
	if err := s.cleanupExpiredIfNeeded(ctx, time.Now()); err != nil {
		return false, err
	}
	var exists int
	if err := s.db.QueryRowContext(ctx, "SELECT 1 FROM revoked_tokens WHERE jti = ? AND exp > ? LIMIT 1;", jti, time.Now().Unix()).Scan(&exists); err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (s *TokenStore) TrackAccessToken(ctx context.Context, jti string, userId, clientId int64, exp time.Time) error {
	if jti == "" {
		return nil
	}
	if err := s.cleanupExpiredIfNeeded(ctx, time.Now()); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, "INSERT OR REPLACE INTO access_tokens (jti, user_id, client_id, exp) VALUES (?, ?, ?, ?);", jti, userId, clientId, exp.Unix())
	return err
}

// RevokeAccessTokensByClient moves all tracked access tokens for a client into
// revoked_tokens and drops them from access_tokens. A clientId of 0 affects
// every client. Used by the admin session-revoke endpoint (FIX F9).
func (s *TokenStore) RevokeAccessTokensByClient(ctx context.Context, clientId int64) error {
	if err := s.cleanupExpiredIfNeeded(ctx, time.Now()); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if clientId == 0 {
		if _, err := tx.ExecContext(ctx, "INSERT OR REPLACE INTO revoked_tokens (jti, exp) SELECT jti, exp FROM access_tokens;"); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM access_tokens;"); err != nil {
			return err
		}
	} else {
		if _, err := tx.ExecContext(ctx, "INSERT OR REPLACE INTO revoked_tokens (jti, exp) SELECT jti, exp FROM access_tokens WHERE client_id = ?;", clientId); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM access_tokens WHERE client_id = ?;", clientId); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// RevokeAccessTokensByUserAndClient moves the tracked access tokens for a
// single user/client pair into revoked_tokens and drops them from
// access_tokens. Used by RP-initiated logout so outstanding access tokens die
// together with the session's refresh tokens.
func (s *TokenStore) RevokeAccessTokensByUserAndClient(ctx context.Context, userId, clientId int64) error {
	if err := s.cleanupExpiredIfNeeded(ctx, time.Now()); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, "INSERT OR REPLACE INTO revoked_tokens (jti, exp) SELECT jti, exp FROM access_tokens WHERE user_id = ? AND client_id = ?;", userId, clientId); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM access_tokens WHERE user_id = ? AND client_id = ?;", userId, clientId); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *TokenStore) cleanupExpiredIfNeeded(ctx context.Context, now time.Time) error {
	s.cleanupMu.Lock()
	defer s.cleanupMu.Unlock()

	if !s.lastCleanupAt.IsZero() && now.Sub(s.lastCleanupAt) < tokenStoreCleanupInterval {
		return nil
	}
	if _, err := s.db.ExecContext(ctx, "DELETE FROM access_tokens WHERE exp < ?;", now.Unix()); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, "DELETE FROM revoked_tokens WHERE exp < ?;", now.Unix()); err != nil {
		return err
	}
	s.lastCleanupAt = now
	return nil
}
