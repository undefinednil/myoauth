package dal

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"
)

const (
	refreshTokenCleanupInterval = 1 * time.Minute
	// usedRefreshTokenRetention is how long the hashes of consumed refresh
	// tokens are kept for replay detection before being pruned.
	usedRefreshTokenRetention = 7 * 24 * time.Hour
)

// ErrTokenNotFound is returned by ConsumeByHash when no active refresh token
// matches the hash and the token was not consumed before.
var ErrTokenNotFound = errors.New("refresh token not found")

// ErrTokenReused is the sentinel for presenting a refresh token that was
// already consumed. Callers can match it with errors.Is; TokenReusedError
// additionally carries the user/client chain to revoke.
var ErrTokenReused = errors.New("refresh token already used")

// TokenReusedError describes a replayed refresh token. The chain identifiers
// let the caller revoke every refresh token of that user/client pair.
type TokenReusedError struct {
	UserId   int64
	ClientId int64
}

func (e *TokenReusedError) Error() string {
	return fmt.Sprintf("%v (user %d, client %d)", ErrTokenReused, e.UserId, e.ClientId)
}

func (e *TokenReusedError) Unwrap() error {
	return ErrTokenReused
}

type IRefreshToken interface {
	Insert(ctx context.Context, token *RefreshToken) error
	SelectByToken(ctx context.Context, token string) (*RefreshToken, error)
	ConsumeByHash(ctx context.Context, tokenHash string) (*RefreshToken, error)
	DeleteById(ctx context.Context, id int64) error
	DeleteByUserAndClient(ctx context.Context, userId, clientId int64) error
	DeleteByClient(ctx context.Context, clientId int64) error
	DeleteAll(ctx context.Context) error
}

type RefreshToken struct {
	db            *sql.DB
	Id            int64
	Token         string
	ClientId      int64
	UserId        int64
	ExpireTime    *time.Time
	Scope         string
	cleanupMu     sync.Mutex
	lastCleanupAt time.Time
}

func (r *RefreshToken) Insert(ctx context.Context, token *RefreshToken) error {
	if err := r.cleanupExpiredIfNeeded(ctx, time.Now()); err != nil {
		return err
	}
	_, err := r.db.ExecContext(ctx, "INSERT INTO refresh_tokens (token, client_id, user_id, expire_time, scope) VALUES (?, ?, ?, ?, ?);", HashToken(token.Token), token.ClientId, token.UserId, token.ExpireTime.Unix(), token.Scope)
	return err
}

func (r *RefreshToken) SelectByToken(ctx context.Context, token string) (refreshToken *RefreshToken, err error) {
	if err := r.cleanupExpiredIfNeeded(ctx, time.Now()); err != nil {
		return nil, err
	}
	rows, err := r.db.QueryContext(ctx, "SELECT * FROM refresh_tokens WHERE token = ?;", HashToken(token))
	if err != nil {
		return nil, err
	}
	defer func() {
		err = errors.Join(err, rows.Close())
	}()
	refreshToken = new(RefreshToken)
	if rows.Next() {
		var unixTime int64
		if err := rows.Scan(&refreshToken.Id, &refreshToken.Token, &refreshToken.ClientId, &refreshToken.UserId, &unixTime, &refreshToken.Scope); err != nil {
			return nil, err
		}
		expireTime := time.Unix(unixTime, 0)
		refreshToken.ExpireTime = &expireTime
	} else {
		return nil, nil
	}
	return refreshToken, err
}

// ConsumeByHash atomically claims a refresh token by its hash, deletes it from
// the active table and records a tombstone in used_refresh_tokens. Because the
// delete and the tombstone insert happen in one transaction, concurrent
// consumers of the same token can never both succeed: the loser observes the
// tombstone and gets a *TokenReusedError (matching ErrTokenReused). A hash
// that was never active returns ErrTokenNotFound.
func (r *RefreshToken) ConsumeByHash(ctx context.Context, tokenHash string) (*RefreshToken, error) {
	if err := r.cleanupExpiredIfNeeded(ctx, time.Now()); err != nil {
		return nil, err
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	token := new(RefreshToken)
	var unixTime int64
	err = tx.QueryRowContext(ctx,
		"DELETE FROM refresh_tokens WHERE token = ? RETURNING id, token, client_id, user_id, expire_time, scope;",
		tokenHash).Scan(&token.Id, &token.Token, &token.ClientId, &token.UserId, &unixTime, &token.Scope)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		// Not active: distinguish a replay from an unknown token.
		var reused TokenReusedError
		checkErr := tx.QueryRowContext(ctx, "SELECT user_id, client_id FROM used_refresh_tokens WHERE token_hash = ?;", tokenHash).
			Scan(&reused.UserId, &reused.ClientId)
		if checkErr == nil {
			return nil, &reused
		}
		if !errors.Is(checkErr, sql.ErrNoRows) {
			return nil, checkErr
		}
		return nil, ErrTokenNotFound
	}
	expireTime := time.Unix(unixTime, 0)
	token.ExpireTime = &expireTime
	if _, err := tx.ExecContext(ctx,
		"INSERT OR REPLACE INTO used_refresh_tokens (token_hash, user_id, client_id, used_at) VALUES (?, ?, ?, ?);",
		tokenHash, token.UserId, token.ClientId, time.Now().Unix()); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return token, nil
}

// HashToken returns the hex-encoded SHA-256 digest stored for a refresh token.
// Callers that consume a token by hash must hash the raw token with this
// function.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func (r *RefreshToken) DeleteById(ctx context.Context, id int64) error {
	if err := r.cleanupExpiredIfNeeded(ctx, time.Now()); err != nil {
		return err
	}
	_, err := r.db.ExecContext(ctx, "DELETE FROM refresh_tokens WHERE id = ?;", id)
	return err
}

// DeleteByUserAndClient revokes every refresh token a user holds for a client.
// It is the method used to tear down a replaying refresh token's chain.
func (r *RefreshToken) DeleteByUserAndClient(ctx context.Context, userId, clientId int64) error {
	if err := r.cleanupExpiredIfNeeded(ctx, time.Now()); err != nil {
		return err
	}
	_, err := r.db.ExecContext(ctx, "DELETE FROM refresh_tokens WHERE user_id = ? AND client_id = ?;", userId, clientId)
	return err
}

func (r *RefreshToken) DeleteByClient(ctx context.Context, clientId int64) error {
	if err := r.cleanupExpiredIfNeeded(ctx, time.Now()); err != nil {
		return err
	}
	_, err := r.db.ExecContext(ctx, "DELETE FROM refresh_tokens WHERE client_id = ?;", clientId)
	return err
}

func (r *RefreshToken) DeleteAll(ctx context.Context) error {
	if err := r.cleanupExpiredIfNeeded(ctx, time.Now()); err != nil {
		return err
	}
	_, err := r.db.ExecContext(ctx, "DELETE FROM refresh_tokens;")
	return err
}

// cleanupExpiredIfNeeded prunes expired refresh tokens and replay tombstones
// older than usedRefreshTokenRetention, at most once per interval.
func (r *RefreshToken) cleanupExpiredIfNeeded(ctx context.Context, now time.Time) error {
	r.cleanupMu.Lock()
	defer r.cleanupMu.Unlock()

	if !r.lastCleanupAt.IsZero() && now.Sub(r.lastCleanupAt) < refreshTokenCleanupInterval {
		return nil
	}
	if _, err := r.db.ExecContext(ctx, "DELETE FROM refresh_tokens WHERE expire_time < ?;", now.Unix()); err != nil {
		return err
	}
	if _, err := r.db.ExecContext(ctx, "DELETE FROM used_refresh_tokens WHERE used_at < ?;", now.Add(-usedRefreshTokenRetention).Unix()); err != nil {
		return err
	}
	r.lastCleanupAt = now
	return nil
}
