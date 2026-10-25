package dal

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

const refreshTokenCleanupInterval = 1 * time.Minute

type IRefreshToken interface {
	Init() error
	Insert(token *RefreshToken) error
	SelectByToken(token string) (*RefreshToken, error)
	DeleteById(id int64) error
	DeleteByUserAndClient(userId, clientId int64) error
	DeleteByClient(clientId int64) error
	DeleteAll() error
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

func (r *RefreshToken) Init() error {
	if _, err := r.db.Exec(`
	CREATE TABLE IF NOT EXISTS refresh_tokens (
	    id INTEGER PRIMARY KEY AUTOINCREMENT,
	    token TEXT NOT NULL,
	    client_id INTEGER NOT NULL,
	    user_id INTEGER NOT NULL,
		expire_time INTEGER NOT NULL,
		scope TEXT NOT NULL DEFAULT ''
	);`); err != nil {
		return err
	}
	// Migrate existing databases that predate the scope column (FIX F4).
	if err := r.ensureScopeColumn(); err != nil {
		return err
	}
	// create index if not exists
	rows, err := r.db.Query(`SELECT * FROM sqlite_master WHERE type = "index" AND tbl_name = "refresh_tokens" AND name = "idx_token";`)
	if err != nil {
		return err
	}
	if !rows.Next() {
		if _, err = r.db.Exec(`CREATE INDEX idx_token ON refresh_tokens(token);`); err != nil {
			return err
		}
	}
	if err := rows.Close(); err != nil {
		return err
	}
	rows, err = r.db.Query(`SELECT * FROM sqlite_master WHERE type = "index" AND tbl_name = "refresh_tokens" AND name = "idx_expire_time";`)
	if err != nil {
		return err
	}
	if !rows.Next() {
		if _, err = r.db.Exec(`CREATE INDEX idx_expire_time ON refresh_tokens(expire_time);`); err != nil {
			return err
		}
	}
	return rows.Close()
}

func (r *RefreshToken) Insert(token *RefreshToken) error {
	if err := r.cleanupExpiredIfNeeded(time.Now()); err != nil {
		return err
	}
	_, err := r.db.Exec("INSERT INTO refresh_tokens (token, client_id, user_id, expire_time, scope) VALUES (?, ?, ?, ?, ?);", hashToken(token.Token), token.ClientId, token.UserId, token.ExpireTime.Unix(), token.Scope)
	return err
}

func (r *RefreshToken) SelectByToken(token string) (refreshToken *RefreshToken, err error) {
	if err := r.cleanupExpiredIfNeeded(time.Now()); err != nil {
		return nil, err
	}
	rows, err := r.db.Query("SELECT * FROM refresh_tokens WHERE token = ?;", hashToken(token))
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

// ensureScopeColumn adds the scope column to a pre-existing refresh_tokens
// table so older databases migrate transparently (FIX F4).
func (r *RefreshToken) ensureScopeColumn() error {
	rows, err := r.db.Query("PRAGMA table_info(refresh_tokens);")
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var (
			cid       int
			name      string
			colType   string
			notNull   int
			dfltValue sql.NullString
			pk        int
		)
		if err := rows.Scan(&cid, &name, &colType, &notNull, &dfltValue, &pk); err != nil {
			return err
		}
		if name == "scope" {
			return nil
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	_, err = r.db.Exec("ALTER TABLE refresh_tokens ADD COLUMN scope TEXT NOT NULL DEFAULT '';")
	return err
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func (r *RefreshToken) DeleteById(id int64) error {
	if err := r.cleanupExpiredIfNeeded(time.Now()); err != nil {
		return err
	}
	_, err := r.db.Exec("DELETE FROM refresh_tokens WHERE id = ?;", id)
	return err
}

func (r *RefreshToken) DeleteByUserAndClient(userId, clientId int64) error {
	if err := r.cleanupExpiredIfNeeded(time.Now()); err != nil {
		return err
	}
	_, err := r.db.Exec("DELETE FROM refresh_tokens WHERE user_id = ? AND client_id = ?;", userId, clientId)
	return err
}

func (r *RefreshToken) DeleteByClient(clientId int64) error {
	if err := r.cleanupExpiredIfNeeded(time.Now()); err != nil {
		return err
	}
	_, err := r.db.Exec("DELETE FROM refresh_tokens WHERE client_id = ?;", clientId)
	return err
}

func (r *RefreshToken) DeleteAll() error {
	if err := r.cleanupExpiredIfNeeded(time.Now()); err != nil {
		return err
	}
	_, err := r.db.Exec("DELETE FROM refresh_tokens;")
	return err
}

func (r *RefreshToken) cleanupExpiredIfNeeded(now time.Time) error {
	r.cleanupMu.Lock()
	defer r.cleanupMu.Unlock()

	if now.Sub(r.lastCleanupAt) < refreshTokenCleanupInterval {
		return nil
	}
	if _, err := r.db.Exec("DELETE FROM refresh_tokens WHERE expire_time < ?;", now.Unix()); err != nil {
		return err
	}
	r.lastCleanupAt = now
	return nil
}
