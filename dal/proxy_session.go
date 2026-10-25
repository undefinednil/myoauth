package dal

import (
	"database/sql"
	"errors"
	"sync"
	"time"
)

const proxySessionCleanupInterval = 1 * time.Minute

type IProxySession interface {
	Init() error
	Insert(session *ProxySession) error
	SelectById(id string) (*ProxySession, error)
	UpdateById(session *ProxySession) error
	DeleteById(id string) error
	DeleteExpired(now int64) error
}

// ProxySession is a server-side forward-auth session. The browser cookie only
// carries the opaque high-entropy id; the OAuth tokens stay in SQLite so the
// auth subrequest can rotate them without needing to propagate Set-Cookie
// through nginx's auth_request (FIX A).
type ProxySession struct {
	db            *sql.DB
	Id            string
	UserUuid      string
	Name          string
	AccessToken   string
	RefreshToken  string
	AccessExp     int64
	Exp           int64
	CreatedAt     int64
	cleanupMu     sync.Mutex
	lastCleanupAt time.Time
}

func (p *ProxySession) Init() error {
	if _, err := p.db.Exec(`
	CREATE TABLE IF NOT EXISTS proxy_sessions (
	    id TEXT PRIMARY KEY,
	    user_uuid TEXT NOT NULL,
	    name TEXT NOT NULL,
	    access_token TEXT NOT NULL,
	    refresh_token TEXT NOT NULL,
	    access_exp INTEGER NOT NULL,
	    exp INTEGER NOT NULL,
	    created_at INTEGER NOT NULL
	);`); err != nil {
		return err
	}
	if _, err := p.db.Exec(`CREATE INDEX IF NOT EXISTS idx_proxy_sessions_exp ON proxy_sessions(exp);`); err != nil {
		return err
	}
	return nil
}

func (p *ProxySession) Insert(session *ProxySession) error {
	if err := p.cleanupExpiredIfNeeded(time.Now()); err != nil {
		return err
	}
	_, err := p.db.Exec(
		"INSERT INTO proxy_sessions (id, user_uuid, name, access_token, refresh_token, access_exp, exp, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?);",
		session.Id, session.UserUuid, session.Name, session.AccessToken, session.RefreshToken,
		session.AccessExp, session.Exp, session.CreatedAt)
	return err
}

func (p *ProxySession) SelectById(id string) (session *ProxySession, err error) {
	if err := p.cleanupExpiredIfNeeded(time.Now()); err != nil {
		return nil, err
	}
	rows, err := p.db.Query(
		"SELECT id, user_uuid, name, access_token, refresh_token, access_exp, exp, created_at FROM proxy_sessions WHERE id = ?;", id)
	if err != nil {
		return nil, err
	}
	defer func() {
		err = errors.Join(err, rows.Close())
	}()
	session = new(ProxySession)
	if rows.Next() {
		if err := rows.Scan(
			&session.Id, &session.UserUuid, &session.Name, &session.AccessToken, &session.RefreshToken,
			&session.AccessExp, &session.Exp, &session.CreatedAt); err != nil {
			return nil, err
		}
	} else {
		return nil, nil
	}
	return session, err
}

func (p *ProxySession) UpdateById(session *ProxySession) error {
	if err := p.cleanupExpiredIfNeeded(time.Now()); err != nil {
		return err
	}
	_, err := p.db.Exec(
		"UPDATE proxy_sessions SET user_uuid = ?, name = ?, access_token = ?, refresh_token = ?, access_exp = ?, exp = ? WHERE id = ?;",
		session.UserUuid, session.Name, session.AccessToken, session.RefreshToken,
		session.AccessExp, session.Exp, session.Id)
	return err
}

func (p *ProxySession) DeleteById(id string) error {
	if err := p.cleanupExpiredIfNeeded(time.Now()); err != nil {
		return err
	}
	_, err := p.db.Exec("DELETE FROM proxy_sessions WHERE id = ?;", id)
	return err
}

// DeleteExpired removes every session whose absolute expiry has passed.
func (p *ProxySession) DeleteExpired(now int64) error {
	_, err := p.db.Exec("DELETE FROM proxy_sessions WHERE exp < ?;", now)
	return err
}

func (p *ProxySession) cleanupExpiredIfNeeded(now time.Time) error {
	p.cleanupMu.Lock()
	defer p.cleanupMu.Unlock()

	if now.Sub(p.lastCleanupAt) < proxySessionCleanupInterval {
		return nil
	}
	if err := p.DeleteExpired(now.Unix()); err != nil {
		return err
	}
	p.lastCleanupAt = now
	return nil
}
