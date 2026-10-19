package dal

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	_ "github.com/glebarez/go-sqlite"
	"github.com/undefinednil/myoauth/util"
)

// latestSchemaVersion is the PRAGMA user_version the versioned migrations
// below bring the database up to.
const latestSchemaVersion = 2

// sqlitePragmas are passed through the driver's DSN so that every pooled
// connection gets them, not only the first one that happens to run a PRAGMA
// statement. The glebarez/go-sqlite driver runs each `_pragma` value as
// `PRAGMA <value>` when a connection is opened.
const sqlitePragmas = "_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)"

type Database struct {
	instance      *sql.DB
	Users         IUser
	RefreshTokens IRefreshToken
	Clients       IClient
	TokenStore    ITokenStore
	ProxySessions IProxySession
}

// sqliteDSN attaches the connection pragmas to the database path. The driver
// treats everything after the first '?' as query parameters (except for
// file: URIs), so the pragmas apply to every connection the pool opens,
// including ones created after startup.
func sqliteDSN(path string) string {
	if strings.Contains(path, "?") {
		return path + "&" + sqlitePragmas
	}
	return path + "?" + sqlitePragmas
}

func (d *Database) Init(ctx context.Context, conf *util.Configuration) error {
	dbPath := conf.DbPath
	_, statErr := os.Stat(dbPath)
	newFile := errors.Is(statErr, os.ErrNotExist)

	sqlite, err := sql.Open("sqlite", sqliteDSN(dbPath))
	if err != nil {
		return err
	}
	sqlite.SetMaxOpenConns(1)
	// WAL mode is a persistent property of the database file, so running it
	// once is enough. Foreign keys and the busy timeout are DSN pragmas.
	if _, err := sqlite.ExecContext(ctx, "PRAGMA journal_mode=WAL;"); err != nil {
		_ = sqlite.Close()
		return err
	}
	if newFile && dbPath != ":memory:" {
		// Best-effort: keep a freshly created database file private. The chmod
		// is intentionally non-fatal (it is a no-op-like operation on Windows)
		// and never breaks startup.
		if err := os.Chmod(dbPath, 0o600); err != nil {
			log.Printf("could not set 0600 permissions on database file %q: %v\n", dbPath, err)
		}
	}
	if err := migrate(ctx, sqlite); err != nil {
		_ = sqlite.Close()
		return err
	}
	// Startup prune of replay tombstones; during normal operation they are also
	// pruned opportunistically by RefreshToken.ConsumeByHash.
	if _, err := sqlite.ExecContext(ctx, "DELETE FROM used_refresh_tokens WHERE used_at < ?;", time.Now().Add(-usedRefreshTokenRetention).Unix()); err != nil {
		_ = sqlite.Close()
		return err
	}
	users := &User{db: sqlite}
	refreshTokens := &RefreshToken{db: sqlite}
	clients := &Client{db: sqlite}
	tokenStore := &TokenStore{db: sqlite}
	proxySessions := &ProxySession{db: sqlite}
	d.instance = sqlite
	d.Users = users
	d.RefreshTokens = refreshTokens
	d.Clients = clients
	d.TokenStore = tokenStore
	d.ProxySessions = proxySessions
	return nil
}

// Ping reports whether the underlying database is reachable. It is used by the
// handler health endpoint.
func (d *Database) Ping(ctx context.Context) error {
	return d.instance.PingContext(ctx)
}

// Close flushes the WAL back into the main database file (best effort) and
// closes the connection pool. A failed checkpoint is logged but never fails
// shutdown.
func (d *Database) Close() error {
	if d.instance == nil {
		return nil
	}
	if _, err := d.instance.Exec("PRAGMA wal_checkpoint(TRUNCATE);"); err != nil {
		log.Printf("wal checkpoint on shutdown failed (continuing): %v\n", err)
	}
	return d.instance.Close()
}

// migration is one versioned, idempotent schema change. The version is stored
// in PRAGMA user_version; a fresh database and a pre-versioning database
// (user_version 0 with tables already present) both run the same migrations.
type migration struct {
	version int
	apply   func(ctx context.Context, tx *sql.Tx) error
}

var migrations = []migration{
	{version: 1, apply: migrateBaseSchema},
	{version: 2, apply: migrateUsedRefreshTokens},
}

// migrate applies every migration newer than the database's current
// user_version. Each migration runs in its own transaction together with the
// user_version bump, so a failure can never leave a half-applied version.
func migrate(ctx context.Context, db *sql.DB) error {
	var current int
	if err := db.QueryRowContext(ctx, "PRAGMA user_version;").Scan(&current); err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}
	if current > latestSchemaVersion {
		return fmt.Errorf("database schema version %d is newer than the supported version %d", current, latestSchemaVersion)
	}
	for _, m := range migrations {
		if m.version <= current {
			continue
		}
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("begin migration %d: %w", m.version, err)
		}
		if err := m.apply(ctx, tx); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("migration %d: %w", m.version, err)
		}
		if _, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d;", m.version)); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("migration %d: set user_version: %w", m.version, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("migration %d: commit: %w", m.version, err)
		}
		current = m.version
	}
	return nil
}

func execAll(ctx context.Context, tx *sql.Tx, stmts ...string) error {
	for _, stmt := range stmts {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	return nil
}

// migrateBaseSchema creates every table and index of the original schema. The
// IF NOT EXISTS clauses make the migration a no-op for existing databases that
// predate versioning (user_version 0 with tables already present).
func migrateBaseSchema(ctx context.Context, tx *sql.Tx) error {
	if err := execAll(ctx, tx,
		`CREATE TABLE IF NOT EXISTS users (
		    id INTEGER PRIMARY KEY AUTOINCREMENT,
		    uuid TEXT NOT NULL UNIQUE,
		    name TEXT NOT NULL UNIQUE,
		    password TEXT NOT NULL,
			deleted INTEGER NOT NULL DEFAULT 0
		);`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_uuid ON users(uuid);`,
		`CREATE TABLE IF NOT EXISTS clients (
		    id INTEGER PRIMARY KEY AUTOINCREMENT,
		    client_id TEXT NOT NULL,
		    secret TEXT NOT NULL,
		    redirects TEXT NOT NULL,
		    access_token_age INTEGER NOT NULL,
		    refresh_token_age INTEGER NOT NULL,
			deleted INTEGER NOT NULL DEFAULT 0
		);`,
		`CREATE INDEX IF NOT EXISTS idx_client_id ON clients(client_id);`,
		// Hard error on purpose: a database that cannot enforce unique active
		// client ids (for example one with pre-existing duplicate rows) must be
		// fixed by the operator instead of silently allowing duplicates.
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_client_id_active ON clients(client_id) WHERE deleted = 0;`,
		`CREATE TABLE IF NOT EXISTS refresh_tokens (
		    id INTEGER PRIMARY KEY AUTOINCREMENT,
		    token TEXT NOT NULL,
		    client_id INTEGER NOT NULL,
		    user_id INTEGER NOT NULL,
			expire_time INTEGER NOT NULL,
			scope TEXT NOT NULL DEFAULT ''
		);`,
		`CREATE INDEX IF NOT EXISTS idx_token ON refresh_tokens(token);`,
		`CREATE INDEX IF NOT EXISTS idx_expire_time ON refresh_tokens(expire_time);`,
		`CREATE TABLE IF NOT EXISTS revoked_tokens (
		    jti TEXT PRIMARY KEY,
		    exp INTEGER NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS access_tokens (
		    jti TEXT PRIMARY KEY,
		    user_id INTEGER NOT NULL,
		    client_id INTEGER NOT NULL,
		    exp INTEGER NOT NULL
		);`,
		`CREATE INDEX IF NOT EXISTS idx_access_tokens_client ON access_tokens(client_id);`,
		`CREATE TABLE IF NOT EXISTS proxy_sessions (
		    id TEXT PRIMARY KEY,
		    user_uuid TEXT NOT NULL,
		    name TEXT NOT NULL,
		    access_token TEXT NOT NULL,
		    refresh_token TEXT NOT NULL,
		    access_exp INTEGER NOT NULL,
		    exp INTEGER NOT NULL,
		    created_at INTEGER NOT NULL
		);`,
		`CREATE INDEX IF NOT EXISTS idx_proxy_sessions_exp ON proxy_sessions(exp);`,
	); err != nil {
		return err
	}
	return ensureScopeColumn(ctx, tx)
}

// migrateUsedRefreshTokens adds the replay-detection tombstones for consumed
// refresh tokens.
func migrateUsedRefreshTokens(ctx context.Context, tx *sql.Tx) error {
	return execAll(ctx, tx,
		`CREATE TABLE IF NOT EXISTS used_refresh_tokens (
		    token_hash TEXT PRIMARY KEY,
		    user_id INTEGER NOT NULL,
		    client_id INTEGER NOT NULL,
		    used_at INTEGER NOT NULL
		);`,
		`CREATE INDEX IF NOT EXISTS idx_used_refresh_tokens_used_at ON used_refresh_tokens(used_at);`,
	)
}

// ensureScopeColumn adds the scope column to a pre-existing refresh_tokens
// table so older databases migrate transparently (FIX F4).
func ensureScopeColumn(ctx context.Context, tx *sql.Tx) error {
	rows, err := tx.QueryContext(ctx, "PRAGMA table_info(refresh_tokens);")
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
	_, err = tx.ExecContext(ctx, "ALTER TABLE refresh_tokens ADD COLUMN scope TEXT NOT NULL DEFAULT '';")
	return err
}
