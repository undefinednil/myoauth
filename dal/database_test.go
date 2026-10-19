package dal

import (
	"database/sql"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	_ "github.com/glebarez/go-sqlite"
	"github.com/undefinednil/myoauth/util"
)

// newTestDB opens a temporary file-backed database (so several connections see
// the same data) and migrates it to the latest schema version.
func newTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(t.TempDir(), "test.db")))
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	if err := migrate(t.Context(), db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

func assertUserVersion(t *testing.T, db *sql.DB, want int) {
	t.Helper()
	var got int
	if err := db.QueryRowContext(t.Context(), "PRAGMA user_version;").Scan(&got); err != nil {
		t.Fatalf("read user_version: %v", err)
	}
	if got != want {
		t.Fatalf("user_version = %d, want %d", got, want)
	}
}

func assertTableExists(t *testing.T, db *sql.DB, table string) {
	t.Helper()
	var count int
	if err := db.QueryRowContext(t.Context(),
		"SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?;", table).Scan(&count); err != nil {
		t.Fatalf("check table %q: %v", table, err)
	}
	if count != 1 {
		t.Fatalf("table %q does not exist", table)
	}
}

func refreshTokenColumns(t *testing.T, db *sql.DB) map[string]bool {
	t.Helper()
	rows, err := db.QueryContext(t.Context(), "PRAGMA table_info(refresh_tokens);")
	if err != nil {
		t.Fatalf("table_info: %v", err)
	}
	defer func() { _ = rows.Close() }()
	columns := make(map[string]bool)
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
			t.Fatalf("scan table_info: %v", err)
		}
		columns[name] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("table_info rows: %v", err)
	}
	return columns
}

func TestMigrateFreshDatabase(t *testing.T) {
	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(t.TempDir(), "fresh.db")))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	if err := migrate(t.Context(), db); err != nil {
		t.Fatalf("migrate fresh database: %v", err)
	}
	assertUserVersion(t, db, latestSchemaVersion)
	for _, table := range []string{"users", "clients", "refresh_tokens", "revoked_tokens", "access_tokens", "proxy_sessions", "used_refresh_tokens"} {
		assertTableExists(t, db, table)
	}
	if !refreshTokenColumns(t, db)["scope"] {
		t.Fatal("fresh refresh_tokens table is missing the scope column")
	}
	// Running the migrations again must be a clean no-op.
	if err := migrate(t.Context(), db); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
	assertUserVersion(t, db, latestSchemaVersion)
}

// TestMigrateExistingUnversionedDatabase models a database created by the
// pre-versioning code: user_version 0, tables already present, refresh_tokens
// without the scope column. The upgrade must reach the latest version without
// losing any data.
func TestMigrateExistingUnversionedDatabase(t *testing.T) {
	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(t.TempDir(), "legacy.db")))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	if _, err := db.Exec(`
	CREATE TABLE users (
	    id INTEGER PRIMARY KEY AUTOINCREMENT,
	    uuid TEXT NOT NULL UNIQUE,
	    name TEXT NOT NULL UNIQUE,
	    password TEXT NOT NULL,
		deleted INTEGER NOT NULL DEFAULT 0
	);
	CREATE TABLE clients (
	    id INTEGER PRIMARY KEY AUTOINCREMENT,
	    client_id TEXT NOT NULL,
	    secret TEXT NOT NULL,
	    redirects TEXT NOT NULL,
	    access_token_age INTEGER NOT NULL,
	    refresh_token_age INTEGER NOT NULL,
		deleted INTEGER NOT NULL DEFAULT 0
	);
	CREATE TABLE refresh_tokens (
	    id INTEGER PRIMARY KEY AUTOINCREMENT,
	    token TEXT NOT NULL,
	    client_id INTEGER NOT NULL,
	    user_id INTEGER NOT NULL,
		expire_time INTEGER NOT NULL
	);
	INSERT INTO users (uuid, name, password) VALUES ('uuid-1', 'alice', 'hash');
	INSERT INTO clients (client_id, secret, redirects, access_token_age, refresh_token_age) VALUES ('client-1', 'secret', 'https://rp.example', 3600, 7200);
	INSERT INTO refresh_tokens (token, client_id, user_id, expire_time) VALUES ('hash-1', 1, 1, 9999999999);
	`); err != nil {
		t.Fatalf("create legacy schema: %v", err)
	}

	if err := migrate(t.Context(), db); err != nil {
		t.Fatalf("migrate legacy database: %v", err)
	}
	assertUserVersion(t, db, latestSchemaVersion)
	if !refreshTokenColumns(t, db)["scope"] {
		t.Fatal("scope column was not added to the legacy refresh_tokens table")
	}
	assertTableExists(t, db, "used_refresh_tokens")

	var (
		uuid, name, password string
	)
	if err := db.QueryRowContext(t.Context(), "SELECT uuid, name, password FROM users WHERE id = 1;").Scan(&uuid, &name, &password); err != nil {
		t.Fatalf("legacy user lost: %v", err)
	}
	if uuid != "uuid-1" || name != "alice" || password != "hash" {
		t.Fatalf("legacy user changed: uuid=%q name=%q password=%q", uuid, name, password)
	}
	var token string
	if err := db.QueryRowContext(t.Context(), "SELECT token FROM refresh_tokens WHERE id = 1;").Scan(&token); err != nil {
		t.Fatalf("legacy refresh token lost: %v", err)
	}
	if token != "hash-1" {
		t.Fatalf("legacy refresh token changed: %q", token)
	}
	var clientId string
	if err := db.QueryRowContext(t.Context(), "SELECT client_id FROM clients WHERE id = 1;").Scan(&clientId); err != nil {
		t.Fatalf("legacy client lost: %v", err)
	}
	if clientId != "client-1" {
		t.Fatalf("legacy client changed: %q", clientId)
	}
	var indexCount int
	if err := db.QueryRowContext(t.Context(),
		"SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = 'idx_client_id_active';").Scan(&indexCount); err != nil {
		t.Fatalf("check unique index: %v", err)
	}
	if indexCount != 1 {
		t.Fatal("unique active client index was not created during migration")
	}
}

func TestMigrateRefusesNewerSchema(t *testing.T) {
	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(t.TempDir(), "newer.db")))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.Exec("PRAGMA user_version = 99;"); err != nil {
		t.Fatal(err)
	}
	if err := migrate(t.Context(), db); err == nil {
		t.Fatal("migrate must refuse a schema newer than the binary supports")
	}
}

// TestSQLitePragmasOnEveryConnection proves the DSN pragmas apply to every
// connection, not only to the first one a pool opens.
func TestSQLitePragmasOnEveryConnection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pragma.db")
	for i := 0; i < 2; i++ {
		db, err := sql.Open("sqlite", sqliteDSN(path))
		if err != nil {
			t.Fatal(err)
		}
		var foreignKeys, busyTimeout int
		if err := db.QueryRow("PRAGMA foreign_keys;").Scan(&foreignKeys); err != nil {
			t.Fatalf("connection %d: pragma foreign_keys: %v", i, err)
		}
		if err := db.QueryRow("PRAGMA busy_timeout;").Scan(&busyTimeout); err != nil {
			t.Fatalf("connection %d: pragma busy_timeout: %v", i, err)
		}
		_ = db.Close()
		if foreignKeys != 1 {
			t.Fatalf("connection %d: foreign_keys = %d, want 1", i, foreignKeys)
		}
		if busyTimeout != 5000 {
			t.Fatalf("connection %d: busy_timeout = %d, want 5000", i, busyTimeout)
		}
	}
}

func TestSQLiteForeignKeysEnforced(t *testing.T) {
	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(t.TempDir(), "fk.db")))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.Exec(`
	CREATE TABLE parents (id INTEGER PRIMARY KEY);
	CREATE TABLE children (id INTEGER PRIMARY KEY, parent_id INTEGER REFERENCES parents(id));
	`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO children (parent_id) VALUES (123);"); err == nil {
		t.Fatal("foreign key violation was not rejected")
	}
}

func TestDatabaseInitPingClose(t *testing.T) {
	conf := &util.Configuration{DbPath: filepath.Join(t.TempDir(), "init.db")}
	db := new(Database)
	if err := db.Init(t.Context(), conf); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := db.Ping(t.Context()); err != nil {
		t.Fatalf("Ping: %v", err)
	}
	var mode string
	if err := db.instance.QueryRow("PRAGMA journal_mode;").Scan(&mode); err != nil {
		t.Fatalf("journal_mode: %v", err)
	}
	if mode != "wal" {
		t.Fatalf("journal_mode = %q, want wal", mode)
	}
	info, err := os.Stat(conf.DbPath)
	if err != nil {
		t.Fatalf("stat db file: %v", err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("db file mode = %v, want 0600", info.Mode().Perm())
	}
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}
