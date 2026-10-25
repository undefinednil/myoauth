package dal

import (
	"database/sql"
	"testing"
	"time"

	_ "github.com/glebarez/go-sqlite"
)

// TestRefreshTokenScopeMigration ensures a database created before the scope
// column existed is migrated in place (FIX F4).
func TestRefreshTokenScopeMigration(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	if _, err := db.Exec(`
	CREATE TABLE refresh_tokens (
	    id INTEGER PRIMARY KEY AUTOINCREMENT,
	    token TEXT NOT NULL,
	    client_id INTEGER NOT NULL,
	    user_id INTEGER NOT NULL,
		expire_time INTEGER NOT NULL
	);`); err != nil {
		t.Fatalf("create legacy table: %v", err)
	}

	rt := &RefreshToken{db: db}
	if err := rt.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	exp := time.Now().Add(time.Hour)
	if err := rt.Insert(&RefreshToken{Token: "tok", ClientId: 1, UserId: 2, ExpireTime: &exp, Scope: "openid profile"}); err != nil {
		t.Fatalf("Insert after migration: %v", err)
	}
	got, err := rt.SelectByToken("tok")
	if err != nil {
		t.Fatalf("SelectByToken: %v", err)
	}
	if got == nil || got.Scope != "openid profile" {
		t.Fatalf("scope not persisted after migration: %+v", got)
	}
}
