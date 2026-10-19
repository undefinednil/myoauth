package dal

import (
	"database/sql"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	_ "github.com/glebarez/go-sqlite"
)

func newRefreshTokenStore(t *testing.T) *RefreshToken {
	t.Helper()
	return &RefreshToken{db: newTestDB(t)}
}

// openLegacyRefreshTokenDB opens a temporary database with a caller-supplied
// legacy schema and no migrations applied.
func openLegacyRefreshTokenDB(t *testing.T, schema string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(t.TempDir(), "legacy.db")))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec(schema); err != nil {
		t.Fatalf("create legacy schema: %v", err)
	}
	return db
}

// TestRefreshTokenScopeMigration ensures a database created before the scope
// column existed is migrated in place (FIX F4).
func TestRefreshTokenScopeMigration(t *testing.T) {
	db := openLegacyRefreshTokenDB(t, `
	CREATE TABLE refresh_tokens (
	    id INTEGER PRIMARY KEY AUTOINCREMENT,
	    token TEXT NOT NULL,
	    client_id INTEGER NOT NULL,
	    user_id INTEGER NOT NULL,
		expire_time INTEGER NOT NULL
	);`)
	if err := migrate(t.Context(), db); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	rt := &RefreshToken{db: db}
	exp := time.Now().Add(time.Hour)
	ctx := t.Context()
	if err := rt.Insert(ctx, &RefreshToken{Token: "tok", ClientId: 1, UserId: 2, ExpireTime: &exp, Scope: "openid profile"}); err != nil {
		t.Fatalf("Insert after migration: %v", err)
	}
	got, err := rt.SelectByToken(ctx, "tok")
	if err != nil {
		t.Fatalf("SelectByToken: %v", err)
	}
	if got == nil || got.Scope != "openid profile" {
		t.Fatalf("scope not persisted after migration: %+v", got)
	}
}

func TestRefreshTokenConsumeByHash(t *testing.T) {
	rt := newRefreshTokenStore(t)
	ctx := t.Context()
	exp := time.Now().Add(time.Hour)
	if err := rt.Insert(ctx, &RefreshToken{Token: "raw-token", ClientId: 7, UserId: 9, ExpireTime: &exp, Scope: "openid"}); err != nil {
		t.Fatalf("Insert: %v", err)
	}

	got, err := rt.ConsumeByHash(ctx, HashToken("raw-token"))
	if err != nil {
		t.Fatalf("ConsumeByHash: %v", err)
	}
	if got.ClientId != 7 || got.UserId != 9 || got.Scope != "openid" || got.ExpireTime == nil {
		t.Fatalf("unexpected consumed token: %+v", got)
	}
	// The active row is gone after a successful consume.
	active, err := rt.SelectByToken(ctx, "raw-token")
	if err != nil {
		t.Fatalf("SelectByToken after consume: %v", err)
	}
	if active != nil {
		t.Fatalf("token still active after consume: %+v", active)
	}
}

func TestRefreshTokenConsumeUnknownReturnsNotFound(t *testing.T) {
	rt := newRefreshTokenStore(t)
	if _, err := rt.ConsumeByHash(t.Context(), HashToken("never-issued")); !errors.Is(err, ErrTokenNotFound) {
		t.Fatalf("ConsumeByHash error = %v, want ErrTokenNotFound", err)
	}
}

func TestRefreshTokenConsumeReplay(t *testing.T) {
	rt := newRefreshTokenStore(t)
	ctx := t.Context()
	exp := time.Now().Add(time.Hour)
	if err := rt.Insert(ctx, &RefreshToken{Token: "replayed", ClientId: 3, UserId: 4, ExpireTime: &exp}); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	if _, err := rt.ConsumeByHash(ctx, HashToken("replayed")); err != nil {
		t.Fatalf("first consume: %v", err)
	}

	_, err := rt.ConsumeByHash(ctx, HashToken("replayed"))
	if !errors.Is(err, ErrTokenReused) {
		t.Fatalf("replay error = %v, want ErrTokenReused", err)
	}
	var reused *TokenReusedError
	if !errors.As(err, &reused) {
		t.Fatalf("replay error %v does not expose TokenReusedError", err)
	}
	if reused.UserId != 4 || reused.ClientId != 3 {
		t.Fatalf("replay error chain = user %d client %d, want user 4 client 3", reused.UserId, reused.ClientId)
	}
}

func TestRefreshTokenConsumeConcurrent(t *testing.T) {
	rt := newRefreshTokenStore(t)
	ctx := t.Context()
	exp := time.Now().Add(time.Hour)
	if err := rt.Insert(ctx, &RefreshToken{Token: "concurrent", ClientId: 1, UserId: 2, ExpireTime: &exp}); err != nil {
		t.Fatalf("Insert: %v", err)
	}

	const consumers = 8
	results := make(chan error, consumers)
	var wg sync.WaitGroup
	for i := 0; i < consumers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := rt.ConsumeByHash(ctx, HashToken("concurrent"))
			results <- err
		}()
	}
	wg.Wait()
	close(results)

	success, reused := 0, 0
	for err := range results {
		switch {
		case err == nil:
			success++
		case errors.Is(err, ErrTokenReused):
			reused++
		default:
			t.Fatalf("unexpected consume error: %v", err)
		}
	}
	if success != 1 || reused != consumers-1 {
		t.Fatalf("concurrent consume: %d successes, %d replays, want 1 and %d", success, reused, consumers-1)
	}
}

func TestRefreshTokenTombstonePruning(t *testing.T) {
	rt := newRefreshTokenStore(t)
	ctx := t.Context()
	exp := time.Now().Add(time.Hour)
	if err := rt.Insert(ctx, &RefreshToken{Token: "pruned", ClientId: 1, UserId: 2, ExpireTime: &exp}); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	if _, err := rt.ConsumeByHash(ctx, HashToken("pruned")); err != nil {
		t.Fatalf("consume: %v", err)
	}
	var count int
	if err := rt.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM used_refresh_tokens;").Scan(&count); err != nil {
		t.Fatalf("count tombstones: %v", err)
	}
	if count != 1 {
		t.Fatalf("tombstone count = %d, want 1", count)
	}

	// Advance the clock past the retention window; the next opportunistic
	// cleanup must prune the tombstone.
	if err := rt.cleanupExpiredIfNeeded(ctx, time.Now().Add(usedRefreshTokenRetention+time.Hour)); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if err := rt.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM used_refresh_tokens;").Scan(&count); err != nil {
		t.Fatalf("count tombstones after prune: %v", err)
	}
	if count != 0 {
		t.Fatalf("tombstone count after prune = %d, want 0", count)
	}
	// Once pruned, the token looks unknown again instead of reused.
	if _, err := rt.ConsumeByHash(ctx, HashToken("pruned")); !errors.Is(err, ErrTokenNotFound) {
		t.Fatalf("consume after prune error = %v, want ErrTokenNotFound", err)
	}
}

func TestRefreshTokenRevokeChain(t *testing.T) {
	rt := newRefreshTokenStore(t)
	ctx := t.Context()
	exp := time.Now().Add(time.Hour)
	for _, raw := range []string{"chain-a", "chain-b"} {
		if err := rt.Insert(ctx, &RefreshToken{Token: raw, ClientId: 5, UserId: 6, ExpireTime: &exp}); err != nil {
			t.Fatalf("Insert %s: %v", raw, err)
		}
	}
	if err := rt.DeleteByUserAndClient(ctx, 6, 5); err != nil {
		t.Fatalf("DeleteByUserAndClient: %v", err)
	}
	for _, raw := range []string{"chain-a", "chain-b"} {
		if _, err := rt.ConsumeByHash(ctx, HashToken(raw)); !errors.Is(err, ErrTokenNotFound) {
			t.Fatalf("token %s after revoke = %v, want ErrTokenNotFound", raw, err)
		}
	}
}

// The three delete variants each remove exactly the intended rows.
func TestRefreshTokenDeleteVariants(t *testing.T) {
	rt := newRefreshTokenStore(t)
	ctx := t.Context()
	exp := time.Now().Add(time.Hour)
	insert := func(raw string, clientId, userId int64) {
		t.Helper()
		if err := rt.Insert(ctx, &RefreshToken{Token: raw, ClientId: clientId, UserId: userId, ExpireTime: &exp}); err != nil {
			t.Fatalf("Insert %s: %v", raw, err)
		}
	}
	insert("drop-by-id", 1, 1)
	insert("drop-by-client", 2, 2)
	insert("drop-by-client-2", 2, 3)
	insert("keep-me", 3, 4)

	byId, err := rt.SelectByToken(ctx, "drop-by-id")
	if err != nil || byId == nil {
		t.Fatalf("SelectByToken drop-by-id: %v", err)
	}
	if err := rt.DeleteById(ctx, byId.Id); err != nil {
		t.Fatalf("DeleteById: %v", err)
	}
	if got, err := rt.SelectByToken(ctx, "drop-by-id"); err != nil || got != nil {
		t.Fatalf("token after DeleteById = %+v (err %v), want nil", got, err)
	}

	if err := rt.DeleteByClient(ctx, 2); err != nil {
		t.Fatalf("DeleteByClient: %v", err)
	}
	for _, raw := range []string{"drop-by-client", "drop-by-client-2"} {
		if got, err := rt.SelectByToken(ctx, raw); err != nil || got != nil {
			t.Fatalf("token %s after DeleteByClient = %+v (err %v), want nil", raw, got, err)
		}
	}
	if got, err := rt.SelectByToken(ctx, "keep-me"); err != nil || got == nil {
		t.Fatalf("unrelated token after DeleteByClient = %+v (err %v), want a row", got, err)
	}

	if err := rt.DeleteAll(ctx); err != nil {
		t.Fatalf("DeleteAll: %v", err)
	}
	if got, err := rt.SelectByToken(ctx, "keep-me"); err != nil || got != nil {
		t.Fatalf("token after DeleteAll = %+v (err %v), want nil", got, err)
	}
}
