package dal

import (
	"database/sql"
	"testing"

	_ "github.com/glebarez/go-sqlite"
)

func newProxySessionStore(t *testing.T) *ProxySession {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	p := &ProxySession{db: db}
	if err := p.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	return p
}

func TestProxySessionCRUD(t *testing.T) {
	p := newProxySessionStore(t)

	session := &ProxySession{
		Id:           "session-1",
		UserUuid:     "uuid-1",
		Name:         "alice",
		AccessToken:  "access-1",
		RefreshToken: "refresh-1",
		AccessExp:    100,
		Exp:          200,
		CreatedAt:    50,
	}
	if err := p.Insert(session); err != nil {
		t.Fatalf("Insert: %v", err)
	}

	got, err := p.SelectById("session-1")
	if err != nil {
		t.Fatalf("SelectById: %v", err)
	}
	if got == nil || got.UserUuid != "uuid-1" || got.AccessToken != "access-1" || got.RefreshToken != "refresh-1" {
		t.Fatalf("unexpected session: %+v", got)
	}

	session.AccessToken = "access-2"
	session.RefreshToken = "refresh-2"
	session.AccessExp = 150
	if err := p.UpdateById(session); err != nil {
		t.Fatalf("UpdateById: %v", err)
	}
	got, err = p.SelectById("session-1")
	if err != nil {
		t.Fatalf("SelectById after update: %v", err)
	}
	if got == nil || got.AccessToken != "access-2" || got.RefreshToken != "refresh-2" || got.AccessExp != 150 {
		t.Fatalf("update not persisted: %+v", got)
	}

	if err := p.DeleteById("session-1"); err != nil {
		t.Fatalf("DeleteById: %v", err)
	}
	got, err = p.SelectById("session-1")
	if err != nil {
		t.Fatalf("SelectById after delete: %v", err)
	}
	if got != nil {
		t.Fatalf("session still present after delete: %+v", got)
	}
}

func TestProxySessionMissingReturnsNil(t *testing.T) {
	p := newProxySessionStore(t)
	got, err := p.SelectById("does-not-exist")
	if err != nil {
		t.Fatalf("SelectById: %v", err)
	}
	if got != nil {
		t.Fatalf("want nil for missing session, got %+v", got)
	}
}

// DeleteExpired removes only rows whose absolute expiry is strictly in the past;
// a session expiring exactly at "now" is retained.
func TestProxySessionDeleteExpiredBoundary(t *testing.T) {
	p := newProxySessionStore(t)

	for _, s := range []*ProxySession{
		{Id: "past", UserUuid: "u", Name: "n", AccessToken: "a", RefreshToken: "r", AccessExp: 1, Exp: 99, CreatedAt: 1},
		{Id: "now", UserUuid: "u", Name: "n", AccessToken: "a", RefreshToken: "r", AccessExp: 1, Exp: 100, CreatedAt: 1},
		{Id: "future", UserUuid: "u", Name: "n", AccessToken: "a", RefreshToken: "r", AccessExp: 1, Exp: 101, CreatedAt: 1},
	} {
		if err := p.Insert(s); err != nil {
			t.Fatalf("Insert %s: %v", s.Id, err)
		}
	}

	if err := p.DeleteExpired(100); err != nil {
		t.Fatalf("DeleteExpired: %v", err)
	}

	for _, tc := range []struct {
		id   string
		want bool
	}{
		{"past", false},
		{"now", true},
		{"future", true},
	} {
		got, err := p.SelectById(tc.id)
		if err != nil {
			t.Fatalf("SelectById %s: %v", tc.id, err)
		}
		if (got != nil) != tc.want {
			t.Fatalf("session %s present=%v, want %v", tc.id, got != nil, tc.want)
		}
	}
}
