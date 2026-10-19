package dal

import (
	"errors"
	"testing"

	_ "github.com/glebarez/go-sqlite"
)

func TestClientDuplicateInsertReturnsErrClientExists(t *testing.T) {
	c := &Client{db: newTestDB(t)}
	ctx := t.Context()

	if err := c.Insert(ctx, &Client{ClientId: "dup", Secret: "s", Redirects: "r", AccessTokenAge: 1, RefreshTokenAge: 2}); err != nil {
		t.Fatalf("first Insert: %v", err)
	}
	err := c.Insert(ctx, &Client{ClientId: "dup", Secret: "s2", Redirects: "r2", AccessTokenAge: 1, RefreshTokenAge: 2})
	if !errors.Is(err, ErrClientExists) {
		t.Fatalf("duplicate Insert error = %v, want ErrClientExists", err)
	}

	// A soft-deleted client releases its client_id (the unique index is partial).
	existing, err := c.SelectByClientId(ctx, "dup")
	if err != nil {
		t.Fatalf("SelectByClientId: %v", err)
	}
	if existing == nil {
		t.Fatal("client not found after insert")
	}
	if err := c.DeleteById(ctx, existing.Id); err != nil {
		t.Fatalf("DeleteById: %v", err)
	}
	if err := c.Insert(ctx, &Client{ClientId: "dup", Secret: "s3", Redirects: "r3", AccessTokenAge: 1, RefreshTokenAge: 2}); err != nil {
		t.Fatalf("Insert after soft delete: %v", err)
	}
}

func TestClientUpdateDuplicateReturnsErrClientExists(t *testing.T) {
	c := &Client{db: newTestDB(t)}
	ctx := t.Context()

	if err := c.Insert(ctx, &Client{ClientId: "one", Secret: "s", Redirects: "r", AccessTokenAge: 1, RefreshTokenAge: 2}); err != nil {
		t.Fatalf("Insert one: %v", err)
	}
	if err := c.Insert(ctx, &Client{ClientId: "two", Secret: "s", Redirects: "r", AccessTokenAge: 1, RefreshTokenAge: 2}); err != nil {
		t.Fatalf("Insert two: %v", err)
	}
	two, err := c.SelectByClientId(ctx, "two")
	if err != nil || two == nil {
		t.Fatalf("SelectByClientId two: %v %+v", err, two)
	}
	two.ClientId = "one"
	if err := c.UpdateById(ctx, two); !errors.Is(err, ErrClientExists) {
		t.Fatalf("duplicate UpdateById error = %v, want ErrClientExists", err)
	}
}

// SelectAll only returns live clients, and DeleteById is a soft delete: the row
// disappears from every selector but the client_id is released for reuse.
func TestClientSelectAllAndSoftDelete(t *testing.T) {
	c := &Client{db: newTestDB(t)}
	ctx := t.Context()

	for _, id := range []string{"list-a", "list-b", "list-c"} {
		if err := c.Insert(ctx, &Client{ClientId: id, Secret: "s", Redirects: "r", AccessTokenAge: 1, RefreshTokenAge: 2}); err != nil {
			t.Fatalf("Insert %s: %v", id, err)
		}
	}
	all, err := c.SelectAll(ctx)
	if err != nil {
		t.Fatalf("SelectAll: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("SelectAll returned %d clients, want 3", len(all))
	}

	victim, err := c.SelectByClientId(ctx, "list-b")
	if err != nil || victim == nil {
		t.Fatalf("SelectByClientId list-b: %v", err)
	}
	if err := c.DeleteById(ctx, victim.Id); err != nil {
		t.Fatalf("DeleteById: %v", err)
	}
	remaining, err := c.SelectAll(ctx)
	if err != nil {
		t.Fatalf("SelectAll after delete: %v", err)
	}
	if len(remaining) != 2 {
		t.Fatalf("SelectAll after delete returned %d clients, want 2", len(remaining))
	}
	for _, client := range remaining {
		if client.Id == victim.Id {
			t.Fatalf("soft-deleted client still returned by SelectAll: %+v", client)
		}
	}
	if gone, err := c.SelectById(ctx, victim.Id); err != nil || gone != nil {
		t.Fatalf("SelectById after delete = %+v (err %v), want nil", gone, err)
	}
}
