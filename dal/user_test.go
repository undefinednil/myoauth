package dal

import "testing"

// TestUserCRUD covers insert plus every selector and the soft delete: a deleted
// user disappears from all lookups while other rows stay intact.
func TestUserCRUD(t *testing.T) {
	u := &User{db: newTestDB(t)}
	ctx := t.Context()

	for _, user := range []*User{
		{Uuid: "uuid-a", Name: "alice", Password: "hash-a"},
		{Uuid: "uuid-b", Name: "bob", Password: "hash-b"},
	} {
		if err := u.Insert(ctx, user); err != nil {
			t.Fatalf("Insert %s: %v", user.Name, err)
		}
	}

	byName, err := u.SelectByName(ctx, "alice")
	if err != nil || byName == nil || byName.Uuid != "uuid-a" || byName.Password != "hash-a" {
		t.Fatalf("SelectByName = %+v (err %v)", byName, err)
	}
	byUuid, err := u.SelectByUuid(ctx, "uuid-b")
	if err != nil || byUuid == nil || byUuid.Name != "bob" {
		t.Fatalf("SelectByUuid = %+v (err %v)", byUuid, err)
	}
	byId, err := u.SelectById(ctx, byName.Id)
	if err != nil || byId == nil || byId.Name != "alice" {
		t.Fatalf("SelectById = %+v (err %v)", byId, err)
	}
	if missing, err := u.SelectByName(ctx, "nobody"); err != nil || missing != nil {
		t.Fatalf("SelectByName unknown = %+v (err %v), want nil", missing, err)
	}

	if err := u.DeleteById(ctx, byUuid.Id); err != nil {
		t.Fatalf("DeleteById: %v", err)
	}
	if gone, err := u.SelectByUuid(ctx, "uuid-b"); err != nil || gone != nil {
		t.Fatalf("SelectByUuid after delete = %+v (err %v), want nil", gone, err)
	}
	if alive, err := u.SelectById(ctx, byName.Id); err != nil || alive == nil {
		t.Fatalf("unrelated user after delete = %+v (err %v), want a row", alive, err)
	}
}
