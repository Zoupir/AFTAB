package provisioning

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type memStore struct {
	accounts  []ManagedAccount
	suspended map[string]Reason
	fail      bool
}

func (s *memStore) ManagedAccounts(context.Context) ([]ManagedAccount, error) { return s.accounts, nil }
func (s *memStore) SuspendAccount(_ context.Context, id string, reason Reason) error {
	if s.fail {
		return errors.New("db outage")
	}
	if s.suspended == nil {
		s.suspended = map[string]Reason{}
	}
	s.suspended[id] = reason
	return nil
}

type memRuntime struct {
	users                          map[string]string
	failAdd, failRemove, failQuery bool
	added, removed                 int
}

func (e *memRuntime) GetUserUUID(_ context.Context, id string) (string, bool, error) {
	if e.failQuery {
		return "", false, errors.New("rpc timeout")
	}
	v, ok := e.users[id]
	return v, ok, nil
}
func (e *memRuntime) AddUser(_ context.Context, id, uuid string) error {
	if e.failAdd {
		return errors.New("rpc failed")
	}
	if e.users == nil {
		e.users = map[string]string{}
	}
	e.users[id] = uuid
	e.added++
	return nil
}
func (e *memRuntime) RemoveUser(_ context.Context, id string) error {
	if e.failRemove {
		return errors.New("rpc failed")
	}
	delete(e.users, id)
	e.removed++
	return nil
}
func TestRestoreAfterRestartAndIdempotence(t *testing.T) {
	now := time.Date(2026, 10, 26, 10, 0, 0, 0, time.UTC)
	db := &memStore{accounts: []ManagedAccount{
		{ID: "valid", UUID: "uuid-valid", QuotaBytes: 1000, UsedBytes: 100, ExpiresAt: now.Add(time.Hour), Provisioned: true},
		{ID: "expired", UUID: "uuid-expired", QuotaBytes: 100, UsedBytes: 5, ExpiresAt: now.Add(-time.Second), Provisioned: true},
		{ID: "exhausted", UUID: "uuid-exhausted", QuotaBytes: 100, UsedBytes: 100, ExpiresAt: now.Add(time.Hour), Provisioned: true},
		{ID: "disabled", UUID: "uuid-disabled", QuotaBytes: 100, ExpiresAt: now.Add(time.Hour), Disabled: true},
		{ID: "pending", UUID: "uuid-pending", QuotaBytes: 100, ExpiresAt: now.Add(time.Hour)},
	}}
	eng := &memRuntime{users: map[string]string{"expired": "uuid-expired", "pending": "uuid-pending"}}
	rec := Reconciler{Store: db, Engine: eng}
	got, e := rec.RunOnce(context.Background(), now)
	if e != nil {
		t.Fatal(e)
	}
	if got.Restored != 1 || got.Suspended != 2 || got.Removed != 2 || got.Skipped != 2 || eng.users["valid"] != "uuid-valid" || eng.users["pending"] != "" {
		t.Fatalf("recovery failed result=%+v users=%v", got, eng.users)
	}
	if db.suspended["expired"] != Expired || db.suspended["exhausted"] != Quota {
		t.Fatal(db.suspended)
	}
	// Simulate committed DB state after successful suspension.
	db.accounts[1].Disabled = true
	db.accounts[1].Provisioned = false
	db.accounts[2].Disabled = true
	db.accounts[2].Provisioned = false
	got, e = rec.RunOnce(context.Background(), now)
	if e != nil || got.Restored != 0 || got.Suspended != 0 || eng.added != 1 || eng.removed != 2 {
		t.Fatalf("repeated reconciliation mutated state: %+v %v", got, e)
	}
}
func TestRejectIdentityCollision(t *testing.T) {
	now := time.Now().UTC()
	db := &memStore{accounts: []ManagedAccount{{ID: "one", UUID: "expected", Provisioned: true, ExpiresAt: now.Add(time.Hour)}}}
	eng := &memRuntime{users: map[string]string{"one": "different"}}
	got, e := (Reconciler{db, eng}).RunOnce(context.Background(), now)
	if e == nil || !strings.Contains(e.Error(), "identity collision") || got.Failed != 1 || eng.added != 0 || eng.removed != 0 {
		t.Fatalf("collision was changed: %+v %v", got, e)
	}
}
func TestFailClosedOnRemoveAndPersistErrors(t *testing.T) {
	now := time.Now().UTC()
	db := &memStore{accounts: []ManagedAccount{{ID: "expired", UUID: "old", Provisioned: true, ExpiresAt: now.Add(-time.Hour)}}}
	eng := &memRuntime{users: map[string]string{"expired": "old"}, failRemove: true}
	result, e := (Reconciler{db, eng}).RunOnce(context.Background(), now)
	if e == nil || result.Suspended != 0 || len(db.suspended) != 0 {
		t.Fatal("reported revoked when removal failed")
	}
	eng.failRemove = false
	db.fail = true
	result, e = (Reconciler{db, eng}).RunOnce(context.Background(), now)
	if e == nil || result.Suspended != 0 || len(db.suspended) != 0 {
		t.Fatal("reported suspended when DB failed")
	}
	db.fail = false
	result, e = (Reconciler{db, eng}).RunOnce(context.Background(), now)
	if e != nil || result.Suspended != 1 || db.suspended["expired"] != Expired {
		t.Fatalf("retry did not persist %v %+v", e, result)
	}
}
func TestNoResurrectionOnQueryFailure(t *testing.T) {
	now := time.Now().UTC()
	db := &memStore{accounts: []ManagedAccount{{ID: "one", UUID: "u", Provisioned: true, ExpiresAt: now.Add(time.Hour)}}}
	eng := &memRuntime{failQuery: true}
	result, e := (Reconciler{db, eng}).RunOnce(context.Background(), now)
	if e == nil || result.Restored > 0 || eng.added > 0 {
		t.Fatalf("unverified restore %+v %v", result, e)
	}
}
