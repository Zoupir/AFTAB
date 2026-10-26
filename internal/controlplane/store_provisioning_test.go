package controlplane

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/Zoupir/AFTAB/internal/provisioning"
)

func TestManagedAccountsAreLimitedToAFTABDatabase(t *testing.T) {
	s, e := Open(filepath.Join(t.TempDir(), "recovery.sqlite"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	ctx := context.Background()
	if e := s.EnsureMeteringSchema(ctx); e != nil {
		t.Fatal(e)
	}
	a, _, e := s.Create(ctx, "recovery-phone", "android", 7, 3)
	if e != nil {
		t.Fatal(e)
	}
	if e := s.MarkProvisioned(ctx, a.ID); e != nil {
		t.Fatal(e)
	}
	pending, _, e := s.Create(ctx, "recovery-pending", "windows", 1, 1)
	if e != nil {
		t.Fatal(e)
	}
	users, e := s.ManagedAccounts(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if len(users) != 2 {
		t.Fatalf("expected 2 managed users, got %d", len(users))
	}
	seen := map[string]provisioning.ManagedAccount{}
	for _, u := range users {
		seen[u.ID] = u
	}
	if seen[a.ID].UUID != a.UUID || !seen[a.ID].Provisioned || seen[a.ID].Disabled {
		t.Fatal("active account was not recovered")
	}
	if seen[pending.ID].Provisioned {
		t.Fatal("pending account must remain pending")
	}
	if !seen[a.ID].ExpiresAt.After(time.Now().UTC()) {
		t.Fatal("unexpected expiry")
	}
	if e := s.SuspendAccount(ctx, a.ID, provisioning.Expired); e != nil {
		t.Fatal(e)
	}
	got, e := s.Get(ctx, a.ID)
	if e != nil {
		t.Fatal(e)
	}
	if !got.Disabled || got.Provisioned {
		t.Fatal("suspension not persisted")
	}
}
