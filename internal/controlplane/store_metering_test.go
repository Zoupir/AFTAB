package controlplane

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/Zoupir/AFTAB/internal/metering"
)

// Requires modernc.org/sqlite from the AFTAB branch and is intended for its CI.
func TestSQLiteMeteringSnapshotSurvivesRestart(t *testing.T) {
	file := filepath.Join(t.TempDir(), "quota.sqlite")
	s, err := Open(file)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if e := s.EnsureMeteringSchema(ctx); e != nil {
		t.Fatal(e)
	}
	if e := s.EnsureMeteringSchema(ctx); e != nil {
		t.Fatal("migration must be idempotent", e)
	}
	a, token, e := s.Create(ctx, "person-phone", "android", 30, 1)
	if e != nil {
		t.Fatal(e)
	}
	if e := s.MarkProvisioned(ctx, a.ID); e != nil {
		t.Fatal(e)
	}
	samples := []metering.Counters{{Uplink: 100, Downlink: 150}, {Uplink: 100, Downlink: 150}, {Uplink: 120, Downlink: 160}}
	for _, p := range samples {
		if _, e := s.ApplySample(ctx, a.ID, p); e != nil {
			t.Fatal(e)
		}
	}
	active, e := s.ActiveAccounts(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if len(active) != 1 || active[0].UsedBytes != 280 {
		t.Fatalf("expected 280 bytes, got %+v", active)
	}
	if e := s.Close(); e != nil {
		t.Fatal(e)
	}
	s, e = Open(file)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if e := s.EnsureMeteringSchema(ctx); e != nil {
		t.Fatal(e)
	}
	got, e := s.ApplySample(ctx, a.ID, metering.Counters{Uplink: 2, Downlink: 7})
	if e != nil {
		t.Fatal(e)
	}
	if got.UsedBytes != 289 {
		t.Fatalf("reset must preserve cumulative bytes: %d", got.UsedBytes)
	}
	if _, e := s.LookupSubscription(ctx, token); e != nil {
		t.Fatal("valid account falsely revoked", e)
	}
	if e := s.MarkSuspended(ctx, a.ID, metering.SuspendQuota); e != nil {
		t.Fatal(e)
	}
	if _, e := s.LookupSubscription(ctx, token); !errors.Is(e, ErrInactive) {
		t.Fatal("revoked token still usable", e)
	}
	accounts, e := s.ActiveAccounts(ctx)
	if e != nil || len(accounts) != 0 {
		t.Fatal("suspended account still active")
	}
}
func TestSQLiteMeteringImportedAccountBaseline(t *testing.T) {
	s, e := Open(filepath.Join(t.TempDir(), "import.sqlite"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	ctx := context.Background()
	if e := s.EnsureMeteringSchema(ctx); e != nil {
		t.Fatal(e)
	}
	a, _, e := s.Create(ctx, "person-win", "windows", 1, 1)
	if e != nil {
		t.Fatal(e)
	}
	if e := s.MarkProvisioned(ctx, a.ID); e != nil {
		t.Fatal(e)
	}
	if e := s.SetUsage(ctx, a.ID, 200); e != nil {
		t.Fatal(e)
	}
	got, e := s.ApplySample(ctx, a.ID, metering.Counters{Uplink: 90, Downlink: 10})
	if e != nil || got.UsedBytes != 200 {
		t.Fatalf("imported account double charged: %+v %v", got, e)
	}
	got, e = s.ApplySample(ctx, a.ID, metering.Counters{Uplink: 95, Downlink: 20})
	if e != nil || got.UsedBytes != 215 {
		t.Fatalf("imported account later delta incorrect: %+v %v", got, e)
	}
	if !got.ExpiresAt.After(time.Now().UTC()) {
		t.Fatal("unexpected expiry")
	}
}
