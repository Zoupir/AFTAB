package metering

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

type testStore struct {
	mu       sync.Mutex
	users    map[string]ManagedAccount
	last     map[string]Counters
	reasons  map[string]Decision
	failMark bool
}

func (s *testStore) ActiveAccounts(_ context.Context) ([]ManagedAccount, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []ManagedAccount
	for _, u := range s.users {
		if !u.Disabled && u.Provisioned {
			out = append(out, u)
		}
	}
	return out, nil
}
func (s *testStore) ApplySample(_ context.Context, id string, current Counters) (ManagedAccount, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[id]
	if !ok {
		return u, errors.New("not found")
	}
	delta, e := Delta(s.last[id], current)
	if e != nil {
		return u, e
	}
	u.UsedBytes, e = Accumulate(u.UsedBytes, delta)
	if e != nil {
		return u, e
	}
	s.last[id] = current
	s.users[id] = u
	return u, nil
}
func (s *testStore) MarkSuspended(_ context.Context, id string, reason Decision) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failMark {
		return errors.New("simulated database outage")
	}
	u := s.users[id]
	u.Disabled = true
	u.Provisioned = false
	s.users[id] = u
	s.reasons[id] = reason
	return nil
}

type testEngine struct {
	samples      map[string]Counters
	failed       bool
	removals     []string
	stillPresent bool
}

func (e *testEngine) UserTraffic(_ context.Context, id string) (Counters, error) {
	return e.samples[id], nil
}
func (e *testEngine) GetUserUUID(_ context.Context, id string) (string, bool, error) {
	return "", e.stillPresent, nil
}
func (e *testEngine) RemoveUser(_ context.Context, id string) error {
	if e.failed {
		return errors.New("simulated xray API error")
	}
	e.removals = append(e.removals, id)
	return nil
}
func TestMeteringCountersAndQuotaEnforcement(t *testing.T) {
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	store := &testStore{users: map[string]ManagedAccount{"friend": {ID: "friend", QuotaBytes: 300, ExpiresAt: now.Add(time.Hour), Provisioned: true}}, last: map[string]Counters{}, reasons: map[string]Decision{}}
	engine := &testEngine{samples: map[string]Counters{"friend": {Uplink: 120, Downlink: 70}}}
	r := Reconciler{Store: store, Engine: engine}
	ctx := context.Background()
	if e := r.RunOnce(ctx, now); e != nil {
		t.Fatal(e)
	}
	if store.users["friend"].UsedBytes != 190 {
		t.Fatal("first sample not recorded")
	}
	if e := r.RunOnce(ctx, now); e != nil {
		t.Fatal(e)
	}
	if store.users["friend"].UsedBytes != 190 {
		t.Fatal("duplicate polling counted the same bytes")
	}
	engine.samples["friend"] = Counters{Uplink: 140, Downlink: 110}
	if e := r.RunOnce(ctx, now); e != nil {
		t.Fatal(e)
	}
	if store.users["friend"].UsedBytes != 250 {
		t.Fatal("delta not recorded")
	}
	engine.samples["friend"] = Counters{Uplink: 10, Downlink: 55} // Xray counters reset after restart.
	if e := r.RunOnce(ctx, now); e != nil {
		t.Fatal(e)
	}
	if store.users["friend"].UsedBytes != 315 {
		t.Fatalf("wrong total %d", store.users["friend"].UsedBytes)
	}
	if !store.users["friend"].Disabled || store.reasons["friend"] != SuspendQuota || len(engine.removals) != 1 {
		t.Fatal("quota did not revoke user")
	}
}
func TestNoFalseSuccessOnFailedXrayRemovalAndExpiry(t *testing.T) {
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	store := &testStore{users: map[string]ManagedAccount{"expired": {ID: "expired", QuotaBytes: 500, ExpiresAt: now.Add(-time.Second), Provisioned: true}}, last: map[string]Counters{}, reasons: map[string]Decision{}}
	engine := &testEngine{samples: map[string]Counters{}, failed: true}
	r := Reconciler{Store: store, Engine: engine}
	if err := r.RunOnce(context.Background(), now); err == nil {
		t.Fatal("missing failure from failed Xray API")
	}
	if store.users["expired"].Disabled {
		t.Fatal("failed Xray deletion falsely reported as suspended")
	}
	engine.failed = false
	if e := r.RunOnce(context.Background(), now); e != nil {
		t.Fatal(e)
	}
	if !store.users["expired"].Disabled || store.reasons["expired"] != SuspendExpired {
		t.Fatal("expired user not suspended")
	}
	if e := r.RunOnce(context.Background(), now); e != nil {
		t.Fatal(e)
	}
	if got := len(engine.removals); got != 1 {
		t.Fatalf("redundant revocations: %d", got)
	}
}
func TestAtomicFailureCannotMarkSuspended(t *testing.T) {
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	store := &testStore{users: map[string]ManagedAccount{"u": {ID: "u", QuotaBytes: 1, UsedBytes: 2, ExpiresAt: now.Add(time.Minute), Provisioned: true}}, last: map[string]Counters{}, reasons: map[string]Decision{}, failMark: true}
	engine := &testEngine{samples: map[string]Counters{}}
	r := Reconciler{Store: store, Engine: engine}
	err := r.RunOnce(context.Background(), now)
	if err == nil || !store.users["u"].Provisioned {
		t.Fatal("must report uncertain DB commit after engine deletion")
	}
	if got := fmt.Sprint(err); got == "" {
		t.Fatal("empty error")
	}
}

func TestDeletionSuccessWithoutVerificationCannotMarkSuspended(t *testing.T) {
	now := time.Now().UTC()
	store := &testStore{users: map[string]ManagedAccount{"test": {ID: "test", Provisioned: true, UsedBytes: 101, QuotaBytes: 100, ExpiresAt: now.Add(time.Hour)}}, last: map[string]Counters{}, reasons: map[string]Decision{}}
	engine := &testEngine{stillPresent: true}
	err := (Reconciler{Store: store, Engine: engine}).RunOnce(context.Background(), now)
	if err == nil || store.users["test"].Disabled || len(store.reasons) != 0 {
		t.Fatalf("accepted unverified removal: %v", err)
	}
	engine.stillPresent = false
	err = (Reconciler{Store: store, Engine: engine}).RunOnce(context.Background(), now)
	if err != nil || !store.users["test"].Disabled {
		t.Fatalf("retry should succeed: %v", err)
	}
}
