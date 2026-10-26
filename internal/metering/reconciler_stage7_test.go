package metering

import (
	"context"
	"errors"
	"testing"
	"time"
)

type stage7Store struct {
	a    ManagedAccount
	fail bool
	mark int
}

func (s *stage7Store) ActiveAccounts(context.Context) ([]ManagedAccount, error) {
	if s.a.Disabled {
		return nil, nil
	}
	return []ManagedAccount{s.a}, nil
}
func (s *stage7Store) ApplySample(context.Context, string, Counters) (ManagedAccount, error) {
	return s.a, nil
}
func (s *stage7Store) MarkSuspended(_ context.Context, _ string, _ Decision) error {
	if s.fail {
		s.fail = false
		return errors.New("disk error")
	}
	s.mark++
	s.a.Disabled = true
	return nil
}

type stage7Engine struct {
	exists  bool
	uuid    string
	removes int
	err     error
}

func (e *stage7Engine) UserTraffic(context.Context, string) (Counters, error) { return Counters{}, nil }
func (e *stage7Engine) GetUserUUID(context.Context, string) (string, bool, error) {
	return e.uuid, e.exists, e.err
}
func (e *stage7Engine) RemoveUser(context.Context, string) error {
	e.removes++
	e.exists = false
	return nil
}
func TestStage7RetryAndCollision(t *testing.T) {
	const uuid = "872e14a6-1433-4753-b8cb-f194629e158a"
	now := time.Now().UTC()
	store := &stage7Store{a: ManagedAccount{ID: "1a5bc922-c418-4985-a4da-8ce4de68f725", UUID: uuid, UsedBytes: 3, QuotaBytes: 2, ExpiresAt: now.Add(time.Hour), Provisioned: true}, fail: true}
	engine := &stage7Engine{exists: true, uuid: uuid}
	rec := Reconciler{Store: store, Engine: engine}
	if err := rec.RunOnce(context.Background(), now); err == nil {
		t.Fatal("database failure hidden")
	}
	if engine.removes != 1 || store.mark != 0 {
		t.Fatal("removal and failure handling incorrect")
	}
	if err := rec.RunOnce(context.Background(), now); err != nil {
		t.Fatal("retry of DB-only suspension failed", err)
	}
	if engine.removes != 1 || store.mark != 1 {
		t.Fatal("double remove or lost suspension")
	}
	store.a.Disabled = false
	store.mark = 0
	engine.exists = true
	engine.uuid = "9b3df72f-17e6-4c4d-815a-7ce16305bfff"
	if err := rec.RunOnce(context.Background(), now); err == nil {
		t.Fatal("collision must be rejected")
	}
	if engine.removes != 1 || store.mark != 0 {
		t.Fatal("collision changed foreign identity")
	}
	engine.err = errors.New("timeout")
	if err := rec.RunOnce(context.Background(), now); err == nil {
		t.Fatal("identity timeout must be rejected")
	}
}
