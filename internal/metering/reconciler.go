package metering

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// ManagedAccount is a durable AFTAB-owned account; no shared 3x-ui users are scanned.
type ManagedAccount struct {
	ID          string
	UUID        string
	QuotaBytes  int64
	UsedBytes   int64
	ExpiresAt   time.Time
	Disabled    bool
	Provisioned bool
}

type Repository interface {
	ActiveAccounts(context.Context) ([]ManagedAccount, error)
	ApplySample(context.Context, string, Counters) (ManagedAccount, error)
	MarkSuspended(context.Context, string, Decision) error
}
type Engine interface {
	UserTraffic(context.Context, string) (Counters, error)
	RemoveUser(context.Context, string) error
	GetUserUUID(context.Context, string) (string, bool, error)
}
type Reconciler struct {
	Store  Repository
	Engine Engine
}

func (r Reconciler) RunOnce(ctx context.Context, now time.Time) error {
	if r.Store == nil || r.Engine == nil {
		return errors.New("metering needs a persistent store and an Xray agent")
	}
	accounts, err := r.Store.ActiveAccounts(ctx)
	if err != nil {
		return fmt.Errorf("list active accounts: %w", err)
	}
	var failures []error
	for _, a := range accounts {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !a.Provisioned || a.Disabled {
			continue
		}
		if !now.Before(a.ExpiresAt) {
			if err := r.suspend(ctx, a.ID, a.UUID, SuspendExpired); err != nil {
				failures = append(failures, fmt.Errorf("expire %s: %w", a.ID, err))
			}
			continue
		}
		if a.QuotaBytes > 0 && a.UsedBytes >= a.QuotaBytes {
			if err := r.suspend(ctx, a.ID, a.UUID, SuspendQuota); err != nil {
				failures = append(failures, fmt.Errorf("quota %s: %w", a.ID, err))
			}
			continue
		}
		sample, err := r.Engine.UserTraffic(ctx, a.ID)
		if err != nil {
			failures = append(failures, fmt.Errorf("sample %s: %w", a.ID, err))
			continue
		}
		fresh, err := r.Store.ApplySample(ctx, a.ID, sample)
		if err != nil {
			failures = append(failures, fmt.Errorf("account %s: %w", a.ID, err))
			continue
		}
		decision := Evaluate(Account{
			QuotaBytes: fresh.QuotaBytes, UsedBytes: fresh.UsedBytes, ExpiresAt: fresh.ExpiresAt,
			Disabled: fresh.Disabled, Provisioned: fresh.Provisioned,
		}, now)
		if decision == SuspendQuota || decision == SuspendExpired {
			if err := r.suspend(ctx, a.ID, a.UUID, decision); err != nil {
				failures = append(failures, fmt.Errorf("suspend %s: %w", a.ID, err))
			}
		}
	}
	return errors.Join(failures...)
}

// suspend is retry-safe if Xray removal succeeded but the DB commit failed.
// A missing peer is ALREADY disconnected, so commit the durable suspension.
// A query error must NEVER be treated as a missing peer.
func (r Reconciler) suspend(ctx context.Context, id, expectedUUID string, reason Decision) error {
	got, exists, err := r.Engine.GetUserUUID(ctx, id)
	if err != nil {
		return fmt.Errorf("Xray identity precheck failed: %w", err)
	}
	if exists && expectedUUID != "" && got != expectedUUID {
		return fmt.Errorf("Xray identity collision for %s: refusing removal", id)
	}
	// For AFTAB-managed accounts the DB includes UUID. Absence is already a
	// verified revoked runtime state. Retrying a failed DB commit must not
	// require a second Xray RemoveUser RPC.
	if !exists && expectedUUID != "" {
		return r.persistSuspended(ctx, id, reason)
	}
	// Legacy mock accounts with no UUID must preserve the older API contract;
	// production DB must always provide the account's UUID.
	if err := r.Engine.RemoveUser(ctx, id); err != nil {
		return fmt.Errorf("Xray removal not confirmed: %w", err)
	}
	_, stillPresent, err := r.Engine.GetUserUUID(ctx, id)
	if err != nil || stillPresent {
		return fmt.Errorf("Xray removal verification failed for %s: stillPresent=%v, err=%v", id, stillPresent, err)
	}
	return r.persistSuspended(ctx, id, reason)
}
func (r Reconciler) persistSuspended(ctx context.Context, id string, reason Decision) error {
	if err := r.Store.MarkSuspended(ctx, id, reason); err != nil {
		return fmt.Errorf("Xray peer absent but DB update failed; retry reconciliation: %w", err)
	}
	return nil
}
func (r Reconciler) Serve(ctx context.Context, interval time.Duration, onError func(error)) error {
	if interval < time.Second {
		return errors.New("sampling interval must be at least one second")
	}
	if err := r.RunOnce(ctx, time.Now().UTC()); err != nil && onError != nil {
		onError(err)
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case now := <-ticker.C:
			if err := r.RunOnce(ctx, now.UTC()); err != nil && onError != nil {
				onError(err)
			}
		}
	}
}
