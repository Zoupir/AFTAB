package metering

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// ManagedAccount is the subset of a durable user record needed for metering.
// The store maintains one record per unique Xray user UUID and Xray email.
type ManagedAccount struct {
	ID          string
	QuotaBytes  int64
	UsedBytes   int64
	ExpiresAt   time.Time
	Disabled    bool
	Provisioned bool
}

// Repository implements durable, atomic traffic delta accounting. ApplySample
// must update (last uplink, last downlink, used) in ONE database transaction.
// MarkSuspended is called only after the Xray RemoveUser RPC succeeds.
type Repository interface {
	ActiveAccounts(context.Context) ([]ManagedAccount, error)
	ApplySample(context.Context, string, Counters) (ManagedAccount, error)
	MarkSuspended(context.Context, string, Decision) error
}

// Engine is the agent, not the public control-plane API. Counters must be
// cumulative; the query MUST NOT reset counters (Xray reset=false).
type Engine interface {
	UserTraffic(context.Context, string) (Counters, error)
	RemoveUser(context.Context, string) error
	GetUserUUID(context.Context, string) (string, bool, error)
}

type Reconciler struct {
	Store  Repository
	Engine Engine
}

// RunOnce processes each account without altering unrelated inbounds/users.
// If an API call fails, it reports the failure and leaves the account eligible
// for retry at the next cycle. It never declares an account suspended when the
// Xray runtime has not confirmed removal.
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
			if e := r.suspend(ctx, a.ID, SuspendExpired); e != nil {
				failures = append(failures, fmt.Errorf("expire %s: %w", a.ID, e))
			}
			continue
		}
		if a.QuotaBytes > 0 && a.UsedBytes >= a.QuotaBytes {
			if e := r.suspend(ctx, a.ID, SuspendQuota); e != nil {
				failures = append(failures, fmt.Errorf("quota %s: %w", a.ID, e))
			}
			continue
		}
		counters, e := r.Engine.UserTraffic(ctx, a.ID)
		if e != nil {
			failures = append(failures, fmt.Errorf("sample %s: %w", a.ID, e))
			continue
		}
		fresh, e := r.Store.ApplySample(ctx, a.ID, counters)
		if e != nil {
			failures = append(failures, fmt.Errorf("account %s: %w", a.ID, e))
			continue
		}
		decision := Evaluate(Account{
			QuotaBytes:  fresh.QuotaBytes,
			UsedBytes:   fresh.UsedBytes,
			ExpiresAt:   fresh.ExpiresAt,
			Disabled:    fresh.Disabled,
			Provisioned: fresh.Provisioned,
		}, now)
		if decision == SuspendQuota || decision == SuspendExpired {
			if e := r.suspend(ctx, a.ID, decision); e != nil {
				failures = append(failures, fmt.Errorf("suspend %s: %w", a.ID, e))
			}
		}
	}
	return errors.Join(failures...)
}

func (r Reconciler) suspend(ctx context.Context, id string, reason Decision) error {
	if err := r.Engine.RemoveUser(ctx, id); err != nil {
		return fmt.Errorf("Xray removal not confirmed: %w", err)
	}
	_, stillPresent, err := r.Engine.GetUserUUID(ctx, id)
	if err != nil || stillPresent {
		return fmt.Errorf("Xray removal verification failed for %s: stillPresent=%v, err=%v", id, stillPresent, err)
	}
	if err := r.Store.MarkSuspended(ctx, id, reason); err != nil {
		return fmt.Errorf("Xray removed user but database update failed; requires reconciliation: %w", err)
	}
	return nil
}

// Serve runs a single synchronous poll at a time, plus a prompt first pass.
// Cancelling the context stops all future sampling. This is intentionally a
// caller-managed job; merely importing the package starts no goroutine.
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
		case t := <-ticker.C:
			if err := r.RunOnce(ctx, t.UTC()); err != nil && onError != nil {
				onError(err)
			}
		}
	}
}
