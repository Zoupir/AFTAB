// Package provisioning reconciles durable AFTAB identities with a dedicated
// Xray inbound after a restart. It never changes unrelated inbounds or users.
package provisioning

import (
	"context"
	"errors"
	"fmt"
	"time"
)

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
	ManagedAccounts(context.Context) ([]ManagedAccount, error)
	SuspendAccount(context.Context, string, Reason) error
}

type Runtime interface {
	GetUserUUID(context.Context, string) (uuid string, found bool, err error)
	AddUser(context.Context, string, string) error
	RemoveUser(context.Context, string) error
}

type Reason string

const (
	Expired Reason = "suspend_expired"
	Quota   Reason = "suspend_quota"
)

type Result struct {
	Restored, Suspended, Removed, AlreadyOK, Skipped, Failed int
}

type Reconciler struct {
	Store  Repository
	Engine Runtime
}

// RunOnce runs only over AFTAB-known account IDs. A missing runtime peer with
// provisioned=true and a still-valid account is restored. Expired, over-quota,
// disabled or not-yet-provisioned users cannot be resurrected by this code.
// If an existing peer has the wrong UUID, the code fails closed without
// silently replacing that identity. Reconcile at startup and periodically.
func (r Reconciler) RunOnce(ctx context.Context, now time.Time) (Result, error) {
	var result Result
	if r.Store == nil || r.Engine == nil {
		return result, errors.New("provisioning requires store and agent")
	}
	accounts, err := r.Store.ManagedAccounts(ctx)
	if err != nil {
		return result, fmt.Errorf("list managed accounts: %w", err)
	}
	var failures []error
	for _, a := range accounts {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		validID := a.ID != "" && a.UUID != "" && a.QuotaBytes >= 0 && a.UsedBytes >= 0 && !a.ExpiresAt.IsZero()
		if !validID {
			result.Failed++
			failures = append(failures, fmt.Errorf("invalid managed identity %q", a.ID))
			continue
		}

		reason := Reason("")
		if !now.Before(a.ExpiresAt) {
			reason = Expired
		} else if a.QuotaBytes > 0 && a.UsedBytes >= a.QuotaBytes {
			reason = Quota
		}
		shouldExist := a.Provisioned && !a.Disabled && reason == ""
		got, found, e := r.Engine.GetUserUUID(ctx, a.ID)
		if e != nil {
			result.Failed++
			failures = append(failures, fmt.Errorf("check %s: %w", a.ID, e))
			continue
		}
		if found && got != a.UUID {
			result.Failed++
			failures = append(failures, fmt.Errorf("identity collision for account %s: Xray UUID differs", a.ID))
			continue
		}
		if shouldExist {
			if found {
				result.AlreadyOK++
				continue
			}
			if e = r.Engine.AddUser(ctx, a.ID, a.UUID); e != nil {
				result.Failed++
				failures = append(failures, fmt.Errorf("restore %s: %w", a.ID, e))
				continue
			}
			observed, present, verifyErr := r.Engine.GetUserUUID(ctx, a.ID)
			if verifyErr != nil || !present || observed != a.UUID {
				// Do not record success for a write that has not been read back.
				result.Failed++
				failures = append(failures, fmt.Errorf("restore verification failed for %s: %v", a.ID, verifyErr))
				continue
			}
			result.Restored++
			continue
		}
		if found {
			if e = r.Engine.RemoveUser(ctx, a.ID); e != nil {
				result.Failed++
				failures = append(failures, fmt.Errorf("remove inactive %s: %w", a.ID, e))
				continue
			}
			_, present, verifyErr := r.Engine.GetUserUUID(ctx, a.ID)
			if verifyErr != nil || present {
				result.Failed++
				failures = append(failures, fmt.Errorf("removal verification failed for %s: %v", a.ID, verifyErr))
				continue
			}
			result.Removed++
		}
		if reason != "" && a.Provisioned && !a.Disabled {
			if e = r.Store.SuspendAccount(ctx, a.ID, reason); e != nil {
				result.Failed++
				failures = append(failures, fmt.Errorf("persist suspension %s: %w", a.ID, e))
				continue
			}
			result.Suspended++
		} else {
			result.Skipped++
		}
	}
	return result, errors.Join(failures...)
}
