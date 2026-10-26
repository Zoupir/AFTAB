package controlplane

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/Zoupir/AFTAB/internal/metering"
	"github.com/Zoupir/AFTAB/internal/provisioning"
)

// ManagedAccounts intentionally enumerates only identities stored by AFTAB.
// Recovery must never infer ownership of other Xray or 3x-ui peers.
func (s *Store) ManagedAccounts(ctx context.Context) ([]provisioning.ManagedAccount, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,uuid,quota_bytes,used_bytes,expires_at,disabled,provisioned FROM accounts ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []provisioning.ManagedAccount{}
	for rows.Next() {
		var a provisioning.ManagedAccount
		var expiry string
		var dis, prov int
		if err := rows.Scan(&a.ID, &a.UUID, &a.QuotaBytes, &a.UsedBytes, &expiry, &dis, &prov); err != nil {
			return nil, err
		}
		a.ExpiresAt, err = time.Parse(time.RFC3339, expiry)
		if err != nil {
			return nil, fmt.Errorf("invalid expiration for account %s: %w", a.ID, err)
		}
		a.Disabled = dis != 0
		a.Provisioned = prov != 0
		out = append(out, a)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// SuspendAccount preserves the quota worker's existing, test-covered SQL
// transition and ensures recovery uses the same account status changes.
func (s *Store) SuspendAccount(ctx context.Context, id string, reason provisioning.Reason) error {
	var matched metering.Decision
	switch reason {
	case provisioning.Expired:
		matched = metering.SuspendExpired
	case provisioning.Quota:
		matched = metering.SuspendQuota
	default:
		return fmt.Errorf("unsupported suspend reason")
	}
	err := s.MarkSuspended(ctx, id, matched)
	if err == sql.ErrNoRows {
		return ErrMissing
	}
	return err
}
