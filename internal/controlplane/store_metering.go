package controlplane

// Apply this file to the AFTAB v1 branch alongside internal/metering.
// It adds transactionally durable raw Xray sample checkpoints.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Zoupir/AFTAB/internal/metering"
)

// EnsureMeteringSchema is an idempotent migration. Call it exactly once
// during panel startup, before starting the metering worker. The existing
// Store.Open creates the base accounts table and serializes SQLite access.
func (s *Store) EnsureMeteringSchema(ctx context.Context) error {
	statements := []string{
		"ALTER TABLE accounts ADD COLUMN last_uplink INTEGER NOT NULL DEFAULT 0",
		"ALTER TABLE accounts ADD COLUMN last_downlink INTEGER NOT NULL DEFAULT 0",
		"ALTER TABLE accounts ADD COLUMN sample_initialized INTEGER NOT NULL DEFAULT 0",
		"ALTER TABLE accounts ADD COLUMN suspend_reason TEXT NOT NULL DEFAULT ''",
	}
	for _, q := range statements {
		if _, err := s.db.ExecContext(ctx, q); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
			return fmt.Errorf("metering migration: %w", err)
		}
	}
	return nil
}

func (s *Store) ActiveAccounts(ctx context.Context) ([]metering.ManagedAccount, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,uuid,quota_bytes,used_bytes,expires_at,disabled,provisioned
        FROM accounts WHERE disabled=0 AND provisioned=1 ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []metering.ManagedAccount{}
	for rows.Next() {
		var a metering.ManagedAccount
		var expiry string
		var disabled, provisioned int
		if err := rows.Scan(&a.ID, &a.UUID, &a.QuotaBytes, &a.UsedBytes, &expiry, &disabled, &provisioned); err != nil {
			return nil, err
		}
		a.ExpiresAt, err = time.Parse(time.RFC3339, expiry)
		if err != nil {
			return nil, err
		}
		a.Disabled = disabled != 0
		a.Provisioned = provisioned != 0
		out = append(out, a)
	}
	return out, rows.Err()
}

// ApplySample is the single place where account quota is charged.
// It stores samples AND cumulative usage atomically. Repeated samples are
// idempotent. On a counter drop, the new value is charged as post-reset use.
// Historical used_bytes > 0 accounts get a baseline on their first sample to
// prevent double-charging usage imported from another billing system.
func (s *Store) ApplySample(ctx context.Context, id string, counters metering.Counters) (metering.ManagedAccount, error) {
	var zero metering.ManagedAccount
	if counters.Uplink < 0 || counters.Downlink < 0 {
		return zero, metering.ErrInvalidSample
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return zero, err
	}
	defer tx.Rollback()
	var current metering.ManagedAccount
	var expiry string
	var disabled, provisioned, initialized int
	var old metering.Counters
	err = tx.QueryRowContext(ctx, `SELECT quota_bytes,used_bytes,expires_at,disabled,provisioned,
       last_uplink,last_downlink,sample_initialized FROM accounts WHERE id=?`, id).
		Scan(&current.QuotaBytes, &current.UsedBytes, &expiry, &disabled, &provisioned, &old.Uplink, &old.Downlink, &initialized)
	if errors.Is(err, sql.ErrNoRows) {
		return zero, ErrMissing
	}
	if err != nil {
		return zero, err
	}
	current.ID = id
	current.ExpiresAt, err = time.Parse(time.RFC3339, expiry)
	if err != nil {
		return zero, err
	}
	current.Disabled = disabled != 0
	current.Provisioned = provisioned != 0
	if current.Disabled || !current.Provisioned {
		return zero, metering.ErrInvalidSample
	}
	var delta int64
	if initialized == 0 && current.UsedBytes > 0 {
		// Imported account with existing usage: take first runtime baseline.
		delta = 0
	} else {
		delta, err = metering.Delta(old, counters)
		if err != nil {
			return zero, err
		}
	}
	current.UsedBytes, err = metering.Accumulate(current.UsedBytes, delta)
	if err != nil {
		return zero, err
	}
	result, err := tx.ExecContext(ctx, `UPDATE accounts SET used_bytes=?,last_uplink=?,last_downlink=?,sample_initialized=1
       WHERE id=? AND disabled=0 AND provisioned=1`, current.UsedBytes, counters.Uplink, counters.Downlink, id)
	if err != nil {
		return zero, err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return zero, err
	}
	if changed != 1 {
		return zero, errors.New("metering checkpoint was not applied")
	}
	if err := tx.Commit(); err != nil {
		return zero, err
	}
	return current, nil
}

// MarkSuspended commits the local state only after the Xray peer has been
// removed successfully by the reconciler. If this DB call fails, the caller
// must retry reconciliation rather than announcing a completed suspension.
func (s *Store) MarkSuspended(ctx context.Context, id string, reason metering.Decision) error {
	if reason != metering.SuspendQuota && reason != metering.SuspendExpired {
		return errors.New("invalid suspension reason")
	}
	result, err := s.db.ExecContext(ctx, `UPDATE accounts
       SET disabled=1, provisioned=0, suspend_reason=?
       WHERE id=? AND disabled=0 AND provisioned=1`, string(reason), id)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count == 0 {
		return ErrMissing
	}
	return nil
}
