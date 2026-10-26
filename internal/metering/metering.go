// Package metering implements traffic accounting rules for AFTAB. It does not
// reset or interfere with the upstream Xray counters and contains no I/O.
package metering

import (
	"errors"
	"math"
	"time"
)

var ErrInvalidSample = errors.New("invalid Xray traffic sample")
var ErrCounterOverflow = errors.New("traffic counter overflow")

type Counters struct {
	Uplink   int64
	Downlink int64
}

type Account struct {
	QuotaBytes  int64
	UsedBytes   int64
	ExpiresAt   time.Time
	Disabled    bool
	Provisioned bool
}

// Delta returns the number of bytes newly consumed since the last stored
// sample. If a counter drops (e.g., Xray restart or stats reset), the new
// counter value is treated as traffic since that reset. The algorithm cannot
// guarantee zero missed bytes if Xray restarts between observations, so
// production must document the bound and sample at short intervals.
func Delta(previous, current Counters) (int64, error) {
	if previous.Uplink < 0 || previous.Downlink < 0 || current.Uplink < 0 || current.Downlink < 0 {
		return 0, ErrInvalidSample
	}
	up := current.Uplink
	if current.Uplink >= previous.Uplink {
		up = current.Uplink - previous.Uplink
	}
	down := current.Downlink
	if current.Downlink >= previous.Downlink {
		down = current.Downlink - previous.Downlink
	}
	if up > math.MaxInt64-down {
		return 0, ErrCounterOverflow
	}
	return up + down, nil
}

func Accumulate(used int64, delta int64) (int64, error) {
	if used < 0 || delta < 0 {
		return 0, ErrInvalidSample
	}
	if used > math.MaxInt64-delta {
		return 0, ErrCounterOverflow
	}
	return used + delta, nil
}

type Decision string

const (
	Keep           Decision = "keep"
	SuspendQuota   Decision = "suspend_quota"
	SuspendExpired Decision = "suspend_expired"
	IgnoreInactive Decision = "ignore_inactive"
)

func Evaluate(a Account, now time.Time) Decision {
	if a.Disabled || !a.Provisioned {
		return IgnoreInactive
	}
	if !now.Before(a.ExpiresAt) {
		return SuspendExpired
	}
	if a.QuotaBytes > 0 && a.UsedBytes >= a.QuotaBytes {
		return SuspendQuota
	}
	return Keep
}
