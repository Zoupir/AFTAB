package metering

import (
	"math"
	"testing"
	"time"
)

func TestCounterDelta(t *testing.T) {
	cases := []struct {
		title             string
		previous, current Counters
		want              int64
	}{
		{"initial", Counters{}, Counters{20, 70}, 90},
		{"normal", Counters{20, 70}, Counters{35, 100}, 45},
		{"restart", Counters{400, 700}, Counters{5, 30}, 35},
		{"upload reset", Counters{400, 700}, Counters{5, 715}, 20},
		{"idle", Counters{400, 700}, Counters{400, 700}, 0},
	}
	for _, tc := range cases {
		t.Run(tc.title, func(t *testing.T) {
			v, e := Delta(tc.previous, tc.current)
			if e != nil || v != tc.want {
				t.Fatalf("got=%d err=%v; want=%d", v, e, tc.want)
			}
		})
	}
	if _, e := Delta(Counters{}, Counters{-1, 0}); e != ErrInvalidSample {
		t.Fatal("negative stats accepted")
	}
	if _, e := Delta(Counters{}, Counters{math.MaxInt64, 10}); e != ErrCounterOverflow {
		t.Fatal("overflow accepted")
	}
}
func TestQuotaAndExpiry(t *testing.T) {
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	good := Account{QuotaBytes: 1 << 30, UsedBytes: 10, ExpiresAt: now.Add(time.Hour), Provisioned: true}
	if got := Evaluate(good, now); got != Keep {
		t.Fatal(got)
	}
	good.UsedBytes = good.QuotaBytes
	if got := Evaluate(good, now); got != SuspendQuota {
		t.Fatal(got)
	}
	good.ExpiresAt = now
	if got := Evaluate(good, now); got != SuspendExpired {
		t.Fatal(got)
	}
	good.Disabled = true
	if got := Evaluate(good, now); got != IgnoreInactive {
		t.Fatal(got)
	}
}
func TestPersistenceAccounting(t *testing.T) {
	used := int64(0)
	samples := []Counters{{Uplink: 100, Downlink: 300}, {Uplink: 150, Downlink: 500}, {Uplink: 5, Downlink: 20}, {Uplink: 15, Downlink: 27}}
	previous := Counters{}
	for _, s := range samples {
		d, e := Delta(previous, s)
		if e != nil {
			t.Fatal(e)
		}
		used, e = Accumulate(used, d)
		if e != nil {
			t.Fatal(e)
		}
		previous = s
	}
	if used != 692 {
		t.Fatalf("unexpected usage %d", used)
	}
	if _, e := Accumulate(math.MaxInt64, 1); e != ErrCounterOverflow {
		t.Fatal("overflow accepted")
	}
}
