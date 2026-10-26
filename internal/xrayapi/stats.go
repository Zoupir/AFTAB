package xrayapi

// Add beside the branch's client.go which owns Client.call and readBytesField.
// Xray upstream: app/stats/command/command.proto (QueryStats, reset=false).
import (
	"context"
	"errors"
	"fmt"
	"math"

	"github.com/Zoupir/AFTAB/internal/metering"
	"google.golang.org/protobuf/encoding/protowire"
)

const queryStatsMethod = "/xray.app.stats.command.StatsService/QueryStats"

func parseCounter(raw []byte) (int64, error) {
	var value int64
	var found bool
	for len(raw) > 0 {
		n, typ, k := protowire.ConsumeTag(raw)
		if k < 0 {
			return 0, errors.New("malformed stats tag")
		}
		raw = raw[k:]
		fieldLen := protowire.ConsumeFieldValue(n, typ, raw)
		if fieldLen < 0 {
			return 0, errors.New("malformed stats field")
		}
		if n == 2 {
			if typ != protowire.VarintType {
				return 0, errors.New("invalid counter type")
			}
			v, k := protowire.ConsumeVarint(raw)
			if k < 0 || v > math.MaxInt64 {
				return 0, errors.New("negative or overflowing counter")
			}
			value = int64(v)
			found = true
		}
		raw = raw[fieldLen:]
	}
	if !found {
		return 0, errors.New("missing stats value")
	}
	return value, nil
}

func (c Client) UserTraffic(ctx context.Context, id string) (metering.Counters, error) {
	if !uuidPattern.MatchString(id) {
		return metering.Counters{}, errors.New("invalid user ID")
	}
	prefix := "user>>>" + EmailFor(id) + ">>>traffic>>>"
	// Field 1 pattern; omit field 2 reset, preserving default false.
	payload := fieldStr(nil, 1, prefix)
	wire, err := c.call(ctx, queryStatsMethod, payload)
	if err != nil {
		return metering.Counters{}, fmt.Errorf("Xray stats query failed: %w", err)
	}
	entries, err := readBytesField(wire, 1)
	if err != nil {
		return metering.Counters{}, err
	}
	var out metering.Counters
	seenUp, seenDown := false, false
	for _, entry := range entries {
		names, err := readBytesField(entry, 1)
		if err != nil {
			return metering.Counters{}, err
		}
		if len(names) != 1 {
			return metering.Counters{}, errors.New("invalid Xray stats name")
		}
		name := string(names[0])
		if name != prefix+"uplink" && name != prefix+"downlink" {
			continue
		}
		n, err := parseCounter(entry)
		if err != nil {
			return metering.Counters{}, err
		}
		if name == prefix+"uplink" {
			if seenUp {
				return metering.Counters{}, errors.New("duplicate uplink sample")
			}
			out.Uplink = n
			seenUp = true
		}
		if name == prefix+"downlink" {
			if seenDown {
				return metering.Counters{}, errors.New("duplicate downlink sample")
			}
			out.Downlink = n
			seenDown = true
		}
	}
	// No entries is expected for a new idle account. The Xray node
	// configuration MUST explicitly enable stats and policy, otherwise samples
	// will all stay zero; validate these settings during node provisioning.
	return out, nil
}
