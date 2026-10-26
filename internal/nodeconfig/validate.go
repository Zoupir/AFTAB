// Package nodeconfig validates Xray runtime prerequisites before allowing
// AFTAB to claim volume enforcement is available. It never modifies a node.
package nodeconfig

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

type config struct {
	API struct {
		Tag      string   `json:"tag"`
		Listen   string   `json:"listen"`
		Services []string `json:"services"`
	} `json:"api"`
	Stats  json.RawMessage `json:"stats"`
	Policy struct {
		Levels map[string]struct {
			Uplink   bool `json:"statsUserUplink"`
			Downlink bool `json:"statsUserDownlink"`
		} `json:"levels"`
	} `json:"policy"`
	Inbounds []struct {
		Tag      string `json:"tag"`
		Protocol string `json:"protocol"`
	} `json:"inbounds"`
}

// VerifyRuntimeConfig fails closed if the services required for quota
// enforcement are missing. It does not promise a successful live stats query;
// after deployment, an integration test must generate traffic and verify
// positive counters on the actual Xray version in use.
func VerifyRuntimeConfig(raw []byte, managedTag string) error {
	if managedTag == "" {
		return errors.New("missing dedicated inbound tag")
	}
	// Xray has additional legitimate keys; decode only the fields this
	// safety gate understands, and validate them strictly.
	var c config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid node JSON: %w", err)
	}
	stats := bytes.TrimSpace(c.Stats)
	if len(stats) < 2 || stats[0] != '{' || stats[len(stats)-1] != '}' {
		return errors.New("Xray stats object is missing or invalid")
	}
	level, ok := c.Policy.Levels["0"]
	if !ok || !level.Uplink || !level.Downlink {
		return errors.New("Xray policy.levels.0 must enable per-user uplink and downlink stats")
	}
	required := map[string]bool{"StatsService": false, "HandlerService": false}
	for _, svc := range c.API.Services {
		if _, ok := required[svc]; ok {
			required[svc] = true
		}
	}
	for svc, enabled := range required {
		if !enabled {
			return fmt.Errorf("Xray api.services is missing %s", svc)
		}
	}
	if c.API.Tag == "" {
		return errors.New("Xray api tag is missing")
	}
	host, port, err := net.SplitHostPort(c.API.Listen)
	if err != nil {
		return errors.New("Xray API must specify an explicit loopback address and port")
	}
	ip := net.ParseIP(host)
	n, e := strconv.Atoi(port)
	if ip == nil || !ip.IsLoopback() || e != nil || n < 1 || n > 65535 {
		return errors.New("Xray admin API must be bound to numeric loopback")
	}
	seen := false
	for _, i := range c.Inbounds {
		if strings.EqualFold(i.Tag, c.API.Tag) && i.Protocol != "" {
			return errors.New("managed API tag overlaps a regular inbound")
		}
		if i.Tag == managedTag {
			if seen {
				return errors.New("duplicate managed inbound tag")
			}
			seen = true
			if i.Protocol != "vless" {
				return errors.New("managed inbound must be VLESS")
			}
		}
	}
	if !seen {
		return errors.New("dedicated AFTAB VLESS inbound not found")
	}
	return nil
}
