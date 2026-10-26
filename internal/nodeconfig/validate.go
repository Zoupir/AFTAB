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
		Tag      string          `json:"tag"`
		Protocol string          `json:"protocol"`
		Listen   string          `json:"listen"`
		Port     json.RawMessage `json:"port"`
		Settings struct {
			Address        string `json:"address"`
			RewriteAddress string `json:"rewriteAddress"`
		} `json:"settings"`
	} `json:"inbounds"`
	Routing struct {
		Rules []struct {
			InboundTag  []string `json:"inboundTag"`
			OutboundTag string   `json:"outboundTag"`
		} `json:"rules"`
	} `json:"routing"`
}

func numericLoopback(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func numericPort(raw json.RawMessage) bool {
	var port int
	if err := json.Unmarshal(raw, &port); err != nil {
		return false
	}
	return port >= 1 && port <= 65535
}

func directLoopback(address string) bool {
	host, port, err := net.SplitHostPort(address)
	if err != nil || !numericLoopback(host) {
		return false
	}
	n, err := strconv.Atoi(port)
	return err == nil && n >= 1 && n <= 65535
}

// VerifyRuntimeConfig checks both official Xray API wiring modes:
// (1) api.listen on numeric loopback; (2) loopback API inbound plus routing.
// It does not establish effective runtime safety, firewall exposure, or stats
// correctness. A real isolated staging test is still mandatory.
func VerifyRuntimeConfig(raw []byte, managedTag string) error {
	if managedTag == "" {
		return errors.New("missing dedicated inbound tag")
	}
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
	if c.API.Tag == "" || c.API.Tag == managedTag {
		return errors.New("API tag missing or overlapping AFTAB managed tag")
	}
	var managedCount int
	seenTags := map[string]bool{}
	for _, i := range c.Inbounds {
		if i.Tag != "" {
			if seenTags[i.Tag] {
				return fmt.Errorf("duplicate inbound tag %q", i.Tag)
			}
			seenTags[i.Tag] = true
		}
		if i.Tag == managedTag {
			managedCount++
			if i.Protocol != "vless" {
				return errors.New("managed inbound must be VLESS")
			}
		}
	}
	if managedCount == 0 {
		return errors.New("dedicated AFTAB VLESS inbound not found")
	}
	if managedCount != 1 {
		return errors.New("duplicate managed inbound tag")
	}
	if c.API.Listen != "" {
		// The simplified mode does not need any API inbound. Reject ambiguous
		// inbound with the same tag as the API's built-in outbound.
		if !directLoopback(c.API.Listen) || seenTags[c.API.Tag] {
			return errors.New("direct API must listen on loopback without inbound tag collision")
		}
		return nil
	}
	// Legacy mode uses an explicit loopback inbound and a routing rule that
	// forwards its traffic to the api.tag outbound. These tags may differ.
	apiInboundTags := map[string]bool{}
	for _, rule := range c.Routing.Rules {
		if rule.OutboundTag == c.API.Tag {
			for _, tag := range rule.InboundTag {
				if tag == managedTag {
					return errors.New("managed inbound must never route to the admin API")
				}
				apiInboundTags[tag] = true
			}
		}
	}
	if len(apiInboundTags) != 1 {
		return errors.New("legacy API mode needs exactly one routed API inbound")
	}
	for _, i := range c.Inbounds {
		if !apiInboundTags[i.Tag] {
			continue
		}
		if i.Protocol != "tunnel" && i.Protocol != "dokodemo-door" {
			return errors.New("API inbound must be tunnel/dokodemo-door")
		}
		if !numericLoopback(i.Listen) || !numericPort(i.Port) {
			return errors.New("legacy API inbound must listen on numeric loopback with one TCP port")
		}
		if i.Protocol == "tunnel" && !numericLoopback(i.Settings.RewriteAddress) {
			return errors.New("legacy tunnel API target must be loopback")
		}
		if i.Protocol == "dokodemo-door" && !numericLoopback(i.Settings.Address) {
			return errors.New("legacy dokodemo-door API target must be loopback")
		}
		return nil
	}
	return errors.New("legacy API routing rule targets a missing inbound")
}
