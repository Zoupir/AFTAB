package agenthttp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/Zoupir/AFTAB/internal/metering"
)

type TrafficEngine interface {
	UserTraffic(context.Context, string) (metering.Counters, error)
}

func (c LocalClient) UserTraffic(ctx context.Context, id string) (metering.Counters, error) {
	if err := c.validate(); err != nil {
		return metering.Counters{}, err
	}
	if len(id) != 36 || strings.ContainsAny(id, "/\\") {
		return metering.Counters{}, errors.New("invalid ID")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+c.Addr+"/v1/users/"+id+"/traffic", nil)
	if err != nil {
		return metering.Counters{}, err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	resp, err := safeAgentClient(c.HTTP).Do(req)
	if err != nil {
		return metering.Counters{}, errors.New("agent traffic unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return metering.Counters{}, fmt.Errorf("agent traffic HTTP %d", resp.StatusCode)
	}
	uplink, downlink, err := parseTraffic(resp.Body)
	if err != nil {
		return metering.Counters{}, fmt.Errorf("invalid agent traffic response: %w", err)
	}
	return metering.Counters{Uplink: uplink, Downlink: downlink}, nil
}
