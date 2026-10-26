package agenthttp

// This file provides the panel-side traffic interface. Its HTTP endpoint must
// also be added to agenthttp.Handler.ServeHTTP via the integration instructions.
import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

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
	client := c.HTTP
	if client == nil {
		client = &http.Client{Timeout: 7 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return metering.Counters{}, errors.New("agent traffic unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return metering.Counters{}, fmt.Errorf("agent traffic HTTP %d", resp.StatusCode)
	}
	var stats struct {
		Uplink   int64 `json:"uplink"`
		Downlink int64 `json:"downlink"`
	}
	decoder := json.NewDecoder(io.LimitReader(resp.Body, 4096))
	if err := decoder.Decode(&stats); err != nil {
		return metering.Counters{}, err
	}
	if stats.Uplink < 0 || stats.Downlink < 0 {
		return metering.Counters{}, metering.ErrInvalidSample
	}
	return metering.Counters{Uplink: stats.Uplink, Downlink: stats.Downlink}, nil
}
