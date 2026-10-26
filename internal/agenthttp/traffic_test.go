package agenthttp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Zoupir/AFTAB/internal/metering"
)

type trafficMock struct{}

func (trafficMock) AddUser(context.Context, string, string) error { return nil }
func (trafficMock) RemoveUser(context.Context, string) error      { return nil }
func (trafficMock) UserTraffic(context.Context, string) (metering.Counters, error) {
	return metering.Counters{Uplink: 45, Downlink: 180}, nil
}

func TestAgentTrafficAuthAndLocalClient(t *testing.T) {
	id := "1a5bc922-c418-4985-a4da-8ce4de68f725"
	secret := strings.Repeat("u", 64)
	srv := httptest.NewServer(&Handler{Token: secret, Engine: trafficMock{}})
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")
	client := LocalClient{Addr: addr, Token: secret}
	got, e := client.UserTraffic(context.Background(), id)
	if e != nil || got.Uplink != 45 || got.Downlink != 180 {
		t.Fatalf("unexpected traffic: %+v error=%v", got, e)
	}
	r, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/users/"+id+"/traffic", nil)
	resp, e := http.DefaultClient.Do(r)
	if e != nil {
		t.Fatal(e)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("unauthorized traffic query accepted: %d", resp.StatusCode)
	}
	var blocked map[string]string
	if e := json.NewDecoder(resp.Body).Decode(&blocked); e != nil {
		t.Fatal(e)
	}
}
