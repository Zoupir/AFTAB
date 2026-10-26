package agenthttp

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Zoupir/AFTAB/internal/metering"
)

const testID = "1a5bc922-c418-4985-a4da-8ce4de68f725"
const testUUID = "872e14a6-1433-4753-b8cb-f194629e158a"

var testToken = strings.Repeat("X", 48)

func localAgent(t *testing.T, f func(http.ResponseWriter, *http.Request)) (LocalClient, func()) {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(f))
	return LocalClient{Addr: strings.TrimPrefix(s.URL, "http://"), Token: testToken}, s.Close
}
func TestStrictTrafficResponse(t *testing.T) {
	cases := []struct {
		name, body string
		ok         bool
	}{
		{"valid", `{"uplink":0,"downlink":0}`, true},
		{"nonzero", `{"uplink":23,"downlink":88}`, true},
		{"empty", `{}`, false},
		{"partial", `{"uplink":23}`, false},
		{"duplicate", `{"uplink":1,"uplink":100,"downlink":3}`, false},
		{"unknown", `{"uplink":0,"downlink":0,"debug":1}`, false},
		{"null", `{"uplink":null,"downlink":0}`, false},
		{"negative", `{"uplink":-1,"downlink":0}`, false},
		{"fraction", `{"uplink":0.5,"downlink":0}`, false},
		{"overflow", `{"uplink":9223372036854775808,"downlink":0}`, false},
		{"string", `{"uplink":"0","downlink":0}`, false},
		{"array", `[0,0]`, false},
		{"trailing", `{"uplink":0,"downlink":0} {}`, false},
		{"huge", `{"uplink":0,"downlink":0,"padding":"` + strings.Repeat("x", 5000) + `"}`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, close := localAgent(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, tc.body) })
			defer close()
			got, err := c.UserTraffic(context.Background(), testID)
			if (err == nil) != tc.ok {
				t.Fatalf("traffic=%+v error=%v expected success=%v", got, err, tc.ok)
			}
			if !tc.ok && got != (metering.Counters{}) {
				t.Fatalf("invalid sample unexpectedly used: %+v", got)
			}
		})
	}
}
func TestStrictIdentityResponse(t *testing.T) {
	cases := []struct {
		name, body string
		ok, found  bool
	}{
		{"found", `{"found":true,"uuid":"` + testUUID + `"}`, true, true},
		{"absent", `{"found":false,"uuid":""}`, true, false},
		{"missing found", `{"uuid":""}`, false, false},
		{"missing UUID", `{"found":false}`, false, false},
		{"wrong found type", `{"found":0,"uuid":""}`, false, false},
		{"invalid UUID", `{"found":true,"uuid":"definitely-not-an-id"}`, false, false},
		{"false with UUID", `{"found":false,"uuid":"` + testUUID + `"}`, false, false},
		{"duplicate", `{"found":true,"found":false,"uuid":""}`, false, false},
		{"null", `{"found":null,"uuid":""}`, false, false},
		{"trailing", `{"found":false,"uuid":""}[]`, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, close := localAgent(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, tc.body) })
			defer close()
			_, found, err := c.GetUserUUID(context.Background(), testID)
			if (err == nil) != tc.ok || err == nil && found != tc.found {
				t.Fatalf("found=%v err=%v expected ok=%v found=%v", found, err, tc.ok, tc.found)
			}
		})
	}
}
func TestAgentWriteNeedsExplicitAck(t *testing.T) {
	cases := []struct {
		path, body string
		ok         bool
	}{
		{"add", `{"status":"provisioned"}`, true},
		{"add", `{"status":"removed"}`, false},
		{"add", `{}`, false},
		{"add", `{"status":"provisioned"}{}`, false},
		{"disable", `{"status":"removed"}`, true},
		{"disable", `{"status":"provisioned"}`, false},
		{"disable", `{"status":null}`, false},
	}
	for _, tc := range cases {
		t.Run(tc.path+"/"+tc.body, func(t *testing.T) {
			c, close := localAgent(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, tc.body) })
			defer close()
			var err error
			if tc.path == "add" {
				err = c.AddUser(context.Background(), testID, testUUID)
			} else {
				err = c.RemoveUser(context.Background(), testID)
			}
			if (err == nil) != tc.ok {
				t.Fatalf("err=%v expected ok=%v", err, tc.ok)
			}
		})
	}
}
func TestNeverFollowRedirectWithBearer(t *testing.T) {
	var redirected atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirected.Add(1)
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"uplink":1,"downlink":1}`)
	}))
	defer target.Close()
	client, close := localAgent(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	})
	defer close()
	client.HTTP = &http.Client{} // caller-configured client still must not follow.
	if _, err := client.UserTraffic(context.Background(), testID); err == nil {
		t.Fatal("redirected traffic sample accepted")
	}
	if _, _, err := client.GetUserUUID(context.Background(), testID); err == nil {
		t.Fatal("redirected identity accepted")
	}
	if err := client.AddUser(context.Background(), testID, testUUID); err == nil {
		t.Fatal("redirected add accepted")
	}
	if err := client.RemoveUser(context.Background(), testID); err == nil {
		t.Fatal("redirected revoke accepted")
	}
	if redirected.Load() != 0 {
		t.Fatalf("followed redirect %d times", redirected.Load())
	}
}
