package nodeconfig

import (
	"strings"
	"testing"
)

const valid = `{
  "api":{"tag":"api","listen":"127.0.0.1:10085","services":["HandlerService","StatsService"]},
  "stats":{},
  "policy":{"levels":{"0":{"statsUserUplink":true,"statsUserDownlink":true}}},
  "inbounds":[{"tag":"aftab-vless","protocol":"vless"},{"tag":"api-proxy","protocol":"dokodemo-door"}],
  "outbounds":[{"tag":"direct","protocol":"freedom"}]
}`

func TestRequiredStatsAndIsolation(t *testing.T) {
	if e := VerifyRuntimeConfig([]byte(valid), "aftab-vless"); e != nil {
		t.Fatal(e)
	}
	tests := []struct{ title, conf, needle string }{
		{"stats missing", strings.Replace(valid, `"stats":{},`, "", 1), "stats object"},
		{"policy disabled", strings.Replace(valid, `"statsUserUplink":true`, `"statsUserUplink":false`, 1), "uplink"},
		{"stats service disabled", strings.Replace(valid, `"StatsService"`, `"OtherService"`, 1), "StatsService"},
		{"public API", strings.Replace(valid, `127.0.0.1:10085`, `0.0.0.0:10085`, 1), "loopback"},
		{"unmanaged inbound", strings.Replace(valid, `aftab-vless`, `other-inbound`, 1), "not found"},
		{"wrong protocol", strings.Replace(valid, `"tag":"aftab-vless","protocol":"vless"`, `"tag":"aftab-vless","protocol":"trojan"`, 1), "VLESS"},
	}
	for _, tc := range tests {
		t.Run(tc.title, func(t *testing.T) {
			err := VerifyRuntimeConfig([]byte(tc.conf), "aftab-vless")
			if err == nil || !strings.Contains(err.Error(), tc.needle) {
				t.Fatalf("invalid config accepted / unexpected error: %v", err)
			}
		})
	}
}
