package nodeconfig

import (
	"strings"
	"testing"
)

const direct = `{
"api":{"tag":"api","listen":"127.0.0.1:10085","services":["StatsService","HandlerService"]},
"stats":{},"policy":{"levels":{"0":{"statsUserUplink":true,"statsUserDownlink":true}}},
"inbounds":[{"tag":"aftab-vless","protocol":"vless"}]}`

const legacy = `{
"api":{"tag":"api","services":["StatsService","HandlerService"]},
"stats":{},"policy":{"levels":{"0":{"statsUserUplink":true,"statsUserDownlink":true}}},
"inbounds":[{"tag":"aftab-vless","protocol":"vless"},{"tag":"api","protocol":"tunnel","listen":"127.0.0.1","port":10085,"settings":{"rewriteAddress":"127.0.0.1"}}],
"routing":{"rules":[{"inboundTag":["api"],"outboundTag":"api"}]}}`

func TestAPIModes(t *testing.T) {
	t.Run("direct", func(t *testing.T) {
		if err := VerifyRuntimeConfig([]byte(direct), "aftab-vless"); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("legacy", func(t *testing.T) {
		if err := VerifyRuntimeConfig([]byte(legacy), "aftab-vless"); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("legacy dokodemo", func(t *testing.T) {
		s := strings.ReplaceAll(legacy, `"protocol":"tunnel"`, `"protocol":"dokodemo-door"`)
		s = strings.ReplaceAll(s, `"rewriteAddress":"127.0.0.1"`, `"address":"127.0.0.1"`)
		if err := VerifyRuntimeConfig([]byte(s), "aftab-vless"); err != nil {
			t.Fatal(err)
		}
	})
}

func TestRejectUnsafeAPIModes(t *testing.T) {
	tests := map[string]string{
		"direct public":           strings.Replace(direct, "127.0.0.1:10085", "0.0.0.0:10085", 1),
		"direct unspecified":      strings.Replace(direct, "127.0.0.1:10085", "localhost:10085", 1),
		"missing mode":            strings.Replace(direct, `,"listen":"127.0.0.1:10085"`, "", 1),
		"legacy public":           strings.Replace(legacy, `"listen":"127.0.0.1"`, `"listen":"0.0.0.0"`, 1),
		"legacy target public":    strings.Replace(legacy, `"rewriteAddress":"127.0.0.1"`, `"rewriteAddress":"0.0.0.0"`, 1),
		"legacy missing route":    strings.Replace(legacy, `"inboundTag":["api"]`, `"inboundTag":["not-api"]`, 1),
		"legacy ambiguous direct": strings.Replace(legacy, `"tag":"api","services"`, `"tag":"api","listen":"127.0.0.1:10085","services"`, 1),
		"managed tag collision":   strings.Replace(direct, `"tag":"api"`, `"tag":"aftab-vless"`, 1),
		"duplicate inbound tag":   strings.Replace(legacy, `{"tag":"api","protocol":"tunnel"`, `{"tag":"aftab-vless","protocol":"tunnel"`, 1),
	}
	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			if err := VerifyRuntimeConfig([]byte(data), "aftab-vless"); err == nil {
				t.Fatalf("unexpected acceptance of unsafe configuration")
			}
		})
	}
}
