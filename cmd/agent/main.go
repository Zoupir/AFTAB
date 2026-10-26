package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/Zoupir/AFTAB/internal/agenthttp"
	"github.com/Zoupir/AFTAB/internal/nodeconfig"
	"github.com/Zoupir/AFTAB/internal/xrayapi"
)

func main() {
	addr := flag.String("listen", "127.0.0.1:19111", "agent listener; loopback only")
	xray := flag.String("xray", "127.0.0.1:10085", "dedicated Xray gRPC API; loopback only")
	inbound := flag.String("inbound", "aftab-vless", "dedicated AFTAB-owned VLESS inbound tag")
	flag.Parse()
	if !agenthttp.Loopback(*addr) {
		log.Fatal("agent listener must be local-only")
	}
	engine := xrayapi.Client{Address: *xray, InboundTag: *inbound}
	if e := xrayapi.ValidateClient(engine); e != nil {
		log.Fatal(e)
	}
	configPath := os.Getenv("AFTAB_XRAY_CONFIG")
	if configPath == "" {
		log.Fatal("AFTAB_XRAY_CONFIG is required for quota-enabled agent")
	}
	raw, e := os.ReadFile(configPath)
	if e != nil {
		log.Fatal("cannot read dedicated Xray node configuration: ", e)
	}
	if e = nodeconfig.VerifyRuntimeConfig(raw, *inbound); e != nil {
		log.Fatal("Xray stats safety check failed: ", e)
	}
	token := os.Getenv("AFTAB_AGENT_TOKEN")
	if len(token) < 32 {
		log.Fatal("set a random AFTAB_AGENT_TOKEN of at least 32 characters")
	}
	srv := http.Server{Addr: *addr, Handler: &agenthttp.Handler{Token: token, Engine: engine}, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192}
	log.Printf("AFTAB agent loopback endpoint %s (inbound %s; no public listeners)", *addr, *inbound)
	log.Fatal(srv.ListenAndServe())
}
