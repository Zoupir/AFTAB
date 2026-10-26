package xrayapi

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protowire"
)

func wireFields(t *testing.T, data []byte) map[protowire.Number][]byte {
	t.Helper()
	out := map[protowire.Number][]byte{}
	for len(data) > 0 {
		n, typ, size := protowire.ConsumeTag(data)
		if size < 0 || typ != protowire.BytesType {
			t.Fatal("unexpected protobuf wire type")
		}
		data = data[size:]
		value, sz := protowire.ConsumeBytes(data)
		if sz < 0 {
			t.Fatal("malformed field")
		}
		out[n] = value
		data = data[sz:]
	}
	return out
}
func TestOfficialXrayAlterInboundSchema(t *testing.T) {
	id := "1a5bc922-c418-4985-a4da-8ce4de68f725"
	peer := "872e14a6-1433-4753-b8cb-f194629e158a"
	outer := wireFields(t, addRequest("aftab-in", EmailFor(id), peer))
	if string(outer[1]) != "aftab-in" {
		t.Fatal("wrong inbound tag")
	}
	operation := wireFields(t, outer[2])
	if string(operation[1]) != "xray.app.proxyman.command.AddUserOperation" {
		t.Fatal("wrong operation type")
	}
	user := wireFields(t, wireFields(t, operation[2])[1])
	if string(user[2]) != EmailFor(id) {
		t.Fatal("wrong stable email")
	}
	acctType := wireFields(t, user[3])
	if string(acctType[1]) != "xray.proxy.vless.Account" {
		t.Fatal("wrong account type")
	}
	acct := wireFields(t, acctType[2])
	if string(acct[1]) != peer || string(acct[2]) != "xtls-rprx-vision" || string(acct[3]) != "none" {
		t.Fatal("wrong VLESS user fields")
	}
	rem := wireFields(t, removeRequest("aftab-in", EmailFor(id)))
	remOp := wireFields(t, rem[2])
	if string(remOp[1]) != "xray.app.proxyman.command.RemoveUserOperation" {
		t.Fatal("wrong remove operation type")
	}
	if string(wireFields(t, remOp[2])[1]) != EmailFor(id) {
		t.Fatal("wrong remove email")
	}
}

type stubGRPC struct {
	mu       sync.Mutex
	payloads [][]byte
}

func stubHandler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	p := new(wirePacket)
	if e := dec(p); e != nil {
		return nil, e
	}
	h := srv.(*stubGRPC)
	h.mu.Lock()
	h.payloads = append(h.payloads, append([]byte(nil), p.Data...))
	h.mu.Unlock()
	return &wirePacket{}, nil
}
func TestGRPCLoopbackTransport(t *testing.T) {
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	mock := &stubGRPC{}
	srv := grpc.NewServer(grpc.ForceServerCodec(wireCodec{}))
	srv.RegisterService(&grpc.ServiceDesc{ServiceName: "xray.app.proxyman.command.HandlerService", HandlerType: (*stubService)(nil), Methods: []grpc.MethodDesc{{MethodName: "AlterInbound", Handler: stubHandler}}}, mock)
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Stop(); _ = ln.Close() })
	client := Client{Address: ln.Addr().String(), InboundTag: "aftab-in"}
	id := "1a5bc922-c418-4985-a4da-8ce4de68f725"
	peer := "872e14a6-1433-4753-b8cb-f194629e158a"
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	if e := client.AddUser(ctx, id, peer); e != nil {
		t.Fatal(e)
	}
	if e := client.RemoveUser(ctx, id); e != nil {
		t.Fatal(e)
	}
	mock.mu.Lock()
	defer mock.mu.Unlock()
	if len(mock.payloads) != 2 {
		t.Fatalf("expected 2 actual gRPC operations, got %d", len(mock.payloads))
	}
	if !strings.Contains(string(mock.payloads[0]), "AddUserOperation") || !strings.Contains(string(mock.payloads[1]), "RemoveUserOperation") {
		t.Fatal("incorrect operation dispatched")
	}
}

type stubService interface{ isStub() }

func (*stubGRPC) isStub() {}
func TestForbidPublicXrayAPI(t *testing.T) {
	for _, s := range []string{"0.0.0.0:10085", "[::]:10085", "example.com:10085", "69.169.109.229:10085", "127.0.0.1:", "xray.sock"} {
		if LocalEndpoint(s) == nil {
			t.Fatalf("unsafe remote API accepted: %s", s)
		}
	}
	for _, s := range []string{"127.0.0.1:10085", "[::1]:10085"} {
		if LocalEndpoint(s) != nil {
			t.Fatalf("safe loopback rejected: %s", s)
		}
	}
}
