package xrayapi

import (
	"context"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protowire"
)

type mockStatsService interface{ isStats() }
type mockStats struct {
	t  *testing.T
	id string
}

func (*mockStats) isStats() {}
func mockStatsQuery(srv interface{}, ctx context.Context, decode func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	req := new(wirePacket)
	if e := decode(req); e != nil {
		return nil, e
	}
	m := srv.(*mockStats)
	email := "user>>>" + EmailFor(m.id) + ">>>traffic>>>"
	patterns, e := readBytesField(req.Data, 1)
	if e != nil {
		m.t.Fatal(e)
	}
	if len(patterns) != 1 || string(patterns[0]) != email {
		m.t.Fatalf("unexpected stat pattern: %+v", patterns)
	}
	// reset=true must not be sent: we never reset the shared counters.
	for raw := req.Data; len(raw) > 0; {
		n, tp, k := protowire.ConsumeTag(raw)
		if k < 0 {
			m.t.Fatal("bad proto")
		}
		raw = raw[k:]
		f := protowire.ConsumeFieldValue(n, tp, raw)
		if f < 0 {
			m.t.Fatal("bad field")
		}
		if n == 2 {
			m.t.Fatal("Reset was transmitted")
		}
		raw = raw[f:]
	}
	response := []byte{}
	for _, record := range []struct {
		name string
		num  uint64
	}{{email + "uplink", 87}, {email + "downlink", 250}} {
		row := fieldStr(nil, 1, record.name)
		row = protowire.AppendTag(row, 2, protowire.VarintType)
		row = protowire.AppendVarint(row, record.num)
		response = fieldBytes(response, 1, row)
	}
	return &wirePacket{Data: response}, nil
}
func TestXrayStatsRealGRPCTransport(t *testing.T) {
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	id := "1a5bc922-c418-4985-a4da-8ce4de68f725"
	mock := &mockStats{t: t, id: id}
	srv := grpc.NewServer(grpc.ForceServerCodec(wireCodec{}))
	srv.RegisterService(&grpc.ServiceDesc{ServiceName: "xray.app.stats.command.StatsService", HandlerType: (*mockStatsService)(nil), Methods: []grpc.MethodDesc{{MethodName: "QueryStats", Handler: mockStatsQuery}}}, mock)
	go srv.Serve(listener)
	t.Cleanup(func() { srv.Stop(); listener.Close() })
	c := Client{Address: listener.Addr().String(), InboundTag: "aftab-in"}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	result, e := c.UserTraffic(ctx, id)
	if e != nil || result.Uplink != 87 || result.Downlink != 250 {
		t.Fatalf("bad gRPC stats: %+v %v", result, e)
	}
}
