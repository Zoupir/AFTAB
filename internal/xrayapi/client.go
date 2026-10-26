// Package xrayapi implements a minimal, schema-checked gRPC client for
// Xray HandlerService. It does NOT import or embed the Xray proxy core.
// This keeps the management plane small and independent of Xray's Go version.
package xrayapi

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protowire"
)

const alterInbound = "/xray.app.proxyman.command.HandlerService/AlterInbound"
const getInboundUsers = "/xray.app.proxyman.command.HandlerService/GetInboundUsers"

var emailPattern = regexp.MustCompile(`^[a-zA-Z0-9._@-]{3,160}$`)
var uuidPattern = regexp.MustCompile(`^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[1-8][a-fA-F0-9]{3}-[89abAB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$`)
var tagPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$`)

// Agent constructs peer email from a stable UUID. Never accept arbitrary
// Xray user emails or inbound tags from public endpoints.
func EmailFor(id string) string { return "aftab-" + id + "@users.invalid" }

// LocalEndpoint only accepts numeric loopback addresses; gRPC credentials
// are plaintext *within* this local trust boundary. Future remote agents
// require mTLS, not widening this allowlist.
func LocalEndpoint(addr string) error {
	host, port, e := net.SplitHostPort(addr)
	if e != nil {
		return errors.New("invalid Xray API address")
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() || port == "" {
		return errors.New("Xray API must be on numeric loopback")
	}
	return nil
}

// wirePacket provides the standard gRPC proto framing for pre-serialized,
// version-reviewed messages. The wire fields match upstream .proto files:
// command/command.proto, common/protocol/user.proto, common/serial/typed_message.proto,
// proxy/vless/account.proto. No Xray source code is vendored.
type wirePacket struct{ Data []byte }
type wireCodec struct{}

func (wireCodec) Name() string { return "proto" }
func (wireCodec) Marshal(v any) ([]byte, error) {
	m, ok := v.(*wirePacket)
	if !ok {
		return nil, errors.New("incorrect gRPC packet type")
	}
	return m.Data, nil
}
func (wireCodec) Unmarshal(data []byte, v any) error {
	m, ok := v.(*wirePacket)
	if !ok {
		return errors.New("incorrect gRPC response type")
	}
	m.Data = append(m.Data[:0], data...)
	return nil
}
func fieldStr(b []byte, n protowire.Number, v string) []byte {
	b = protowire.AppendTag(b, n, protowire.BytesType)
	return protowire.AppendString(b, v)
}
func fieldBytes(b []byte, n protowire.Number, v []byte) []byte {
	b = protowire.AppendTag(b, n, protowire.BytesType)
	return protowire.AppendBytes(b, v)
}
func typed(typename string, value []byte) []byte {
	b := fieldStr(nil, 1, typename)
	return fieldBytes(b, 2, value)
}
func addRequest(tag, email, uuid string) []byte {
	// VLESS Account: id=1, flow=2, encryption=3
	account := fieldStr(nil, 1, uuid)
	account = fieldStr(account, 2, "xtls-rprx-vision")
	account = fieldStr(account, 3, "none")
	// common.protocol.User: email=2, account=3, level=1 defaults to 0.
	user := fieldStr(nil, 2, email)
	user = fieldBytes(user, 3, typed("xray.proxy.vless.Account", account))
	operation := fieldBytes(nil, 1, user)
	return inboundRequest(tag, typed("xray.app.proxyman.command.AddUserOperation", operation))
}
func removeRequest(tag, email string) []byte {
	operation := fieldStr(nil, 1, email)
	return inboundRequest(tag, typed("xray.app.proxyman.command.RemoveUserOperation", operation))
}
func inboundRequest(tag string, operation []byte) []byte {
	b := fieldStr(nil, 1, tag)
	return fieldBytes(b, 2, operation)
}

type Client struct{ Address, InboundTag string }

func (c Client) validate() error {
	if e := LocalEndpoint(c.Address); e != nil {
		return e
	}
	if !tagPattern.MatchString(c.InboundTag) {
		return errors.New("invalid managed inbound tag")
	}
	return nil
}
func (c Client) call(ctx context.Context, method string, payload []byte) ([]byte, error) {
	if e := c.validate(); e != nil {
		return nil, e
	}
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	conn, e := grpc.NewClient(c.Address, grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.ForceCodec(wireCodec{})))
	if e != nil {
		return nil, fmt.Errorf("Xray API connection: %w", e)
	}
	defer conn.Close()
	response := new(wirePacket)
	if e = conn.Invoke(ctx, method, &wirePacket{Data: payload}, response); e != nil {
		return nil, fmt.Errorf("Xray gRPC call failed: %w", e)
	}
	return response.Data, nil
}
func (c Client) AddUser(ctx context.Context, id, uuid string) error {
	if !uuidPattern.MatchString(id) || !uuidPattern.MatchString(uuid) {
		return errors.New("invalid account ID or VLESS UUID")
	}
	_, e := c.call(ctx, alterInbound, addRequest(c.InboundTag, EmailFor(id), uuid))
	return e
}
func (c Client) RemoveUser(ctx context.Context, id string) error {
	if !uuidPattern.MatchString(id) {
		return errors.New("invalid account ID")
	}
	_, e := c.call(ctx, alterInbound, removeRequest(c.InboundTag, EmailFor(id)))
	return e
}

// readBytesField walks protobuf bytes fields without depending on Xray's
// generated code. Error on any malformed wire field or unexpected wire type.
func readBytesField(input []byte, number protowire.Number) ([][]byte, error) {
	values := make([][]byte, 0, 1)
	for len(input) > 0 {
		n, t, sz := protowire.ConsumeTag(input)
		if sz < 0 {
			return nil, errors.New("invalid Xray response tag")
		}
		input = input[sz:]
		size := protowire.ConsumeFieldValue(n, t, input)
		if size < 0 {
			return nil, errors.New("invalid Xray response field")
		}
		if n == number {
			if t != protowire.BytesType {
				return nil, errors.New("invalid Xray response bytes")
			}
			v, k := protowire.ConsumeBytes(input)
			if k < 0 {
				return nil, errors.New("invalid Xray response bytes value")
			}
			values = append(values, append([]byte(nil), v...))
		}
		input = input[size:]
	}
	return values, nil
}

// GetUserUUID queries the live Xray HandlerService for this exact account.
// The control-plane uses the same method after mutations in integration tests.
// A user that is not present returns found=false; any gRPC failure is returned.
func (c Client) GetUserUUID(ctx context.Context, id string) (string, bool, error) {
	if !uuidPattern.MatchString(id) {
		return "", false, errors.New("invalid account ID")
	}
	request := fieldStr(nil, 1, c.InboundTag)
	request = fieldStr(request, 2, EmailFor(id))
	response, e := c.call(ctx, getInboundUsers, request)
	if status.Code(e) == codes.NotFound {
		return "", false, nil
	}
	if e != nil {
		return "", false, e
	}
	users, e := readBytesField(response, 1)
	if e != nil {
		return "", false, e
	}
	for _, user := range users {
		emails, e := readBytesField(user, 2)
		if e != nil {
			return "", false, e
		}
		if len(emails) == 0 || string(emails[0]) != EmailFor(id) {
			continue
		}
		accounts, e := readBytesField(user, 3)
		if e != nil {
			return "", false, e
		}
		if len(accounts) == 0 {
			return "", false, errors.New("missing VLESS account")
		}
		ty, e := readBytesField(accounts[0], 1)
		if e != nil {
			return "", false, e
		}
		if len(ty) == 0 || string(ty[0]) != "xray.proxy.vless.Account" {
			return "", false, errors.New("incorrect account type")
		}
		body, e := readBytesField(accounts[0], 2)
		if e != nil {
			return "", false, e
		}
		if len(body) == 0 {
			return "", false, errors.New("empty VLESS account")
		}
		uuids, e := readBytesField(body[0], 1)
		if e != nil {
			return "", false, e
		}
		if len(uuids) == 0 {
			return "", false, errors.New("missing VLESS UUID")
		}
		return string(uuids[0]), true, nil
	}
	return "", false, nil
}

func ValidateClient(c Client) error { return c.validate() }
func SecretSafeError(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	if strings.Contains(s, "Xray gRPC call failed") {
		return "xray_runtime_unavailable_or_rejected"
	}
	return "invalid_agent_configuration"
}
