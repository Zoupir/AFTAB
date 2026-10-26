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
 "google.golang.org/grpc/credentials/insecure"
 "google.golang.org/protobuf/encoding/protowire"
)

const alterInbound="/xray.app.proxyman.command.HandlerService/AlterInbound"
var emailPattern=regexp.MustCompile(`^[a-zA-Z0-9._@-]{3,160}$`)
var uuidPattern=regexp.MustCompile(`^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[1-8][a-fA-F0-9]{3}-[89abAB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$`)
var tagPattern=regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$`)

// Agent constructs peer email from a stable UUID. Never accept arbitrary
// Xray user emails or inbound tags from public endpoints.
func EmailFor(id string)string{return "aftab-"+id+"@users.invalid"}

// LocalEndpoint only accepts numeric loopback addresses; gRPC credentials
// are plaintext *within* this local trust boundary. Future remote agents
// require mTLS, not widening this allowlist.
func LocalEndpoint(addr string)error{
 host,port,e:=net.SplitHostPort(addr)
 if e!=nil{return errors.New("invalid Xray API address")}
 ip:=net.ParseIP(host)
 if ip==nil||!ip.IsLoopback()||port==""{return errors.New("Xray API must be on numeric loopback")}
 return nil
}

// wirePacket provides the standard gRPC proto framing for pre-serialized,
// version-reviewed messages. The wire fields match upstream .proto files:
// command/command.proto, common/protocol/user.proto, common/serial/typed_message.proto,
// proxy/vless/account.proto. No Xray source code is vendored.
type wirePacket struct{ Data []byte }
type wireCodec struct{}
func(wireCodec)Name()string{return "proto"}
func(wireCodec)Marshal(v any)([]byte,error){
 m,ok:=v.(*wirePacket);if !ok{return nil,errors.New("incorrect gRPC packet type")}
 return m.Data,nil
}
func(wireCodec)Unmarshal(data []byte,v any)error{
 m,ok:=v.(*wirePacket);if !ok{return errors.New("incorrect gRPC response type")}
 m.Data=append(m.Data[:0],data...);return nil
}
func fieldStr(b []byte,n protowire.Number,v string)[]byte{
 b=protowire.AppendTag(b,n,protowire.BytesType)
 return protowire.AppendString(b,v)
}
func fieldBytes(b []byte,n protowire.Number,v []byte)[]byte{
 b=protowire.AppendTag(b,n,protowire.BytesType)
 return protowire.AppendBytes(b,v)
}
func typed(typename string,value []byte)[]byte{
 b:=fieldStr(nil,1,typename)
 return fieldBytes(b,2,value)
}
func addRequest(tag,email,uuid string)[]byte{
 // VLESS Account: id=1, flow=2, encryption=3
 account:=fieldStr(nil,1,uuid)
 account=fieldStr(account,2,"xtls-rprx-vision")
 account=fieldStr(account,3,"none")
 // common.protocol.User: email=2, account=3, level=1 defaults to 0.
 user:=fieldStr(nil,2,email)
 user=fieldBytes(user,3,typed("xray.proxy.vless.Account",account))
 operation:=fieldBytes(nil,1,user)
 return inboundRequest(tag,typed("xray.app.proxyman.command.AddUserOperation",operation))
}
func removeRequest(tag,email string)[]byte{
 operation:=fieldStr(nil,1,email)
 return inboundRequest(tag,typed("xray.app.proxyman.command.RemoveUserOperation",operation))
}
func inboundRequest(tag string,operation []byte)[]byte{
 b:=fieldStr(nil,1,tag)
 return fieldBytes(b,2,operation)
}
type Client struct{ Address,InboundTag string }
func(c Client)validate()error{
 if e:=LocalEndpoint(c.Address);e!=nil{return e}
 if !tagPattern.MatchString(c.InboundTag){return errors.New("invalid managed inbound tag")}
 return nil
}
func(c Client)invoke(ctx context.Context,payload []byte)error{
 if e:=c.validate();e!=nil{return e}
 ctx,cancel:=context.WithTimeout(ctx,6*time.Second);defer cancel()
 conn,e:=grpc.NewClient(c.Address,grpc.WithTransportCredentials(insecure.NewCredentials()),
   grpc.WithDefaultCallOptions(grpc.ForceCodec(wireCodec{})))
 if e!=nil{return fmt.Errorf("Xray API connection: %w",e)}
 defer conn.Close()
 response:=new(wirePacket)
 if e=conn.Invoke(ctx,alterInbound,&wirePacket{Data:payload},response);e!=nil{return fmt.Errorf("Xray AlterInbound failed: %w",e)}
 return nil
}
func(c Client)AddUser(ctx context.Context,id,uuid string)error{
 if !uuidPattern.MatchString(id)||!uuidPattern.MatchString(uuid){return errors.New("invalid account ID or VLESS UUID")}
 return c.invoke(ctx,addRequest(c.InboundTag,EmailFor(id),uuid))
}
func(c Client)RemoveUser(ctx context.Context,id string)error{
 if !uuidPattern.MatchString(id){return errors.New("invalid account ID")}
 return c.invoke(ctx,removeRequest(c.InboundTag,EmailFor(id)))
}
func ValidateClient(c Client)error{return c.validate()}
func SecretSafeError(err error)string{
 if err==nil{return ""}
 s:=err.Error()
 if strings.Contains(s,"Xray AlterInbound failed") {return "xray_runtime_unavailable_or_rejected"}
 return "invalid_agent_configuration"
}
