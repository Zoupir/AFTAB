package main

import (
 "bufio"
 "encoding/hex"
 "encoding/binary"
 "fmt"
 "io"
 "net"
 "net/http"
 "net/http/httptest"
 "net/url"
 "strconv"
 "strings"
 "testing"
 "time"
)

func TestSOCKSThroughLocalPinnedGateway(t *testing.T){
 // Exercise the complete client -> pinned TLS -> authenticated gateway
 // -> TCP destination path without any real Internet access.
 upstream:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  fmt.Fprint(w,"AFTAB-INTEGRATION-OK")
 }))
 defer upstream.Close()
 parsed,e:=url.Parse(upstream.URL);if e!=nil{t.Fatal(e)}
 destHost,destPortString,e:=net.SplitHostPort(parsed.Host);if e!=nil{t.Fatal(e)}
 destPort,e:=strconv.Atoi(destPortString);if e!=nil{t.Fatal(e)}
 dir:=t.TempDir()
 s,e:=load(dir+"/users.json");if e!=nil{t.Fatal(e)}
 token,e:= (accountBackend{s:s}).CreateUser("integration",1,1);if e!=nil{t.Fatal(e)}
 g:=newGatewayManager(s,dir+"/users.json")
 if e=g.Start(vacantPort(t),false);e!=nil{t.Fatal(e)}
 defer g.Stop()
 cfg:=clientConfig{Server:g.Status().Listen,Listen:"127.0.0.1:10808",Token:token,Pin:g.Status().Fingerprint}
 if e=desktopProbe(cfg);e!=nil{t.Fatal("TLS pin probe failed:",e)}
 pin,_:=hex.DecodeString(cfg.Pin)
 proxyListener,e:=net.Listen("tcp","127.0.0.1:0")
 if e!=nil{t.Fatal(e)}
 defer proxyListener.Close()
 go func(){_ =serveSOCKS(proxyListener,cfg,pin)}()
 client,e:=net.DialTimeout("tcp",proxyListener.Addr().String(),2*time.Second)
 if e!=nil{t.Fatal(e)}
 defer client.Close()
 _=client.SetDeadline(time.Now().Add(8*time.Second))
 if _,e=client.Write([]byte{5,1,0});e!=nil{t.Fatal(e)}
 response:=make([]byte,2)
 if _,e=io.ReadFull(client,response);e!=nil{t.Fatal(e)}
 if response[0]!=5||response[1]!=0{t.Fatal("SOCKS handshake failed")}
 addr:=net.ParseIP(destHost).To4()
 if addr==nil{t.Fatal("expected IPv4 local test destination")}
 request:=append([]byte{5,1,0,1},addr...)
 var portBytes [2]byte;binary.BigEndian.PutUint16(portBytes[:],uint16(destPort))
 request=append(request,portBytes[:]...)
 if _,e=client.Write(request);e!=nil{t.Fatal(e)}
 connectReply:=make([]byte,10)
 if _,e=io.ReadFull(client,connectReply);e!=nil{t.Fatalf("SOCKS CONNECT failed: %v",e)}
 if connectReply[1]!=0{t.Fatalf("SOCKS CONNECT denied: %v",connectReply)}
 if _,e=io.WriteString(client,"GET / HTTP/1.1\r\nHost: "+destHost+"\r\nConnection: close\r\n\r\n");e!=nil{t.Fatal(e)}
 res,e:=http.ReadResponse(bufio.NewReader(client),&http.Request{Method:"GET"})
 if e!=nil{t.Fatal("HTTP tunneled response:",e)}
 defer res.Body.Close()
 body,e:=io.ReadAll(io.LimitReader(res.Body,8192))
 if e!=nil{t.Fatal(e)}
 if !strings.Contains(string(body),"AFTAB-INTEGRATION-OK"){t.Fatalf("gateway returned wrong HTTP body: %q",string(body))}
 if s.userFor(token)==""{t.Fatal("test user was unexpectedly invalidated")}
}
