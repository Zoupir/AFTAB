package main

import (
 "context"
 "net"
 "strings"
 "testing"
 "time"
)

func TestProtectedPublicDestinationFiltering(t *testing.T) {
 cases:=map[string]bool{
  "127.0.0.1":false,
  "10.12.0.1":false,
  "192.168.1.1":false,
  "169.254.169.254":false,
  "100.64.1.1":false,
  "198.18.0.1":false,
  "203.0.113.1":false,
  "2001:db8::1":false,
  "fe80::1":false,
  "::1":false,
  "8.8.8.8":true,
  "1.1.1.1":true,
  "2606:4700:4700::1111":true,
 }
 for literal,want:=range cases {
  got:=allowedPublicIP(net.ParseIP(literal))
  if got!=want{t.Errorf("allowedPublicIP(%s)=%t want=%t",literal,got,want)}
 }
}

func TestProtectedDialRejectsRestrictedRequests(t *testing.T) {
 ctx,cancel:=context.WithTimeout(context.Background(),time.Second)
 defer cancel()
 inputs:=[]struct{host string;port uint16}{
  {"127.0.0.1",443},
  {"169.254.169.254",80},
  {"192.168.1.1",8080},
  {"::1",443},
  {"8.8.8.8",25},
  {"bad\nheader",443},
 }
 for _,x:=range inputs{
  if conn,e:=remoteDestination(ctx,x.host,x.port);e==nil{
   _=conn.Close()
   t.Fatalf("restricted destination was accepted: %q:%d",x.host,x.port)
  }
 }
}
func TestProtectedDestinationNoAddressEcho(t *testing.T){
 ctx,cancel:=context.WithTimeout(context.Background(),time.Second)
 defer cancel()
 _,err:=remoteDestination(ctx,"169.254.169.254",443)
 if err==nil||strings.Contains(err.Error(),"169.254"){t.Fatal("destination address leaked through error string")}
}
