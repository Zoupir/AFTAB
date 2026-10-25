package main

import (
 "context"
 "errors"
 "net"
 "strconv"
 "strings"
 "time"
)

// Publicly reachable research gateways are not allowed to become an
// unauthenticated tunnel into localhost, RFC1918 or metadata services.
var forbiddenDestinations = func()[]*net.IPNet{
 entries:=[]string{
  "0.0.0.0/8","10.0.0.0/8","100.64.0.0/10","127.0.0.0/8",
  "169.254.0.0/16","172.16.0.0/12","192.0.0.0/24",
  "192.0.2.0/24","192.168.0.0/16","198.18.0.0/15",
  "198.51.100.0/24","203.0.113.0/24","224.0.0.0/4",
  "240.0.0.0/4","::/128","::1/128","fc00::/7","fe80::/10",
  "ff00::/8","2001:db8::/32",
 }
 nets:=make([]*net.IPNet,0,len(entries))
 for _,s:=range entries{_,n,_:=net.ParseCIDR(s);nets=append(nets,n)}
 return nets
}()
func allowedPublicIP(ip net.IP)bool{
 if ip==nil||!ip.IsGlobalUnicast()||ip.IsPrivate()||ip.IsLoopback()||ip.IsLinkLocalUnicast(){return false}
 if v4:=ip.To4();v4!=nil{ip=v4}
 for _,n:=range forbiddenDestinations{if n.Contains(ip){return false}}
 return true
}
func remoteDestination(ctx context.Context,host string,port uint16)(net.Conn,error){
 // Only common web endpoints are in scope of this preview.
 switch port{case 80,443,8080,8443:default:return nil,errors.New("destination_port_denied")}
 if strings.ContainsAny(host,"\r\n\x00/\\")||host==""{return nil,errors.New("invalid_destination")}
 var ips []net.IP
 if literal:=net.ParseIP(host);literal!=nil{ips=[]net.IP{literal}}else{
  resolved,e:=net.DefaultResolver.LookupIPAddr(ctx,host)
  if e!=nil{return nil,errors.New("dns_failed")}
  for _,a:=range resolved{ips=append(ips,a.IP)}
 }
 dialer:=net.Dialer{Timeout:5*time.Second}
 for _,ip:=range ips{
  if !allowedPublicIP(ip){continue}
  conn,e:=dialer.DialContext(ctx,"tcp",net.JoinHostPort(ip.String(),strconv.Itoa(int(port))))
  if e==nil{return conn,nil}
 }
 return nil,errors.New("public_destination_unreachable_or_blocked")
}
