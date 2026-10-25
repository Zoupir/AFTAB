package main

import (
 "context"
 "encoding/binary"
 "errors"
 "fmt"
 "io"
 "crypto/tls"
 "net"
 "net/http"
 "strconv"
 "strings"
 "time"
)

// httpGatewayDial uses the authenticated pinned TLS tunnel. It allows
// ordinary HTTP CONNECT clients, including browsers using system settings,
// to operate without configuring a SOCKS5 proxy separately.
func httpGatewayDial(ctx context.Context, cfg clientConfig, address string)(net.Conn,error){
 host,portText,e:=net.SplitHostPort(address)
 if e!=nil||host==""||strings.ContainsAny(host,"\r\n\x00"){return nil,errors.New("invalid proxy destination")}
 p,e:=strconv.Atoi(portText)
 if e!=nil||p<1||p>65535{return nil,errors.New("invalid destination port")}
 dialer:=&net.Dialer{Timeout:8*time.Second}
 up,e:=tlsDialGateway(ctx,dialer,cfg)
 if e!=nil{return nil,e}
 _=up.SetDeadline(time.Now().Add(15*time.Second))
 if _,e=fmt.Fprintf(up,"%s\n%s\n",cfg.Token,host);e!=nil{_ =up.Close();return nil,e}
 var pb [2]byte
 binary.BigEndian.PutUint16(pb[:],uint16(p))
 if _,e=up.Write(pb[:]);e!=nil{_ =up.Close();return nil,e}
 var reply [1]byte
 if _,e=io.ReadFull(up,reply[:]);e!=nil{_ =up.Close();return nil,errors.New("gateway handshake refused")}
 if reply[0]!=0{_ =up.Close();return nil,errors.New("gateway denied destination")}
 _=up.SetDeadline(time.Time{})
 return up,nil
}
func tlsDialGateway(ctx context.Context,dialer *net.Dialer,cfg clientConfig)(net.Conn,error){
 raw,e:=dialer.DialContext(ctx,"tcp",cfg.Server)
 if e!=nil{return nil,e}
 tlsConn:=tls.Client(raw,desktopPinnedConfig(cfg))
 _=tlsConn.SetDeadline(time.Now().Add(10*time.Second))
 if e=tlsConn.HandshakeContext(ctx);e!=nil{_ =tlsConn.Close();return nil,e}
 return tlsConn,nil
}
type localHTTPProxy struct{
 cfg clientConfig
 tracked *socksTracker
}
func (p *localHTTPProxy) ServeHTTP(w http.ResponseWriter,r *http.Request){
 w.Header().Set("Cache-Control","no-store")
 if r.Method==http.MethodConnect{
  hostPort:=r.Host
  if _,_,e:=net.SplitHostPort(hostPort);e!=nil{hostPort=net.JoinHostPort(hostPort,"443")}
  ctx,cancel:=context.WithTimeout(r.Context(),12*time.Second)
  upstream,e:=httpGatewayDial(ctx,p.cfg,hostPort)
  cancel()
  if e!=nil{http.Error(w,"AFTAB gateway unavailable",http.StatusBadGateway);return}
  hj,ok:=w.(http.Hijacker)
  if !ok{_ =upstream.Close();http.Error(w,"hijacking unsupported",500);return}
  local,buffer,e:=hj.Hijack()
  if e!=nil{_ =upstream.Close();return}
  if !p.tracked.track(local){_ =local.Close();_ =upstream.Close();return}
  defer p.tracked.untrack(local);defer local.Close();defer upstream.Close()
  if _,e=io.WriteString(local,"HTTP/1.1 200 Connection Established\r\n\r\n");e!=nil{return}
  // Honour any bytes buffered by net/http when the connection is hijacked.
  relay(local,buffer,upstream,func(int64){})
  return
 }
 if r.Method!=http.MethodGet&&r.Method!=http.MethodHead&&r.Method!=http.MethodPost{
  http.Error(w,"unsupported HTTP method",http.StatusMethodNotAllowed);return
 }
 if r.URL==nil||r.URL.Scheme!="http"||r.URL.Host==""{
  http.Error(w,"HTTP absolute-form URL required",http.StatusBadRequest);return
 }
 upstreamReq:=r.Clone(r.Context())
 upstreamReq.RequestURI=""
 upstreamReq.Header.Del("Proxy-Authorization")
 upstreamReq.Header.Del("Proxy-Connection")
 upstreamReq.Header.Del("Connection")
 transport:=&http.Transport{
  Proxy:nil,DisableKeepAlives:true,MaxIdleConns:0,
  DialContext:func(ctx context.Context,network,address string)(net.Conn,error){
   return httpGatewayDial(ctx,p.cfg,address)
  },
 }
 defer transport.CloseIdleConnections()
 resp,e:=transport.RoundTrip(upstreamReq)
 if e!=nil{http.Error(w,"AFTAB gateway unavailable",http.StatusBadGateway);return}
 defer resp.Body.Close()
 for k,v:=range resp.Header{
  if strings.EqualFold(k,"Proxy-Authenticate"){continue}
  for _,entry:=range v{w.Header().Add(k,entry)}
 }
 w.WriteHeader(resp.StatusCode)
 _,_=io.Copy(w,io.LimitReader(resp.Body,32*1024*1024))
}
func serveLocalHTTPProxy(ln net.Listener,cfg clientConfig,tracker *socksTracker)error{
 handler:=&localHTTPProxy{cfg:cfg,tracked:tracker}
 server:=&http.Server{
  Handler:handler,
  ReadHeaderTimeout:5*time.Second,
  IdleTimeout:30*time.Second,
  MaxHeaderBytes:8192,
 }
 e:=server.Serve(ln)
 if errors.Is(e,http.ErrServerClosed)||errors.Is(e,net.ErrClosed){return nil}
 return e
}
