package main

import (
 "crypto/tls"
 "fmt"
 "io"
 "net"
 "net/http"
 "net/http/httptest"
 "net/url"
 "path/filepath"
 "strings"
 "testing"
 "time"
)

func setupHTTPProxyTest(t *testing.T)(string,func()){
 t.Helper()
 db:=filepath.Join(t.TempDir(),"accounts.json")
 s,e:=load(db);if e!=nil{t.Fatal(e)}
 token,e:=(accountBackend{s:s}).CreateUser("http-integration",1,1)
 if e!=nil{t.Fatal(e)}
 gateway:=newGatewayManager(s,db)
 if e=gateway.Start(vacantPort(t),false);e!=nil{t.Fatal(e)}
 cfg:=clientConfig{Server:gateway.Status().Listen,Listen:"127.0.0.1:10808",Token:token,Pin:gateway.Status().Fingerprint}
 ln,e:=net.Listen("tcp","127.0.0.1:0")
 if e!=nil{_ =gateway.Stop();t.Fatal(e)}
 tracker:=newSOCKSTracker()
 server:=newLocalHTTPProxyServer(cfg,tracker)
 go func(){_ =server.Serve(ln)}()
 return "http://"+ln.Addr().String(),func(){
  _=server.Close();_ =ln.Close();tracker.closeAll();_ =gateway.Stop()
 }
}
func TestHTTPBrowserProxyGet(t *testing.T){
 proxyURL,cleanup:=setupHTTPProxyTest(t);defer cleanup()
 target:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){fmt.Fprint(w,"aftab-http-ok")}))
 defer target.Close()
 parsed,e:=url.Parse(proxyURL);if e!=nil{t.Fatal(e)}
 client:=&http.Client{Timeout:5*time.Second,Transport:&http.Transport{Proxy:http.ProxyURL(parsed),DisableKeepAlives:true}}
 res,e:=client.Get(target.URL);if e!=nil{t.Fatal("http browser proxy: ",e)}
 defer res.Body.Close()
 body,e:=io.ReadAll(res.Body);if e!=nil{t.Fatal(e)}
 if res.StatusCode!=200||!strings.Contains(string(body),"aftab-http-ok"){t.Fatalf("unexpected tunneled HTTP: %s",body)}
}
func TestHTTPSBrowserProxyConnect(t *testing.T){
 proxyURL,cleanup:=setupHTTPProxyTest(t);defer cleanup()
 target:=httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){fmt.Fprint(w,"aftab-https-ok")}))
 defer target.Close()
 parsed,e:=url.Parse(proxyURL);if e!=nil{t.Fatal(e)}
 transport:=&http.Transport{Proxy:http.ProxyURL(parsed),TLSClientConfig:&tls.Config{InsecureSkipVerify:true},DisableKeepAlives:true}
 client:=&http.Client{Timeout:6*time.Second,Transport:transport}
 res,e:=client.Get(target.URL);if e!=nil{t.Fatal("HTTPS via CONNECT: ",e)}
 defer res.Body.Close()
 body,e:=io.ReadAll(res.Body);if e!=nil{t.Fatal(e)}
 if res.StatusCode!=200||!strings.Contains(string(body),"aftab-https-ok"){t.Fatalf("unexpected tunneled HTTPS: %s",body)}
}
