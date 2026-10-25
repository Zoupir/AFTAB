package main

import (
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "net/http"
 "net/http/httptest"
 "net/url"
 "os"
 "path/filepath"
 "strings"
 "testing"
)

func desktopTestApp(t *testing.T)*desktopApp{
 t.Helper()
 a,e:=newDesktop(filepath.Join(t.TempDir(),"AFTAB","desktop.json"))
 if e!=nil{t.Fatal(e)}
 return a
}
func desktopRequest(method,path,body string)*http.Request{
 r:=httptest.NewRequest(method,"http://127.0.0.1:19091"+path,strings.NewReader(body))
 r.RemoteAddr="127.0.0.1:55555"
 r.Header.Set("Content-Type","application/x-www-form-urlencoded")
 return r
}
func TestDesktopBootstrapAndCSRF(t *testing.T){
 a:=desktopTestApp(t)
 denied:=httptest.NewRecorder();a.ServeHTTP(denied,desktopRequest("GET","/",""))
 if denied.Code!=403{t.Fatalf("unbootstrapped UI allowed: %d",denied.Code)}
 opened:=httptest.NewRecorder();a.ServeHTTP(opened,desktopRequest("GET","/open?ticket="+a.secret,""))
 if opened.Code!=http.StatusSeeOther{t.Fatal("launch ticket rejected")}
 cookie:=opened.Result().Cookies()[0]
 if !cookie.HttpOnly||cookie.SameSite!=http.SameSiteStrictMode{t.Fatal("weak desktop cookie")}
 second:=httptest.NewRecorder();a.ServeHTTP(second,desktopRequest("GET","/open?ticket="+a.secret,""))
 if second.Code!=403{t.Fatal("bootstrap ticket reused")}
 page:=desktopRequest("GET","/","");page.AddCookie(cookie)
 content:=httptest.NewRecorder();a.ServeHTTP(content,page)
 if content.Code!=200||!strings.Contains(content.Body.String(),"AFTAB"){t.Fatal("desktop GUI failed")}
 bad:=desktopRequest("POST","/disconnect","");bad.AddCookie(cookie)
 result:=httptest.NewRecorder();a.ServeHTTP(result,bad)
 if result.Code!=403{t.Fatal("post accepted without CSRF")}
 evil:=desktopRequest("GET","/","");evil.Host="attacker.example:19091";evil.AddCookie(cookie)
 response:=httptest.NewRecorder();a.ServeHTTP(response,evil)
 if response.Code!=403{t.Fatal("DNS rebinding host accepted")}
}
func TestDesktopConfigRoundtripWithoutTokenExposure(t *testing.T){
 a:=desktopTestApp(t)
 c:=clientConfig{Server:"127.0.0.1:18443",Listen:"127.0.0.1:10808",Token:"0123456789abcdef0123456789abcdef",Pin:strings.Repeat("ab",32)}
 if e:=desktopConfigValid(c);e!=nil{t.Fatal(e)}
 if e:=a.persist(c);e!=nil{t.Fatal(e)}
 info,e:=os.Stat(a.configFile);if e!=nil{t.Fatal(e)}
 if info.Mode().Perm()&0077!=0{t.Fatal("desktop config is not private")}
 loaded,e:=newDesktop(a.configFile);if e!=nil{t.Fatal(e)}
 if loaded.cfg.Token!=c.Token{t.Fatal("saved token missing")}
 launch:=httptest.NewRecorder();loaded.ServeHTTP(launch,desktopRequest("GET","/open?ticket="+loaded.secret,""))
 cookie:=launch.Result().Cookies()[0]
 page:=desktopRequest("GET","/","");page.AddCookie(cookie)
 w:=httptest.NewRecorder();loaded.ServeHTTP(w,page)
 if strings.Contains(w.Body.String(),c.Token){t.Fatal("account token leaked to HTML")}
 raw,e:=os.ReadFile(a.configFile);if e!=nil{t.Fatal(e)}
 var stored clientConfig
 if e=json.Unmarshal(raw,&stored);e!=nil||stored.Server!=c.Server{t.Fatal("configuration damaged")}
}
func TestDesktopBadConfigurations(t *testing.T){
 valid:=clientConfig{Server:"127.0.0.1:18443",Listen:"127.0.0.1:10808",Token:"0123456789abcdef0123456789abcdef",Pin:strings.Repeat("ab",32)}
 bad:=[]clientConfig{}
 a:=valid;a.Server="evil.example";bad=append(bad,a)
 a=valid;a.Server="evil.example:0";bad=append(bad,a)
 a=valid;a.Token="bad\ninterceptor";bad=append(bad,a)
 a=valid;a.Pin="1234";bad=append(bad,a)
 a=valid;a.Listen="0.0.0.0:10808";bad=append(bad,a)
 for _,c:=range bad{if e:=desktopConfigValid(c);e==nil{t.Fatalf("accepted invalid configuration: %+v",c)}}
}
func TestDesktopLocalPinnedTLSDiagnostic(t *testing.T){
 srv:=httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){w.WriteHeader(204)}))
 defer srv.Close()
 cert:=srv.TLS.Certificates[0].Certificate[0]
 sum:=sha256.Sum256(cert)
 c:=clientConfig{Server:srv.Listener.Addr().String(),Listen:"127.0.0.1:10808",Pin:hex.EncodeToString(sum[:]),Token:"0123456789abcdef0123456789abcdef"}
 if e:=desktopProbe(c);e!=nil{t.Fatal(e)}
 c.Pin=strings.Repeat("ff",32)
 if e:=desktopProbe(c);e==nil{t.Fatal("wrong pin accepted")}
}
func TestDesktopSaveRequiresValidAuthenticatedForm(t *testing.T){
 a:=desktopTestApp(t)
 opened:=httptest.NewRecorder();a.ServeHTTP(opened,desktopRequest("GET","/open?ticket="+a.secret,""))
 cookie:=opened.Result().Cookies()[0]
 vals:=url.Values{"server":{"127.0.0.1:18443"},"pin":{strings.Repeat("ab",32)},"token":{"0123456789abcdef0123456789abcdef"},"csrf":{a.csrf}}
 r:=desktopRequest("POST","/save",vals.Encode());r.AddCookie(cookie)
 ok:=httptest.NewRecorder();a.ServeHTTP(ok,r)
 if ok.Code!=http.StatusSeeOther{t.Fatalf("save failed: %d",ok.Code)}
 if a.cfg.Server!="127.0.0.1:18443"{t.Fatal("config not updated")}
}
