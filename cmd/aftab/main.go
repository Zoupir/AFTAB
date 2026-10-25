package main

import (
 "bufio"
 "crypto/rand"
 "crypto/sha256"
 "crypto/subtle"
 "crypto/tls"
 "crypto/x509"
 "encoding/binary"
 "encoding/hex"
 "encoding/json"
 "errors"
 "flag"
 "fmt"
 "io"
 "log"
 "net"
 "net/http"
 "os"
 "path/filepath"
 "strconv"
 "strings"
 "sync"
 "time"

 "github.com/Zoupir/AFTAB/internal/observability"
)

var diagnostics *observability.Logger
func event(level, component, name, code string, fields ...any) {
 if diagnostics!=nil { diagnostics.Log(level,component,name,observability.ID(),code,fields...) }
}

type User struct {
 Name string `json:"name"`
 Token string `json:"token"`
 Expires string `json:"expires"`
 QuotaBytes int64 `json:"quota_bytes"`
 UsedBytes int64 `json:"used_bytes"`
 Disabled bool `json:"disabled"`
}
type database struct {AdminToken string `json:"admin_token"`; Users map[string]*User `json:"users"`}
type store struct {mu sync.Mutex; path string; db database}
func newToken() string {b:=make([]byte,32);if _,e:=rand.Read(b);e!=nil{panic(e)};return hex.EncodeToString(b)}
func load(path string)(*store,error){
 s:=&store{path:path}
 b,e:=os.ReadFile(path)
 if errors.Is(e,os.ErrNotExist){
  s.db=database{Users:map[string]*User{}}
  if e=os.MkdirAll(filepath.Dir(path),0700);e!=nil{return nil,e}
  if e=s.save();e!=nil{return nil,e}
  return s,nil
 }
 if e!=nil{return nil,e}
 if e=json.Unmarshal(b,&s.db);e!=nil{return nil,e}
 if s.db.Users==nil{s.db.Users=map[string]*User{}}
 return s,nil
}
func(s *store)save()error{
 b,e:=json.MarshalIndent(s.db,"","  ");if e!=nil{return e}
 p:=s.path+".tmp";if e=os.WriteFile(p,b,0600);e!=nil{return e}
 return os.Rename(p,s.path)
}
func(s *store)userFor(t string)string{
 s.mu.Lock();defer s.mu.Unlock()
 for id,u:=range s.db.Users{
  if subtle.ConstantTimeCompare([]byte(t),[]byte(u.Token))!=1||u.Disabled{continue}
  if u.Expires!=""{at,e:=time.Parse(time.RFC3339,u.Expires);if e!=nil||time.Now().After(at){continue}}
  if u.QuotaBytes>0&&u.UsedBytes>=u.QuotaBytes{continue}
  return id
 }
 return ""
}
func(s *store)credit(id string,n int64){
 if n<=0{return};s.mu.Lock();defer s.mu.Unlock()
 if u:=s.db.Users[id];u!=nil{u.UsedBytes+=n;_ =s.save()}
}
func loopback(addr string)bool{h,_,e:=net.SplitHostPort(addr);if e!=nil{return false};ip:=net.ParseIP(h);return ip!=nil&&ip.IsLoopback()}
func gateway(addr,cert,key string,s *store)error{
 pair,e:=tls.LoadX509KeyPair(cert,key);if e!=nil{return e}
 ln,e:=tls.Listen("tcp",addr,&tls.Config{MinVersion:tls.VersionTLS13,Certificates:[]tls.Certificate{pair}});if e!=nil{return e}
 defer ln.Close();event("info","gateway","listener_started","ok")
 for{c,e:=ln.Accept();if e!=nil{return e};go func(){
  defer c.Close();_ =c.SetDeadline(time.Now().Add(15*time.Second))
  r:=bufio.NewReaderSize(c,512)
  tok,e:=r.ReadString('\n');if e!=nil||len(tok)>128{return}
  id:=s.userFor(strings.TrimSpace(tok));if id==""{event("warn","gateway","connection_rejected","unauthorized");return}
  host,e:=r.ReadString('\n');if e!=nil||len(host)>260{return};host=strings.TrimSpace(host)
  pb:=make([]byte,2);if _,e=io.ReadFull(r,pb);e!=nil{return}
  port:=binary.BigEndian.Uint16(pb);if port==0||host==""{return}
  // Lab-only: arbitrary destination access; never expose publicly without ACLs.
  upstream,e:=net.DialTimeout("tcp",net.JoinHostPort(host,strconv.Itoa(int(port))),10*time.Second)
  if e!=nil{event("warn","gateway","dial_failed","upstream_unreachable");_,_=c.Write([]byte{1});return};defer upstream.Close()
  _,_=c.Write([]byte{0});_ =c.SetDeadline(time.Time{})
  relay(c,r,upstream,func(n int64){s.credit(id,n)})
 }()}
}
func relay(c net.Conn,r io.Reader,up net.Conn,account func(int64)){
 var wg sync.WaitGroup;wg.Add(2)
 go func(){defer wg.Done();n,_:=io.Copy(up,r);account(n);if x,ok:=up.(interface{CloseWrite()error});ok{_ =x.CloseWrite()}}()
 go func(){defer wg.Done();n,_:=io.Copy(c,up);account(n);if x,ok:=c.(interface{CloseWrite()error});ok{_ =x.CloseWrite()}}()
 wg.Wait()
}
type clientConfig struct {Server string `json:"server"`; Listen string `json:"listen"`; Token string `json:"token"`; Pin string `json:"pin"`}
func proxy(cfg clientConfig)error{
 if cfg.Listen==""{cfg.Listen="127.0.0.1:10808"}
 if !loopback(cfg.Listen){return errors.New("SOCKS listener must be loopback")}
 pin,e:=hex.DecodeString(strings.ReplaceAll(strings.ToLower(cfg.Pin),":",""));if e!=nil||len(pin)!=32{return errors.New("invalid SHA256 certificate pin")}
 ln,e:=net.Listen("tcp",cfg.Listen);if e!=nil{return e};defer ln.Close();event("info","client","listener_started","ok")
 for{c,e:=ln.Accept();if e!=nil{return e};go func(){defer c.Close();if e:=socks(c,cfg,pin);e!=nil{event("warn","client","connection_failed","proxy_error")}}()}
}
func socks(c net.Conn,cfg clientConfig,pin []byte)error{
 _=c.SetDeadline(time.Now().Add(15*time.Second));r:=bufio.NewReader(c)
 h:=make([]byte,2);if _,e:=io.ReadFull(r,h);e!=nil{return e};if h[0]!=5||h[1]==0{return errors.New("not SOCKS5")}
 methods:=make([]byte,int(h[1]));if _,e:=io.ReadFull(r,methods);e!=nil{return e}
 found:=false;for _,v:=range methods{if v==0{found=true}}
 if !found{_,_=c.Write([]byte{5,255});return errors.New("SOCKS no-auth not offered")}
 _,_=c.Write([]byte{5,0})
 req:=make([]byte,4);if _,e:=io.ReadFull(r,req);e!=nil{return e}
 if req[0]!=5||req[1]!=1{return errors.New("only SOCKS CONNECT supported")}
 var host string
 switch req[3]{
 case 1:b:=make([]byte,4);if _,e:=io.ReadFull(r,b);e!=nil{return e};host=net.IP(b).String()
 case 4:b:=make([]byte,16);if _,e:=io.ReadFull(r,b);e!=nil{return e};host=net.IP(b).String()
 case 3:n,e:=r.ReadByte();if e!=nil{return e};b:=make([]byte,int(n));if _,e=io.ReadFull(r,b);e!=nil{return e};host=string(b)
 default:return errors.New("unsupported address type")
 }
 pb:=make([]byte,2);if _,e:=io.ReadFull(r,pb);e!=nil{return e}
 tlsCfg:=&tls.Config{MinVersion:tls.VersionTLS13,InsecureSkipVerify:true,VerifyPeerCertificate:func(raw [][]byte,_ [][]*x509.Certificate)error{
  if len(raw)==0{return errors.New("missing cert")};actual:=sha256.Sum256(raw[0]);if subtle.ConstantTimeCompare(actual[:],pin)!=1{return errors.New("certificate pin mismatch")};return nil
 }}
 up,e:=tls.DialWithDialer(&net.Dialer{Timeout:10*time.Second},"tcp",cfg.Server,tlsCfg);if e!=nil{return e};defer up.Close()
 _=up.SetDeadline(time.Now().Add(15*time.Second))
 if _,e=fmt.Fprintf(up,"%s\n%s\n",cfg.Token,host);e!=nil{return e}
 if _,e=up.Write(pb);e!=nil{return e}
 reply:=make([]byte,1);if _,e=io.ReadFull(up,reply);e!=nil{return e}
 if reply[0]!=0{return errors.New("destination rejected")}
 _,_=c.Write([]byte{5,0,0,1,0,0,0,0,0,0})
 _=c.SetDeadline(time.Time{});_=up.SetDeadline(time.Time{})
 relay(c,r,up,func(int64){});return nil
}
func admin(addr string,s *store)error{
 if !loopback(addr){return errors.New("admin listener must be loopback")}
 mux:=http.NewServeMux()
 mux.HandleFunc("/",func(w http.ResponseWriter,r *http.Request){w.Header().Set("Content-Type","text/html; charset=utf-8");fmt.Fprint(w,"<html><meta charset=utf-8><title>AFTAB Lab</title><h1>AFTAB research administration API</h1><p>Loopback only. Use authenticated API requests. Not for production.</p></html>")})
 authorized:=func(r *http.Request)bool{s.mu.Lock();defer s.mu.Unlock();t:=strings.TrimPrefix(r.Header.Get("Authorization"),"Bearer ");return t!=""&&subtle.ConstantTimeCompare([]byte(t),[]byte(s.db.AdminToken))==1}
 mux.HandleFunc("/api/users",func(w http.ResponseWriter,r *http.Request){
  if !authorized(r){http.Error(w,"unauthorized",401);return}
  w.Header().Set("Content-Type","application/json")
  if r.Method=="GET"{
   s.mu.Lock();users:=make([]User,0,len(s.db.Users));for _,u:=range s.db.Users{v:=*u;v.Token="";users=append(users,v)};s.mu.Unlock();_ =json.NewEncoder(w).Encode(users);return
  }
  if r.Method!="POST"{http.Error(w,"method not allowed",405);return}
  var q struct{Name string `json:"name"`; Days int `json:"days"`; GB int64 `json:"gb"`}
  if e:=json.NewDecoder(http.MaxBytesReader(w,r.Body,2048)).Decode(&q);e!=nil||len(q.Name)<1||len(q.Name)>80||q.Days<1||q.Days>3650||q.GB<0||q.GB>100000{http.Error(w,"invalid input",400);return}
  s.mu.Lock();defer s.mu.Unlock()
  if _,ok:=s.db.Users[q.Name];ok{http.Error(w,"duplicate",409);return}
  t:=newToken()
  s.db.Users[q.Name]=&User{Name:q.Name,Token:t,Expires:time.Now().Add(time.Duration(q.Days)*24*time.Hour).UTC().Format(time.RFC3339),QuotaBytes:q.GB*1073741824}
  if e:=s.save();e!=nil{http.Error(w,"storage",500);return}
  _=json.NewEncoder(w).Encode(map[string]string{"name":q.Name,"token":t})
 })
 mux.HandleFunc("/api/users/",func(w http.ResponseWriter,r *http.Request){
  if !authorized(r){http.Error(w,"unauthorized",401);return}
  if r.Method!="DELETE"{http.Error(w,"method not allowed",405);return}
  name:=strings.TrimPrefix(r.URL.Path,"/api/users/")
  s.mu.Lock();defer s.mu.Unlock()
  u:=s.db.Users[name];if u==nil{http.Error(w,"not found",404);return}
  u.Disabled=true;if e:=s.save();e!=nil{http.Error(w,"storage",500);return}
  w.WriteHeader(204)
 })
 event("info","admin","listener_started","ok");return http.ListenAndServe(addr,mux)
}
func main(){
 mode:=flag.String("mode","server","server or client")
 listen:=flag.String("listen","","listen address")
 adminAddr:=flag.String("admin","127.0.0.1:19090","loopback admin")
 cert:=flag.String("cert","","server TLS certificate")
 key:=flag.String("key","","server TLS key")
 db:=flag.String("db","./aftab-users.json","user store")
 config:=flag.String("config","","client JSON config")
 logLevel:=flag.String("log-level","info","debug, info, warn or error")
 logFile:=flag.String("log-file","","path to newline-delimited JSON diagnostic logs; default stderr")
 flag.Parse()
 var diagErr error
 diagnostics,diagErr=observability.New(*logLevel,*logFile)
 if diagErr!=nil { log.Fatal("diagnostics initialization failed: ",diagErr) }
 defer diagnostics.Close()
 event("info","process","starting","ok","mode",*mode)
 switch *mode{
 case "server":
  if *listen==""{*listen="127.0.0.1:18443"}
  if *cert==""||*key==""{log.Fatal("missing TLS certificate or key")}
  if !loopback(*listen)||!loopback(*adminAddr){log.Fatal("research v1 only accepts loopback listeners")}
  s,e:=load(*db);if e!=nil{log.Fatal(e)}
  panel,e:=newDashboard(*adminAddr,*db+".admin.json",*logFile,s);if e!=nil{log.Fatal("dashboard initialization failed: ",e)}
  go func(){event("info","dashboard","listener_starting","ok");if e:=panel.ListenAndServe(*adminAddr);e!=nil{log.Print("dashboard stopped: ",e)}}()
  log.Fatal(gateway(*listen,*cert,*key,s))
 case "client":
  if *config==""{log.Fatal("client needs -config")}
  var c clientConfig;b,e:=os.ReadFile(*config);if e!=nil{log.Fatal(e)}
  if e=json.Unmarshal(b,&c);e!=nil{log.Fatal(e)}
  if *listen!=""{c.Listen=*listen}
  log.Fatal(proxy(c))
 default:log.Fatal("unknown mode")
 }
}
