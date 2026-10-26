package main

import (
 "crypto/subtle"
 "embed"
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
 "strings"
 "time"

 "github.com/Zoupir/AFTAB/internal/controlplane"
)

//go:embed ui-dist/*
var ui embed.FS

type api struct{
 users *controlplane.Store
 adminToken string
}
func forbidden(w http.ResponseWriter,status int,reason string){
 w.Header().Set("Content-Type","application/json; charset=utf-8")
 w.WriteHeader(status)
 _=json.NewEncoder(w).Encode(map[string]string{"error":reason})
}
func (a *api) authorized(r *http.Request)bool{
 supplied:=strings.TrimPrefix(r.Header.Get("Authorization"),"Bearer ")
 return len(supplied)==len(a.adminToken)&&subtle.ConstantTimeCompare([]byte(supplied),[]byte(a.adminToken))==1
}
func (a *api)ServeHTTP(w http.ResponseWriter,r *http.Request){
 w.Header().Set("X-Content-Type-Options","nosniff")
 w.Header().Set("X-Frame-Options","DENY")
 w.Header().Set("Referrer-Policy","no-referrer")
 w.Header().Set("Cache-Control","no-store")
 w.Header().Set("Content-Security-Policy","default-src 'self'; base-uri 'none'; frame-ancestors 'none'; object-src 'none'; connect-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'")
 if r.URL.Path=="/health"&&r.Method=="GET"{
  w.Header().Set("Content-Type","application/json")
  _,_=io.WriteString(w,`{"status":"ok","engine":"not-provisioned"}`)
  return
 }
 if r.URL.Path=="/api/v1/users"||r.URL.Path=="/api/v1/users/"||strings.HasPrefix(r.URL.Path,"/api/v1/users/"){
  if !a.authorized(r){forbidden(w,http.StatusUnauthorized,"unauthorized");return}
  w.Header().Set("Content-Type","application/json; charset=utf-8")
  if r.URL.Path=="/api/v1/users"{
   if r.Method=="GET"{
    users,e:=a.users.List(r.Context())
    if e!=nil{forbidden(w,500,"database_error");return}
    _=json.NewEncoder(w).Encode(users);return
   }
   if r.Method=="POST"{
    r.Body=http.MaxBytesReader(w,r.Body,4096)
    var in struct{Name,Device string; Days int; GB int64}
    dec:=json.NewDecoder(r.Body);dec.DisallowUnknownFields()
    if e:=dec.Decode(&in);e!=nil{forbidden(w,400,"invalid_json");return}
    if e:=dec.Decode(&struct{}{});!errors.Is(e,io.EOF){forbidden(w,400,"multiple_json_documents");return}
    acc,token,e:=a.users.Create(r.Context(),in.Name,in.Device,in.Days,in.GB)
    if errors.Is(e,controlplane.ErrExists){forbidden(w,409,"account_exists");return}
    if e!=nil{forbidden(w,400,"invalid_account");return}
    w.WriteHeader(http.StatusCreated)
    _=json.NewEncoder(w).Encode(struct{
     Account controlplane.Account `json:"account"`
     SubscriptionToken string `json:"subscription_token_once"`
     Provisioning string `json:"provisioning"`
    }{acc,token,"pending_engine_integration"})
    return
   }
   w.Header().Set("Allow","GET, POST")
   forbidden(w,405,"method_not_allowed");return
  }
  if strings.HasSuffix(r.URL.Path,"/disable")&&r.Method=="POST"{
   id:=strings.TrimSuffix(strings.TrimPrefix(r.URL.Path,"/api/v1/users/"),"/disable")
   if len(id)!=36||strings.ContainsAny(id,"/\\"){forbidden(w,404,"not_found");return}
   if e:=a.users.Disable(r.Context(),id);e!=nil{
    if errors.Is(e,controlplane.ErrMissing){forbidden(w,404,"not_found")}else{forbidden(w,500,"database_error")}
    return
   }
   _,_=io.WriteString(w,`{"status":"disabled"}`);return
  }
  forbidden(w,404,"not_found");return
 }
 if strings.HasPrefix(r.URL.Path,"/s/"){
  // Do not issue false-positive client profiles before a real Xray peer is
  // provisioned and confirmed. This will be wired into the agent in phase 1.
  forbidden(w,http.StatusServiceUnavailable,"xray_node_not_provisioned");return
 }
 if r.Method!="GET"&&r.Method!="HEAD"{forbidden(w,405,"method_not_allowed");return}
 name:=strings.TrimPrefix(r.URL.Path,"/")
 if name==""{name="index.html"}
 if strings.Contains(name,"..")||strings.Contains(name,"\\"){http.NotFound(w,r);return}
 b,e:=ui.ReadFile("ui-dist/"+name)
 if e!=nil{http.NotFound(w,r);return}
 switch {
 case strings.HasSuffix(name,".html"):w.Header().Set("Content-Type","text/html; charset=utf-8")
 case strings.HasSuffix(name,".js"):w.Header().Set("Content-Type","application/javascript; charset=utf-8")
 case strings.HasSuffix(name,".css"):w.Header().Set("Content-Type","text/css; charset=utf-8")
 }
 _,_=w.Write(b)
}
func isLocalListener(addr string)bool{host,_,e:=net.SplitHostPort(addr);return e==nil&&net.ParseIP(host)!=nil&&net.ParseIP(host).IsLoopback()}
func main(){
 addr:=flag.String("listen","127.0.0.1:19110","local-only admin panel listen address")
 dbpath:=flag.String("db","./data/aftab-control.sqlite","SQLite database file")
 flag.Parse()
 if !isLocalListener(*addr){log.Fatal("control panel must listen on a numeric loopback address")}
 secret:=os.Getenv("AFTAB_ADMIN_TOKEN")
 if len(secret)<32||len(secret)>512{log.Fatal("set AFTAB_ADMIN_TOKEN (minimum 32 characters); no insecure default password")}
 if e:=os.MkdirAll(filepath.Dir(*dbpath),0700);e!=nil{log.Fatal(e)}
 s,e:=controlplane.Open(*dbpath);if e!=nil{log.Fatal(e)}
 defer s.Close()
 srv:=&http.Server{Addr:*addr,Handler:&api{users:s,adminToken:secret},ReadHeaderTimeout:5*time.Second,ReadTimeout:10*time.Second,WriteTimeout:15*time.Second,IdleTimeout:45*time.Second,MaxHeaderBytes:16384}
 fmt.Printf("AFTAB next control plane preview: http://%s (loopback only; engine not provisioned)\n",*addr)
 log.Fatal(srv.ListenAndServe())
}
