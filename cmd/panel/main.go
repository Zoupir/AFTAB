package main

import (
 "crypto/subtle"
 "encoding/base64"
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
 "github.com/Zoupir/AFTAB/internal/subscription"
 "github.com/Zoupir/AFTAB/internal/agenthttp"
)

//go:embed ui-dist/*
var ui embed.FS

type api struct{
 users *controlplane.Store
 adminToken string
 agent *agenthttp.LocalClient
 node *subscription.RealityNode
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
  _,_=io.WriteString(w,`{"status":"ok","engine":"isolated-agent-optional"}`)
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
    provisionState:="pending_agent_configuration"
    if a.agent!=nil{
     if e=a.agent.AddUser(r.Context(),acc.ID,acc.UUID);e==nil{
      if e=a.users.MarkProvisioned(r.Context(),acc.ID);e==nil{
       acc.Provisioned=true
       provisionState="registered_by_agent"
      }else{
       _=a.agent.RemoveUser(r.Context(),acc.ID)
       provisionState="database_provisioning_failed"
      }
     }else{provisionState="agent_registration_failed"}
    }
    uri:=""
    if acc.Provisioned&&a.node!=nil{
     uri,_=subscription.VLESSURI(*a.node,acc.UUID)
    }
    w.WriteHeader(http.StatusCreated)
    _=json.NewEncoder(w).Encode(struct{
     Account controlplane.Account `json:"account"`
     SubscriptionToken string `json:"subscription_token_once"`
     Provisioning string `json:"provisioning"`
     VLESS string `json:"vless_uri,omitempty"`
    }{acc,token,provisionState,uri})
    return
   }
   w.Header().Set("Allow","GET, POST")
   forbidden(w,405,"method_not_allowed");return
  }
  if strings.HasSuffix(r.URL.Path,"/disable")&&r.Method=="POST"{
   id:=strings.TrimSuffix(strings.TrimPrefix(r.URL.Path,"/api/v1/users/"),"/disable")
   if len(id)!=36||strings.ContainsAny(id,"/\\"){forbidden(w,404,"not_found");return}
   account,e:=a.users.Get(r.Context(),id)
   if e!=nil{forbidden(w,404,"not_found");return}
   if account.Provisioned{
    if a.agent==nil{forbidden(w,503,"provisioned_account_requires_agent");return}
    if e:=a.agent.RemoveUser(r.Context(),id);e!=nil{forbidden(w,503,"agent_revoke_failed");return}
   }
   if e:=a.users.Disable(r.Context(),id);e!=nil{
    if errors.Is(e,controlplane.ErrMissing){forbidden(w,404,"not_found")}else{forbidden(w,500,"database_error")}
    return
   }
   _,_=io.WriteString(w,`{"status":"disabled"}`);return
  }
  forbidden(w,404,"not_found");return
 }
 if strings.HasPrefix(r.URL.Path,"/s/"){
  if r.Method!="GET"{forbidden(w,405,"method_not_allowed");return}
  token:=strings.TrimPrefix(r.URL.Path,"/s/")
  if a.node==nil||a.agent==nil{
   forbidden(w,503,"subscription_service_not_configured");return
  }
  acc,e:=a.users.LookupSubscription(r.Context(),token)
  if e!=nil{forbidden(w,404,"subscription_not_found");return}
  uri,e:=subscription.VLESSURI(*a.node,acc.UUID)
  if e!=nil{forbidden(w,503,"invalid_server_profile");return}
  format:=r.URL.Query().Get("format")
  w.Header().Set("Content-Type","text/plain; charset=utf-8")
  w.Header().Set("Cache-Control","private, no-store")
  switch format{
  case "", "uri":_,_=io.WriteString(w,uri+"\\n")
  case "base64":_,_=io.WriteString(w,base64.StdEncoding.EncodeToString([]byte(uri+"\\n")))
  default:forbidden(w,400,"unsupported_subscription_format")
  }
  return
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
 var agent *agenthttp.LocalClient
 if endpoint:=os.Getenv("AFTAB_AGENT_ADDR");endpoint!=""{
  candidate:=agenthttp.LocalClient{Addr:endpoint,Token:os.Getenv("AFTAB_AGENT_TOKEN")}
  if e:=agenthttp.ValidateLocalClient(candidate);e!=nil{log.Fatal(e)}
  agent=&candidate
 }
 var node *subscription.RealityNode
 if v:=os.Getenv("AFTAB_REALITY_NODE_JSON");v!=""{
  var current subscription.RealityNode
  if e:=json.Unmarshal([]byte(v),&current);e!=nil{log.Fatal("invalid AFTAB_REALITY_NODE_JSON")}
  if e:=current.Validate();e!=nil{log.Fatal("invalid AFTAB REALITY node settings: ",e)}
  node=&current
 }
 srv:=&http.Server{Addr:*addr,Handler:&api{users:s,adminToken:secret,agent:agent,node:node},ReadHeaderTimeout:5*time.Second,ReadTimeout:10*time.Second,WriteTimeout:15*time.Second,IdleTimeout:45*time.Second,MaxHeaderBytes:16384}
 fmt.Printf("AFTAB next control plane preview: http://%s (loopback only; engine provisioning via agent)\n",*addr)
 log.Fatal(srv.ListenAndServe())
}
