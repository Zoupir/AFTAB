// Package agenthttp exposes narrow, local-only administrative operations to
// the standalone AFTAB control plane. Multi-host transport requires mTLS and
// is deliberately not enabled in this first phase.
package agenthttp

import (
 "context"
 "crypto/subtle"
 "encoding/json"
 "errors"
 "io"
 "net"
 "net/http"
 "strings"
 "time"
)
type Engine interface{
 AddUser(context.Context,string,string)error
 RemoveUser(context.Context,string)error
}
type Handler struct{
 Token string
 Engine Engine
}
func Loopback(addr string)bool{
 host,port,e:=net.SplitHostPort(addr)
 return e==nil&&port!=""&&net.ParseIP(host)!=nil&&net.ParseIP(host).IsLoopback()
}
func output(w http.ResponseWriter,code int,value any){
 w.Header().Set("Content-Type","application/json; charset=utf-8")
 w.Header().Set("Cache-Control","no-store")
 w.WriteHeader(code)
 _=json.NewEncoder(w).Encode(value)
}
func(h *Handler)ServeHTTP(w http.ResponseWriter,r *http.Request){
 w.Header().Set("X-Content-Type-Options","nosniff")
 if !Loopback(r.RemoteAddr){output(w,403,map[string]string{"error":"local_only"});return}
 if r.URL.Path=="/health"&&r.Method=="GET"{
  output(w,200,map[string]string{"status":"agent_running"});return
 }
 if h.Engine==nil||len(h.Token)<32{output(w,503,map[string]string{"error":"agent_not_configured"});return}
 supplied:=strings.TrimPrefix(r.Header.Get("Authorization"),"Bearer ")
 if len(supplied)!=len(h.Token)||subtle.ConstantTimeCompare([]byte(supplied),[]byte(h.Token))!=1{
  output(w,401,map[string]string{"error":"unauthorized"});return
 }
 ctx,cancel:=context.WithTimeout(r.Context(),7*time.Second);defer cancel()
 if r.URL.Path=="/v1/users"&&r.Method=="POST"{
  r.Body=http.MaxBytesReader(w,r.Body,2048)
  var req struct{ID string `json:"id"`;UUID string `json:"uuid"`}
  dec:=json.NewDecoder(r.Body);dec.DisallowUnknownFields()
  if e:=dec.Decode(&req);e!=nil{output(w,400,map[string]string{"error":"invalid_request"});return}
  if e:=dec.Decode(&struct{}{});!errors.Is(e,io.EOF){output(w,400,map[string]string{"error":"invalid_json"});return}
  if e:=h.Engine.AddUser(ctx,req.ID,req.UUID);e!=nil{
   output(w,502,map[string]string{"error":"engine_add_failed"});return
  }
  output(w,200,map[string]string{"status":"provisioned"});return
 }
 if strings.HasPrefix(r.URL.Path,"/v1/users/")&&strings.HasSuffix(r.URL.Path,"/disable")&&r.Method=="POST"{
  id:=strings.TrimSuffix(strings.TrimPrefix(r.URL.Path,"/v1/users/"),"/disable")
  if strings.ContainsAny(id,"/\\")||len(id)!=36{output(w,404,map[string]string{"error":"not_found"});return}
  if e:=h.Engine.RemoveUser(ctx,id);e!=nil{
   output(w,502,map[string]string{"error":"engine_remove_failed"});return
  }
  output(w,200,map[string]string{"status":"removed"});return
 }
 output(w,404,map[string]string{"error":"not_found"})
}
