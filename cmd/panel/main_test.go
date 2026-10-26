package main

import (
 "bytes"
 "encoding/json"
 "net/http"
 "net/http/httptest"
 "path/filepath"
 "context"
 "encoding/base64"
 "net/url"
 "strings"
 "testing"

 "github.com/Zoupir/AFTAB/internal/controlplane"
 "github.com/Zoupir/AFTAB/internal/agenthttp"
 "github.com/Zoupir/AFTAB/internal/subscription"
)

func request(t *testing.T,handler http.Handler,method,path string,body []byte,authenticated bool)*httptest.ResponseRecorder{
 t.Helper()
 r:=httptest.NewRequest(method,path,bytes.NewReader(body))
 if authenticated{r.Header.Set("Authorization","Bearer "+strings.Repeat("S",64))}
 w:=httptest.NewRecorder()
 handler.ServeHTTP(w,r)
 return w
}
func TestControlPlaneAPISecureLifecycle(t *testing.T){
 s,e:=controlplane.Open(filepath.Join(t.TempDir(),"accounts.sqlite"))
 if e!=nil{t.Fatal(e)}
 defer s.Close()
 handler:=&api{users:s,adminToken:strings.Repeat("S",64)}
 if r:=request(t,handler,"GET","/api/v1/users",nil,false);r.Code!=401{t.Fatalf("unauthenticated list: %d",r.Code)}
 if r:=request(t,handler,"POST","/api/v1/users",[]byte(`{"Name":"bad","Device":"windows","Days":0,"GB":30}`),true);r.Code!=400{t.Fatalf("accepted invalid account: %d",r.Code)}
 payload:=[]byte(`{"Name":"test-win","Device":"windows","Days":30,"GB":30}`)
 r:=request(t,handler,"POST","/api/v1/users",payload,true)
 if r.Code!=201{t.Fatalf("create: %d %s",r.Code,r.Body.String())}
 var created struct{Account controlplane.Account `json:"account"`;SubscriptionToken string `json:"subscription_token_once"`;Provisioning string `json:"provisioning"`}
 if e:=json.Unmarshal(r.Body.Bytes(),&created);e!=nil{t.Fatal(e)}
 if len(created.SubscriptionToken)!=64||created.Provisioning!="pending_agent_configuration"{t.Fatal("incorrect pending provisioning response")}
 r=request(t,handler,"GET","/api/v1/users",nil,true)
 if r.Code!=200||strings.Contains(r.Body.String(),created.SubscriptionToken){t.Fatal("subscription token appeared in user listing")}
 r=request(t,handler,"POST","/api/v1/users",payload,true)
 if r.Code!=409{t.Fatalf("duplicate account not rejected: %d",r.Code)}
 r=request(t,handler,"GET","/s/"+created.SubscriptionToken,nil,false)
 if r.Code!=503||!strings.Contains(r.Body.String(),"not_provisioned"){t.Fatalf("issued invalid unprovisioned subscription: %d",r.Code)}
 r=request(t,handler,"POST","/api/v1/users/"+created.Account.ID+"/disable",nil,true)
 if r.Code!=200{t.Fatalf("disable failed: %d",r.Code)}
 if r:=request(t,handler,"GET","/health",nil,false);r.Code!=200{t.Fatalf("health failed: %d",r.Code)}
}
func TestRejectRemoteAdminListener(t *testing.T){
 for _,addr:=range []string{"0.0.0.0:19110","[::]:19110","vpn.example:19110"}{
  if isLocalListener(addr){t.Fatalf("public listener accepted: %s",addr)}
 }
 if !isLocalListener("127.0.0.1:19110")||!isLocalListener("[::1]:19110"){t.Fatal("loopback rejected")}
}

type mockEngine struct{add,remove int}
func(m *mockEngine)AddUser(_ context.Context,id,uuid string)error{m.add++;return nil}
func(m *mockEngine)RemoveUser(_ context.Context,id string)error{m.remove++;return nil}
func TestPanelProvisionsAndRevokesThroughAgent(t *testing.T){
 s,e:=controlplane.Open(filepath.Join(t.TempDir(),"integration.sqlite"))
 if e!=nil{t.Fatal(e)}
 defer s.Close()
 engine:=&mockEngine{}
 secret:=strings.Repeat("a",64)
 endpoint:=httptest.NewServer(&agenthttp.Handler{Token:secret,Engine:engine})
 defer endpoint.Close()
 parsed,e:=url.Parse(endpoint.URL);if e!=nil{t.Fatal(e)}
 handler:=&api{users:s,adminToken:strings.Repeat("S",64),agent:&agenthttp.LocalClient{Addr:parsed.Host,Token:secret}}
 r:=request(t,handler,"POST","/api/v1/users",[]byte(`{"Name":"friend-android","Device":"android","Days":30,"GB":5}`),true)
 if r.Code!=201{t.Fatalf("create: %d %s",r.Code,r.Body.String())}
 var result struct{Account controlplane.Account `json:"account"`;Provisioning string `json:"provisioning"`}
 if e:=json.Unmarshal(r.Body.Bytes(),&result);e!=nil{t.Fatal(e)}
 if !result.Account.Provisioned||result.Provisioning!="registered_by_agent"||engine.add!=1{t.Fatalf("agent did not actually accept account: %+v",result)}
 r=request(t,handler,"POST","/api/v1/users/"+result.Account.ID+"/disable",nil,true)
 if r.Code!=200||engine.remove!=1{t.Fatalf("agent revocation failed: HTTP %d removal=%d",r.Code,engine.remove)}
 rows,e:=s.List(context.Background());if e!=nil{t.Fatal(e)}
 if !rows[0].Disabled{t.Fatal("database account remained active after engine revocation")}
}

func TestSubscriptionGatesAndURIFormats(t *testing.T){
 db,e:=controlplane.Open(filepath.Join(t.TempDir(),"test-subs.sqlite"));if e!=nil{t.Fatal(e)}
 defer db.Close()
 ctx:=context.Background()
 node:=subscription.RealityNode{
  Name:"lab",Address:"203.0.113.10",Port:443,ServerName:"www.microsoft.com",
  PublicKey:base64.RawURLEncoding.EncodeToString(make([]byte,32)),ShortID:"0a12",
 }
 admin:=strings.Repeat("S",64)
 s,e:=db.Create(ctx,"friend-win","windows",30,5)
 _=s
 _=e
 acc,token,e:=db.Create(ctx,"friend-android","android",30,5)
 if e!=nil{t.Fatal(e)}
 h:=&api{users:db,adminToken:admin,node:&node,agent:&agenthttp.LocalClient{}}
 r:=request(t,h,"GET","/s/"+token,nil,false)
 if r.Code!=404{t.Fatalf("unprovisioned account leaked profile: %d",r.Code)}
 if e:=db.MarkProvisioned(ctx,acc.ID);e!=nil{t.Fatal(e)}
 r=request(t,h,"GET","/s/"+token,nil,false)
 if r.Code!=200||!strings.Contains(r.Body.String(),"vless://")||!strings.Contains(r.Body.String(),"security=reality"){
  t.Fatalf("invalid URI subscription: %d %s",r.Code,r.Body.String())
 }
 if r.Header().Get("Cache-Control")!="private, no-store"{t.Fatal("subscription was cacheable")}
 expected:=r.Body.String()
 r=request(t,h,"GET","/s/"+token+"?format=base64",nil,false)
 if r.Code!=200{t.Fatalf("base64 response %d",r.Code)}
 decoded,e:=base64.StdEncoding.DecodeString(r.Body.String())
 if e!=nil||string(decoded)!=expected{t.Fatalf("invalid base64 subscription: %s",r.Body.String())}
 r=request(t,h,"GET","/s/"+strings.Repeat("a",64),nil,false)
 if r.Code!=404{t.Fatal("unrecognized token was accepted")}
 if e:=db.Disable(ctx,acc.ID);e!=nil{t.Fatal(e)}
 r=request(t,h,"GET","/s/"+token,nil,false)
 if r.Code!=404{t.Fatal("revoked account subscription remained active")}
}
