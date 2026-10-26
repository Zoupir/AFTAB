package main

import (
 "bytes"
 "encoding/json"
 "net/http"
 "net/http/httptest"
 "path/filepath"
 "strings"
 "testing"

 "github.com/Zoupir/AFTAB/internal/controlplane"
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
 if len(created.SubscriptionToken)!=64||created.Provisioning!="pending_engine_integration"{t.Fatal("incorrect pending provisioning response")}
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
