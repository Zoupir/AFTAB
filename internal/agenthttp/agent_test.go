package agenthttp

import(
 "context"
 "net/http"
 "net/http/httptest"
 "strings"
 "sync"
 "testing"
)
type fakeEngine struct{mu sync.Mutex;adds,removes int;id,uuid string;fail bool}
func(f *fakeEngine)AddUser(_ context.Context,id,uuid string)error{f.mu.Lock();defer f.mu.Unlock();f.adds++;f.id=id;f.uuid=uuid;return nil}
func(f *fakeEngine)RemoveUser(_ context.Context,id string)error{f.mu.Lock();defer f.mu.Unlock();f.removes++;f.id=id;return nil}
func TestAgentAuthAndDispatch(t *testing.T){
 secret:=strings.Repeat("z",64)
 engine:=&fakeEngine{}
 h:=&Handler{Token:secret,Engine:engine}
 id:="1a5bc922-c418-4985-a4da-8ce4de68f725"
 u:="872e14a6-1433-4753-b8cb-f194629e158a"
 call:=func(method,path,body,token string)*httptest.ResponseRecorder{
  r:=httptest.NewRequest(method,path,strings.NewReader(body))
  if token!=""{r.Header.Set("Authorization","Bearer "+token)}
  w:=httptest.NewRecorder();h.ServeHTTP(w,r);return w
 }
 payload:=`{"id":"`+id+`","uuid":"`+u+`"}`
 if r:=call("POST","/v1/users",payload,"");r.Code!=401{t.Fatalf("missing token passed: %d",r.Code)}
 if r:=call("POST","/v1/users",payload,"invalid");r.Code!=401{t.Fatal("bad token passed")}
 if r:=call("POST","/v1/users",payload,secret);r.Code!=200{t.Fatalf("add: %d %s",r.Code,r.Body.String())}
 if engine.id!=id||engine.uuid!=u||engine.adds!=1{t.Fatal("add not dispatched once")}
 if r:=call("POST","/v1/users/"+id+"/disable","",secret);r.Code!=200{t.Fatalf("remove: %d %s",r.Code,r.Body.String())}
 if engine.removes!=1{t.Fatal("remove not dispatched")}
 if r:=call("POST","/v1/users",payload+"{}",secret);r.Code!=400{t.Fatal("extra JSON document accepted")}
}
func TestAgentRejectsRemoteListener(t *testing.T){
 for _,addr:=range []string{"0.0.0.0:19111","example.com:19111","69.169.109.229:19111"}{
  if Loopback(addr){t.Fatalf("unsafe listener accepted: %s",addr)}
 }
 if !Loopback("127.0.0.1:19111"){t.Fatal("valid listener rejected")}
 r:=httptest.NewRequest("GET","/health",nil);r.RemoteAddr="192.0.2.2:8812"
 w:=httptest.NewRecorder();(&Handler{}).ServeHTTP(w,r)
 if w.Code!=http.StatusForbidden{t.Fatal("remote client accepted")}
}
