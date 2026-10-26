package main

import(
 "context"
 "encoding/json"
 "net/http/httptest"
 "net/url"
 "os"
 "path/filepath"
 "strings"
 "testing"
 "time"

 "github.com/Zoupir/AFTAB/internal/agenthttp"
 "github.com/Zoupir/AFTAB/internal/controlplane"
 "github.com/Zoupir/AFTAB/internal/xrayapi"
)

// TestLiveXrayProvisioningLifecycle only executes in CI with an ephemeral,
// isolated Xray-core container. The default test suite never contacts a VPS.
func TestLiveXrayProvisioningLifecycle(t *testing.T){
 addr:=os.Getenv("AFTAB_TEST_XRAY_API")
 tag:=os.Getenv("AFTAB_TEST_XRAY_INBOUND")
 if addr==""||tag==""{t.Skip("requires isolated Xray CI test environment")}
 engine:=xrayapi.Client{Address:addr,InboundTag:tag}
 secret:=strings.Repeat("R",64)
 agent:=httptest.NewServer(&agenthttp.Handler{Token:secret,Engine:engine})
 defer agent.Close()
 uri,e:=url.Parse(agent.URL);if e!=nil{t.Fatal(e)}
 db,e:=controlplane.Open(filepath.Join(t.TempDir(),"live-xray.sqlite"));if e!=nil{t.Fatal(e)}
 defer db.Close()
 panel:=&api{users:db,adminToken:strings.Repeat("S",64),agent:&agenthttp.LocalClient{Addr:uri.Host,Token:secret}}
 created:=request(t,panel,"POST","/api/v1/users",[]byte(`{"Name":"real-xray-android","Device":"android","Days":30,"GB":5}`),true)
 if created.Code!=201{t.Fatalf("panel creation failed HTTP %d %s",created.Code,created.Body.String())}
 var result struct{Account controlplane.Account `json:"account"`;Provisioning string `json:"provisioning"`;SubscriptionToken string `json:"subscription_token_once"`}
 if e:=json.Unmarshal(created.Body.Bytes(),&result);e!=nil{t.Fatal(e)}
 if result.Provisioning!="registered_by_agent"||!result.Account.Provisioned{
  t.Fatalf("agent did not accept real Xray user: state=%s",result.Provisioning)
 }
 ctx,cancel:=context.WithTimeout(context.Background(),8*time.Second);defer cancel()
 foundUUID,found,e:=engine.GetUserUUID(ctx,result.Account.ID)
 if e!=nil{t.Fatalf("GetInboundUsers after adding real Xray user: %v",e)}
 if !found||foundUUID!=result.Account.UUID{t.Fatal("actual Xray user UUID did not match created account")}
 if _,e:=db.LookupSubscription(ctx,result.SubscriptionToken);e!=nil{t.Fatalf("valid new subscription not recognized: %v",e)}
 disabled:=request(t,panel,"POST","/api/v1/users/"+result.Account.ID+"/disable",nil,true)
 if disabled.Code!=200{t.Fatalf("real Xray removal request failed %d %s",disabled.Code,disabled.Body.String())}
 _,found,e=engine.GetUserUUID(ctx,result.Account.ID)
 if e==nil&&found{t.Fatal("user still present after revocation")}
 user,e:=db.Get(ctx,result.Account.ID)
 if e!=nil||!user.Disabled{t.Fatalf("database revocation not persisted: %v",e)}
 if _,e:=db.LookupSubscription(ctx,result.SubscriptionToken);e==nil{t.Fatal("revoked subscription still accepted")}
 t.Log("REAL Xray HandlerService add, query, remove succeeded")
}
