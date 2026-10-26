package agenthttp

// LocalClient is the panel-side API for a separately managed AFTAB agent.
// Authentication is a scoped bearer secret, and transport is loopback only.
// Multi-node remote transport requires mutual TLS and separate authorization.
import (
 "bytes"
 "context"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "net/http"
 "strings"
 "time"
)
type LocalClient struct{
 Addr string
 Token string
 HTTP *http.Client
}
func(c LocalClient)validate()error{
 if !Loopback(c.Addr)||len(c.Token)<32||len(c.Token)>512{return errors.New("invalid local agent settings")}
 return nil
}
func(c LocalClient)post(ctx context.Context,path string,payload any)error{
 if e:=c.validate();e!=nil{return e}
 var data []byte
 if payload!=nil{data,_=json.Marshal(payload)}
 req,e:=http.NewRequestWithContext(ctx,"POST","http://"+c.Addr+path,bytes.NewReader(data))
 if e!=nil{return e}
 req.Header.Set("Authorization","Bearer "+c.Token)
 req.Header.Set("Content-Type","application/json")
 client:=c.HTTP
 if client==nil{client=&http.Client{Timeout:7*time.Second}}
 resp,e:=client.Do(req)
 if e!=nil{return errors.New("agent_connection_unavailable")}
 defer resp.Body.Close()
 _,_=io.Copy(io.Discard,io.LimitReader(resp.Body,1024))
 if resp.StatusCode!=200{return fmt.Errorf("agent_rejected_operation_http_%d",resp.StatusCode)}
 return nil
}
func(c LocalClient)AddUser(ctx context.Context,id,uuid string)error{
 return c.post(ctx,"/v1/users",map[string]string{"id":id,"uuid":uuid})
}
func(c LocalClient)RemoveUser(ctx context.Context,id string)error{
 if strings.ContainsAny(id,"/\\")||len(id)!=36{return errors.New("invalid id")}
 return c.post(ctx,"/v1/users/"+id+"/disable",nil)
}
func ValidateLocalClient(c LocalClient)error{return c.validate()}
