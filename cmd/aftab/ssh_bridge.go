package main

// Built-in SSH transport for the Windows desktop controller. AFTAB stays bound
// to loopback on the VPS; no extra firewall rules, PowerShell, or ssh.exe needed.
import (
 "errors"
 "fmt"
 "io"
 "net"
 "os"
 "path/filepath"
 "strconv"
 "strings"
 "sync"
 "time"

 "golang.org/x/crypto/ssh"
 "golang.org/x/crypto/ssh/knownhosts"
)

type sshBridge struct {
 mu sync.Mutex
 client *ssh.Client
 gateway net.Listener
 admin net.Listener
 closed bool
 gatewayAddress string
}

func sshBridgeConfigValid(c clientConfig) error {
 if c.SSHHost=="" {return nil}
 host:=strings.TrimSpace(c.SSHHost)
 if host!=c.SSHHost || len(host)>253 || strings.ContainsAny(host," \t\r\n/:\\") {return errors.New("invalid SSH host")}
 if c.SSHUser=="" || len(c.SSHUser)>64 || strings.ContainsAny(c.SSHUser," \t\r\n") {return errors.New("invalid SSH username")}
 if c.SSHPort==0 || c.SSHPort>65535 {return errors.New("invalid SSH port")}
 if c.GatewayPort<1024 || c.GatewayPort>65535 {return errors.New("invalid remote gateway port")}
 if len(c.SSHPassword)<1 || len(c.SSHPassword)>512 {return errors.New("SSH password required")}
 return nil
}

func dialVerifiedSSH(c clientConfig)(*ssh.Client,error) {
 if e:=sshBridgeConfigValid(c);e!=nil{return nil,e}
 home,e:=os.UserHomeDir()
 if e!=nil{return nil,errors.New("Windows SSH host trust file unavailable")}
 trustFile:=filepath.Join(home,".ssh","known_hosts")
 cb,e:=knownhosts.New(trustFile)
 if e!=nil{return nil,errors.New("SSH host key not trusted: first verify VPS with Windows ssh once")}
 address:=net.JoinHostPort(c.SSHHost,strconv.Itoa(c.SSHPort))
 cfg:=&ssh.ClientConfig{
  User:c.SSHUser,
  Auth:[]ssh.AuthMethod{ssh.Password(c.SSHPassword),ssh.KeyboardInteractive(func(_ string,_ string,questions []string,_ []bool)([]string,error){
   answers:=make([]string,len(questions))
   for i:=range questions{answers[i]=c.SSHPassword}
   return answers,nil
  })},
  HostKeyCallback:cb,
  Timeout:10*time.Second,
 }
 client,e:=ssh.Dial("tcp",address,cfg)
 if e!=nil {return nil,fmt.Errorf("SSH verification/login failed: %w",e)}
 return client,nil
}

func startSSHBridge(c clientConfig)(*sshBridge,error) {
 client,e:=dialVerifiedSSH(c)
 if e!=nil{return nil,e}
 listener,e:=net.Listen("tcp","127.0.0.1:0")
 if e!=nil{_ =client.Close();return nil,errors.New("cannot allocate local secure tunnel port")}
 b:=&sshBridge{client:client,gateway:listener,gatewayAddress:listener.Addr().String()}
 destination:=net.JoinHostPort("127.0.0.1",strconv.Itoa(c.GatewayPort))
 go b.forward(listener,destination)
 // Forward the existing local-only server panel too, when free.
 // A pre-existing SSH forwarding on 19090 is not a fatal error.
 if a,e:=net.Listen("tcp","127.0.0.1:19090");e==nil{
  b.admin=a
  go b.forward(a,"127.0.0.1:19090")
 }
 return b,nil
}
func (b *sshBridge) forward(listener net.Listener,destination string){
 for {
  incoming,e:=listener.Accept()
  if e!=nil{return}
  go func(){
   b.mu.Lock();cl:=b.client;isClosed:=b.closed;b.mu.Unlock()
   if isClosed||cl==nil{_ =incoming.Close();return}
   upstream,e:=cl.Dial("tcp",destination)
   if e!=nil{_ =incoming.Close();return}
   go func(){_,_=io.Copy(upstream,incoming);if x,ok:=upstream.(interface{CloseWrite()error});ok{_=x.CloseWrite()}else{_=upstream.Close()}}()
   _,_=io.Copy(incoming,upstream)
   _=upstream.Close()
   _=incoming.Close()
  }()
 }
}
func (b *sshBridge) Close(){
 if b==nil{return}
 b.mu.Lock()
 if b.closed{b.mu.Unlock();return}
 b.closed=true
 gateway,admin,client:=b.gateway,b.admin,b.client
 b.mu.Unlock()
 if gateway!=nil{_=gateway.Close()}
 if admin!=nil{_=admin.Close()}
 if client!=nil{_=client.Close()}
}
func (b *sshBridge) remoteAlive(port int)bool{
 if b==nil{return true}
 b.mu.Lock();cl:=b.client;closed:=b.closed;b.mu.Unlock()
 if closed||cl==nil{return false}
 conn,e:=cl.Dial("tcp",net.JoinHostPort("127.0.0.1",strconv.Itoa(port)))
 if e!=nil{return false}
 _=conn.Close()
 return true
}
