package main

import (
 "crypto/ed25519"
 "crypto/rand"
 "fmt"
 "io"
 "net"
 "os"
 "path/filepath"
 "strconv"
 "testing"
 "time"

 "golang.org/x/crypto/ssh"
 "golang.org/x/crypto/ssh/knownhosts"
)

// Proves the native tunnel handles password auth, known-host verification and
// SSH direct-tcpip forwarding with no ssh.exe, PowerShell or real internet.
func TestBuiltInSSHBridgeAndHostKeyPinning(t *testing.T) {
 home:=t.TempDir()
 t.Setenv("HOME",home)
 t.Setenv("USERPROFILE",home)
 if e:=os.MkdirAll(filepath.Join(home,".ssh"),0700);e!=nil{t.Fatal(e)}
 _,private,e:=ed25519.GenerateKey(rand.Reader)
 if e!=nil{t.Fatal(e)}
 signer,e:=ssh.NewSignerFromKey(private)
 if e!=nil{t.Fatal(e)}
 config:=&ssh.ServerConfig{PasswordCallback:func(conn ssh.ConnMetadata,password []byte)(*ssh.Permissions,error){
  if conn.User()=="testuser"&&string(password)=="correct-password"{return nil,nil}
  return nil,fmt.Errorf("invalid test credentials")
 }}
 config.AddHostKey(signer)
 sshServer,e:=net.Listen("tcp","127.0.0.1:0")
 if e!=nil{t.Fatal(e)}
 defer sshServer.Close()
 target,e:=net.Listen("tcp","127.0.0.1:0")
 if e!=nil{t.Fatal(e)}
 defer target.Close()
 go func(){
  for {conn,e:=target.Accept();if e!=nil{return}
   go func(){defer conn.Close();_,_=io.Copy(conn,conn)}()
  }
 }()
 go func(){
  for {
   wire,e:=sshServer.Accept()
   if e!=nil{return}
   go func(){
    sshConn,channels,requests,e:=ssh.NewServerConn(wire,config)
    if e!=nil{_ =wire.Close();return}
    defer sshConn.Close()
    go ssh.DiscardRequests(requests)
    for ch:=range channels{
     if ch.ChannelType()!="direct-tcpip"{_ =ch.Reject(ssh.UnknownChannelType,"unsupported");continue}
     var d struct{Address string;Port uint32;Origin string;OriginPort uint32}
     if e:=ssh.Unmarshal(ch.ExtraData(),&d);e!=nil{_ =ch.Reject(ssh.ConnectionFailed,"bad request");continue}
     expectedHost,expectedPort,_:=net.SplitHostPort(target.Addr().String())
     expectedPortNum,_:=strconv.Atoi(expectedPort)
     if d.Address!=expectedHost||int(d.Port)!=expectedPortNum{_ =ch.Reject(ssh.Prohibited,"wrong destination");continue}
     upstream,e:=net.Dial("tcp",target.Addr().String())
     if e!=nil{_ =ch.Reject(ssh.ConnectionFailed,"failed");continue}
     c,reqs,e:=ch.Accept()
     if e!=nil{_ =upstream.Close();continue}
     go ssh.DiscardRequests(reqs)
     go func(){
      defer upstream.Close();defer c.Close()
      go func(){_,_=io.Copy(upstream,c)}()
      _,_=io.Copy(c,upstream)
     }()
    }
   }()
  }
 }()
 host,sshPortStr,_:=net.SplitHostPort(sshServer.Addr().String())
 sshPort,_:=strconv.Atoi(sshPortStr)
 _,gatewayPortStr,_:=net.SplitHostPort(target.Addr().String())
 gatewayPort,_:=strconv.Atoi(gatewayPortStr)
 trust:=filepath.Join(home,".ssh","known_hosts")
 if e:=os.WriteFile(trust,[]byte(knownhosts.Line(knownhosts.Normalize(sshServer.Addr().String()),signer.PublicKey())+"\n"),0600);e!=nil{t.Fatal(e)}
 c:=clientConfig{SSHHost:host,SSHUser:"testuser",SSHPassword:"correct-password",SSHPort:sshPort,GatewayPort:gatewayPort}
 bridge,e:=startSSHBridge(c)
 if e!=nil{t.Fatalf("native verified SSH bootstrap failed: %v",e)}
 defer bridge.Close()
 if !bridge.remoteAlive(gatewayPort){t.Fatal("SSH gateway forwarding is unavailable")}
 local,e:=net.DialTimeout("tcp",bridge.gatewayAddress,2*time.Second)
 if e!=nil{t.Fatal(e)}
 defer local.Close()
 _=local.SetDeadline(time.Now().Add(4*time.Second))
 if _,e=local.Write([]byte("AFTAB-ONECLICK"));e!=nil{t.Fatal(e)}
 b:=make([]byte,len("AFTAB-ONECLICK"))
 if _,e=io.ReadFull(local,b);e!=nil{t.Fatal(e)}
 if string(b)!="AFTAB-ONECLICK"{t.Fatalf("wrong SSH forward response %q",string(b))}
 // An incorrect known_hosts entry must never silently authenticate.
 _,otherPrivate,_:=ed25519.GenerateKey(rand.Reader)
 otherSigner,_:=ssh.NewSignerFromKey(otherPrivate)
 if e:=os.WriteFile(trust,[]byte(knownhosts.Line(knownhosts.Normalize(sshServer.Addr().String()),otherSigner.PublicKey())+"\n"),0600);e!=nil{t.Fatal(e)}
 if _,e=dialVerifiedSSH(c);e==nil{t.Fatal("SSH host-key mismatch accepted")}
}
