package main

import (
 "crypto/ecdsa"
 "crypto/elliptic"
 "crypto/rand"
 "crypto/sha256"
 "crypto/subtle"
 "crypto/tls"
 "crypto/x509"
 "encoding/hex"
 "encoding/pem"
 "errors"
 "math/big"
 "net"
 "os"
 "path/filepath"
 "strconv"
 "sync"
 "time"

 "github.com/Zoupir/AFTAB/internal/dashboard"
)

type gatewayManager struct{
 mu sync.Mutex
 s *store
 directory string
 listener net.Listener
 addr, fingerprint, lastError string
}
func newGatewayManager(s *store,dbPath string)*gatewayManager{
 return &gatewayManager{s:s,directory:dbPath+".certs"}
}
func (g *gatewayManager) Status()dashboard.GatewayStatus{
 g.mu.Lock();defer g.mu.Unlock()
 return dashboard.GatewayStatus{Running:g.listener!=nil,Listen:g.addr,Fingerprint:g.fingerprint,LastError:g.lastError}
}
func(g *gatewayManager) Start(port int)error{
 if port<1024||port>65535{return errors.New("port out of lab range")}
 g.mu.Lock();defer g.mu.Unlock()
 if g.listener!=nil{return errors.New("gateway already running")}
 cert,key,e:=g.certificates();if e!=nil{g.lastError="certificate_error";return e}
 pair,e:=tls.LoadX509KeyPair(cert,key);if e!=nil{g.lastError="tls_certificate_error";return e}
 addr:=net.JoinHostPort("127.0.0.1",strconv.Itoa(port))
 ln,e:=tls.Listen("tcp",addr,&tls.Config{MinVersion:tls.VersionTLS13,Certificates:[]tls.Certificate{pair}})
 if e!=nil{g.lastError="bind_error";return e}
 pin:=sha256.Sum256(pair.Certificate[0])
 g.listener=ln;g.addr=addr;g.fingerprint=hex.EncodeToString(pin[:]);g.lastError=""
 go func(){
  e:=serveGateway(ln,g.s)
  g.mu.Lock();g.listener=nil
  if e!=nil{g.lastError="listener_error"}
  g.mu.Unlock()
  if e!=nil{event("error","gateway","listener_stopped","io_error")}
 }()
 return nil
}
func(g *gatewayManager) Test()error{
 info:=g.Status()
 if !info.Running{return errors.New("gateway not started")}
 expected,e:=hex.DecodeString(info.Fingerprint);if e!=nil{return e}
 config:=&tls.Config{MinVersion:tls.VersionTLS13,InsecureSkipVerify:true,VerifyPeerCertificate:func(raw [][]byte,_ [][]*x509.Certificate)error{
  if len(raw)==0{return errors.New("missing certificate")}
  got:=sha256.Sum256(raw[0]);if subtle.ConstantTimeCompare(got[:],expected)!=1{return errors.New("certificate pin mismatch")}
  return nil
 }}
 dialer:=&net.Dialer{Timeout:3*time.Second}
 c,e:=tls.DialWithDialer(dialer,"tcp",info.Listen,config)
 if e!=nil{return e}
 return c.Close()
}
func(g *gatewayManager)certificates()(string,string,error){
 if e:=os.MkdirAll(g.directory,0700);e!=nil{return "","",e}
 certPath:=filepath.Join(g.directory,"gateway.crt")
 keyPath:=filepath.Join(g.directory,"gateway.key")
 if _,e:=os.Stat(certPath);e==nil{
  if _,e=os.Stat(keyPath);e==nil{return certPath,keyPath,nil}
  return "","",errors.New("TLS key missing")
 }else if !errors.Is(e,os.ErrNotExist){return "","",e}
 if _,e:=os.Stat(keyPath);e==nil{return "","",errors.New("TLS certificate missing")}
 key,e:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader);if e!=nil{return "","",e}
 serial,e:=rand.Int(rand.Reader,new(big.Int).Lsh(big.NewInt(1),128));if e!=nil{return "","",e}
 tmpl:=&x509.Certificate{
  SerialNumber:serial,
  NotBefore:time.Now().Add(-time.Hour),
  NotAfter:time.Now().AddDate(0,1,0),
  KeyUsage:x509.KeyUsageDigitalSignature,
  ExtKeyUsage:[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
  DNSNames:[]string{"localhost"},
  IPAddresses:[]net.IP{net.ParseIP("127.0.0.1")},
  BasicConstraintsValid:true,
 }
 der,e:=x509.CreateCertificate(rand.Reader,tmpl,tmpl,&key.PublicKey,key);if e!=nil{return "","",e}
 pkcs8,e:=x509.MarshalPKCS8PrivateKey(key);if e!=nil{return "","",e}
 if e=os.WriteFile(keyPath,pem.EncodeToMemory(&pem.Block{Type:"PRIVATE KEY",Bytes:pkcs8}),0600);e!=nil{return "","",e}
 if e=os.WriteFile(certPath,pem.EncodeToMemory(&pem.Block{Type:"CERTIFICATE",Bytes:der}),0600);e!=nil{_ =os.Remove(keyPath);return "","",e}
 return certPath,keyPath,nil
}
