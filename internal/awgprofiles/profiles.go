package awgprofiles

// Offline AmneziaWG 3.1 key and per-device profile builder.
// This package does not install or start a VPN server. Profiles become usable
// only after the associated peer has been provisioned on a matching server.
import (
 "crypto/ecdh"
 "crypto/rand"
 "encoding/base64"
 "errors"
 "fmt"
 "net"
 "regexp"
 "strconv"
 "strings"
)

type Mask struct {
 JunkCount int
 JunkMin int
 JunkMax int
 S1, S2, S3, S4 int
 HeaderProtectionKey string
 ContentPaddingAddition string
}

type Device struct {
 Label string
 IPv4 string
 PrivateKey string
 PublicKey string
}

type Server struct {
 Endpoint string
 Port int
 PublicKey string
 DNS string
 Mask Mask
}

var safeLabel=regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$`)
func generateKeypair()(string,string,error){
 secret,err:=ecdh.X25519().GenerateKey(rand.Reader)
 if err!=nil{return "","",err}
 return base64.StdEncoding.EncodeToString(secret.Bytes()),base64.StdEncoding.EncodeToString(secret.PublicKey().Bytes()),nil
}
func NewServerKeypair()(string,string,error){return generateKeypair()}
func NewMask()(Mask,error){
 b:=make([]byte,32)
 if _,e:=rand.Read(b);e!=nil{return Mask{},e}
 return Mask{JunkCount:5,JunkMin:40,JunkMax:120,S1:64,S2:64,S3:64,S4:64,HeaderProtectionKey:base64.StdEncoding.EncodeToString(b),ContentPaddingAddition:"32-128"},nil
}
func NewDevice(label string,hostNumber int)(Device,error){
 if !safeLabel.MatchString(label){return Device{},errors.New("device label must be 1-64 ASCII letters, digits, hyphen or underscore")}
 if hostNumber<2||hostNumber>254{return Device{},errors.New("unique device address must be within 10.96.0.2-254")}
 priv,pub,e:=generateKeypair()
 if e!=nil{return Device{},e}
 return Device{Label:label,IPv4:fmt.Sprintf("10.96.0.%d/32",hostNumber),PrivateKey:priv,PublicKey:pub},nil
}
func parseKey(key string)error{
 raw,e:=base64.StdEncoding.DecodeString(key)
 if e!=nil||len(raw)!=32{return errors.New("expected a base64-encoded 32-byte key")}
 return nil
}
func(m Mask)validate()error{
 if m.JunkCount<0||m.JunkCount>20||m.JunkMin<0||m.JunkMax>1400||m.JunkMin>m.JunkMax{return errors.New("invalid junk parameters")}
 if m.S1<12||m.S2<12||m.S3<12||m.S4<12||m.S1>300||m.S2>300||m.S3>300||m.S4>300{return errors.New("header protection needs bounded S1-S4 >=12")}
 if e:=parseKey(m.HeaderProtectionKey);e!=nil{return e}
 if m.ContentPaddingAddition!="32-128"{return errors.New("unsupported transport padding profile")}
 return nil
}
func(s Server)validate()error{
 if s.Port<1024||s.Port>65535{return errors.New("invalid UDP port")}
 if len(s.Endpoint)<1||len(s.Endpoint)>253||strings.ContainsAny(s.Endpoint,"\r\n\t ;[]/@\\") {return errors.New("invalid endpoint")}
 if net.ParseIP(s.Endpoint)==nil{
  for _,label:=range strings.Split(s.Endpoint,".") {if label==""||len(label)>63||!regexp.MustCompile(`^[a-zA-Z0-9-]+$`).MatchString(label){return errors.New("invalid endpoint hostname")}}
 }
 if e:=parseKey(s.PublicKey);e!=nil{return fmt.Errorf("server public key: %w",e)}
 if s.DNS==""||net.ParseIP(s.DNS)==nil{return errors.New("numeric DNS server required")}
 return s.Mask.validate()
}
func(d Device)validate()error{
 if !safeLabel.MatchString(d.Label){return errors.New("invalid device label")}
 if e:=parseKey(d.PrivateKey);e!=nil{return e}
 if e:=parseKey(d.PublicKey);e!=nil{return e}
 raw,_:=base64.StdEncoding.DecodeString(d.PrivateKey)
 priv,e:=ecdh.X25519().NewPrivateKey(raw)
 if e!=nil{return errors.New("invalid private peer key")}
 actual:=base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes())
 if actual!=d.PublicKey{return errors.New("peer keypair mismatch")}
 ip,network,e:=net.ParseCIDR(d.IPv4)
 if e!=nil{return errors.New("invalid peer subnet")}
 ip4:=ip.To4()
 ones,bits:=network.Mask.Size()
 if ip4==nil||ones!=32||bits!=32||ip4[0]!=10||ip4[1]!=96||ip4[2]!=0||ip4[3]<2||ip4[3]>254{return errors.New("invalid assigned peer /32")}
 return nil
}
func maskLines(m Mask)string {
 return fmt.Sprintf("Jc = %d\nJmin = %d\nJmax = %d\nS1 = %d\nS2 = %d\nS3 = %d\nS4 = %d\nH1 = 1\nH2 = 2\nH3 = 3\nH4 = 4\nHeaderProtectionKey = %s\nContentPaddingAddition = %s\n",m.JunkCount,m.JunkMin,m.JunkMax,m.S1,m.S2,m.S3,m.S4,m.HeaderProtectionKey,m.ContentPaddingAddition)
}
// ClientConfig renders a portable .conf for the *official* AmneziaWG 3.1
// Windows/Android applications. Not yet a working AFTAB backend install.
func ClientConfig(s Server,d Device)(string,error){
 if e:=s.validate();e!=nil{return "",e}
 if e:=d.validate();e!=nil{return "",e}
 endpoint:=net.JoinHostPort(s.Endpoint,strconv.Itoa(s.Port))
 return fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = %s\nDNS = %s\nMTU = 1280\n%s\n[Peer]\nPublicKey = %s\nEndpoint = %s\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n",d.PrivateKey,d.IPv4,s.DNS,maskLines(s.Mask),s.PublicKey,endpoint),nil
}
// ServerPeerEntry grants this device its unique /32 address on a
// separately configured AmneziaWG server. There is no shared user secret.
func ServerPeerEntry(d Device)(string,error){
 if e:=d.validate();e!=nil{return "",e}
 return fmt.Sprintf("[Peer]\n#_Name = %s\nPublicKey = %s\nAllowedIPs = %s\n",d.Label,d.PublicKey,d.IPv4),nil
}
