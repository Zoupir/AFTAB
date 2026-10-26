package subscription

// Client-side renderers for already-provisioned VLESS + REALITY + Vision
// peers. This package does NOT create, install or modify an Xray inbound.
// The control plane must confirm Xray provisioning before publishing links.
import (
 "encoding/base64"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "net"
 "net/url"
 "regexp"
 "strconv"
 "strings"
)

type RealityNode struct {
 Name string `json:"name"`
 Address string `json:"address"`
 Port int `json:"port"`
 ServerName string `json:"server_name"`
 PublicKey string `json:"public_key"`
 ShortID string `json:"short_id"`
}
var (
 hostname=regexp.MustCompile(`^[a-zA-Z0-9.-]{1,253}$`)
 name=regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$`)
 uuid=regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89aAbB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$`)
)
func validHost(v string)bool {
 if net.ParseIP(v)!=nil{return true}
 if !hostname.MatchString(v)||strings.HasPrefix(v,".")||strings.HasSuffix(v,".")||strings.Contains(v,".."){return false}
 for _,part:=range strings.Split(v,"."){if len(part)==0||len(part)>63||strings.HasPrefix(part,"-")||strings.HasSuffix(part,"-"){return false}}
 return true
}
func(n RealityNode)Validate()error{
 if !name.MatchString(n.Name)||!validHost(n.Address)||!validHost(n.ServerName)||n.Port<1||n.Port>65535{return errors.New("invalid node name, address, SNI or port")}
 b,e:=base64.RawURLEncoding.DecodeString(n.PublicKey)
 if e!=nil||len(b)!=32{return errors.New("REALITY public key must be 32 bytes, base64url")}
 if len(n.ShortID)>16||len(n.ShortID)%2!=0{return errors.New("short ID must be 0-16 even-length hex characters")}
 if _,e=hex.DecodeString(n.ShortID);e!=nil{return errors.New("short ID must be hexadecimal")}
 return nil
}
func VLESSURI(n RealityNode,peerUUID string)(string,error){
 if e:=n.Validate();e!=nil{return "",e}
 if !uuid.MatchString(peerUUID){return "",errors.New("invalid VLESS UUID")}
 u:=url.URL{Scheme:"vless",User:url.User(peerUUID),Host:net.JoinHostPort(n.Address,strconv.Itoa(n.Port)),Fragment:"AFTAB-"+n.Name}
 q:=url.Values{}
 q.Set("type","tcp")
 q.Set("security","reality")
 q.Set("encryption","none")
 q.Set("flow","xtls-rprx-vision")
 q.Set("sni",n.ServerName)
 q.Set("fp","chrome")
 q.Set("pbk",n.PublicKey)
 q.Set("sid",n.ShortID)
 u.RawQuery=q.Encode()
 return u.String(),nil
}
func SingBoxOutbounds(nodes []RealityNode,peerUUID string)([]byte,error){
 if !uuid.MatchString(peerUUID){return nil,errors.New("invalid VLESS UUID")}
 if len(nodes)<1||len(nodes)>20{return nil,errors.New("at least one and at most 20 nodes required")}
 type TLS struct{
  Enabled bool `json:"enabled"`
  ServerName string `json:"server_name"`
  UTLS map[string]any `json:"utls"`
  Reality map[string]any `json:"reality"`
 }
 type Outbound struct{
  Type string `json:"type"`
  Tag string `json:"tag"`
  Server string `json:"server,omitempty"`
  ServerPort int `json:"server_port,omitempty"`
  UUID string `json:"uuid,omitempty"`
  Flow string `json:"flow,omitempty"`
  TLS *TLS `json:"tls,omitempty"`
  Outbounds []string `json:"outbounds,omitempty"`
  URL string `json:"url,omitempty"`
  Interval string `json:"interval,omitempty"`
 }
 payload:=struct{Outbounds []Outbound `json:"outbounds"`}{}
 seen:=make(map[string]bool,len(nodes))
 tags:=make([]string,0,len(nodes))
 for _,n:=range nodes{
  if e:=n.Validate();e!=nil{return nil,fmt.Errorf("node %s: %w",n.Name,e)}
  if seen[n.Name]{return nil,errors.New("duplicate node name")}
  seen[n.Name]=true
  tag:="AFTAB-"+n.Name
  tags=append(tags,tag)
  payload.Outbounds=append(payload.Outbounds,Outbound{Type:"vless",Tag:tag,Server:n.Address,ServerPort:n.Port,UUID:peerUUID,Flow:"xtls-rprx-vision",TLS:&TLS{
   Enabled:true,ServerName:n.ServerName,
   UTLS:map[string]any{"enabled":true,"fingerprint":"chrome"},
   Reality:map[string]any{"enabled":true,"public_key":n.PublicKey,"short_id":n.ShortID},
  }})
 }
 if len(tags)>1{payload.Outbounds=append(payload.Outbounds,Outbound{Type:"urltest",Tag:"AFTAB-auto",Outbounds:tags,URL:"https://www.gstatic.com/generate_204",Interval:"3m"})}
 return json.MarshalIndent(payload,"","  ")
}
