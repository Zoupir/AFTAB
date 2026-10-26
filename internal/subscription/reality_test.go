package subscription

import(
 "encoding/base64"
 "encoding/json"
 "net/url"
 "strings"
 "testing"
)
func node(name,addr string)RealityNode{
 return RealityNode{Name:name,Address:addr,Port:443,ServerName:"www.example.org",PublicKey:base64.RawURLEncoding.EncodeToString(make([]byte,32)),ShortID:"0a12"}
}
func TestVLESSAndSingBoxRenderer(t *testing.T){
 n:=node("newjersey","69.169.109.229")
 uuid:="1a5bc922-c418-4985-a4da-8ce4de68f725"
 value,e:=VLESSURI(n,uuid);if e!=nil{t.Fatal(e)}
 u,e:=url.Parse(value);if e!=nil{t.Fatal(e)}
 if u.Scheme!="vless"||u.User.Username()!=uuid||u.Host!="69.169.109.229:443"||u.Query().Get("security")!="reality"||u.Query().Get("pbk")!=n.PublicKey||u.Query().Get("flow")!="xtls-rprx-vision"{t.Fatalf("invalid VLESS URI %s",value)}
 n2:=node("secondary","vpn.example.net")
 result,e:=SingBoxOutbounds([]RealityNode{n,n2},uuid);if e!=nil{t.Fatal(e)}
 var out struct{Outbounds []map[string]any `json:"outbounds"`}
 if e=json.Unmarshal(result,&out);e!=nil{t.Fatal(e)}
 if len(out.Outbounds)!=3||out.Outbounds[2]["type"]!="urltest"{t.Fatalf("missing urltest group: %s",result)}
 tags:=out.Outbounds[2]["outbounds"].([]any)
 if len(tags)!=2||tags[0]!="AFTAB-newjersey"||tags[1]!="AFTAB-secondary"{t.Fatalf("invalid urltest members: %v",tags)}
 tls:=out.Outbounds[0]["tls"].(map[string]any)
 reality:=tls["reality"].(map[string]any)
 if reality["public_key"]!=n.PublicKey||reality["short_id"]!=n.ShortID{t.Fatal("broken REALITY handshake parameters")}
 if strings.Contains(string(result),"private_key"){t.Fatal("private key leaked into client JSON")}
}
func TestRejectInvalidRealityParameters(t *testing.T){
 uuid:="1a5bc922-c418-4985-a4da-8ce4de68f725"
 n:=node("friend","vpn.example.net")
 for _,bad:=range []RealityNode{
  func()RealityNode{v:=n;v.Address="bad\nX-Secret: xyz";return v}(),
  func()RealityNode{v:=n;v.PublicKey="too-short";return v}(),
  func()RealityNode{v:=n;v.ShortID="0X12";return v}(),
  func()RealityNode{v:=n;v.Name="../../";return v}(),
  func()RealityNode{v:=n;v.ServerName="a..com";return v}(),
  func()RealityNode{v:=n;v.Port=70000;return v}(),
 }{
  if _,e:=VLESSURI(bad,uuid);e==nil{t.Fatalf("accepted invalid node: %+v",bad)}
 }
 if _,e:=VLESSURI(n,"not-a-uuid");e==nil{t.Fatal("invalid UUID accepted")}
 if _,e:=SingBoxOutbounds([]RealityNode{n,n},uuid);e==nil{t.Fatal("duplicate node allowed")}
 if _,e:=SingBoxOutbounds(nil,uuid);e==nil{t.Fatal("empty node list allowed")}
}
