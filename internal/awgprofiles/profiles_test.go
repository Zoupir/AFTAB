package awgprofiles

import (
 "encoding/base64"
 "strings"
 "testing"
)

func testServer(t *testing.T)Server{
 t.Helper()
 _,pub,e:=NewServerKeypair()
 if e!=nil{t.Fatal(e)}
 mask,e:=NewMask()
 if e!=nil{t.Fatal(e)}
 return Server{Endpoint:"vpn.example.net",Port:31741,PublicKey:pub,DNS:"1.1.1.1",Mask:mask}
}
func TestIndependentPerDeviceKeypairs(t *testing.T){
 phone,e:=NewDevice("friend_phone",2);if e!=nil{t.Fatal(e)}
 pc,e:=NewDevice("friend_windows",3);if e!=nil{t.Fatal(e)}
 if phone.PrivateKey==pc.PrivateKey||phone.PublicKey==pc.PublicKey||phone.IPv4==pc.IPv4{t.Fatal("devices must not share keys or addresses")}
 s:=testServer(t)
 mobile,e:=ClientConfig(s,phone);if e!=nil{t.Fatal(e)}
 desktop,e:=ClientConfig(s,pc);if e!=nil{t.Fatal(e)}
 for _,required:=range []string{"HeaderProtectionKey = ","H1 = 1","H2 = 2","H3 = 3","H4 = 4","S1 = 64","ContentPaddingAddition = 32-128","AllowedIPs = 0.0.0.0/0, ::/0","Endpoint = vpn.example.net:31741"}{
  if !strings.Contains(mobile,required)||!strings.Contains(desktop,required){t.Fatalf("AWG 3.1 option missing from per-device profiles: %s",required)}
 }
 if strings.Contains(mobile,pc.PrivateKey)||strings.Contains(desktop,phone.PrivateKey){t.Fatal("device secret leaked into another export")}
 entry,e:=ServerPeerEntry(phone);if e!=nil{t.Fatal(e)}
 if strings.Contains(entry,phone.PrivateKey)||!strings.Contains(entry,phone.PublicKey){t.Fatal("server peer entry leaked client secret")}
 if _,e:=base64.StdEncoding.DecodeString(phone.PrivateKey);e!=nil{t.Fatal(e)}
}
func TestNewMaskIsUnique(t *testing.T){
 first,e:=NewMask();if e!=nil{t.Fatal(e)}
 next,e:=NewMask();if e!=nil{t.Fatal(e)}
 if first.HeaderProtectionKey==next.HeaderProtectionKey{t.Fatal("server installations shared header protection key")}
}
func TestRejectMalformedPeerDataAndInjection(t *testing.T){
 s:=testServer(t)
 d,e:=NewDevice("phone",2);if e!=nil{t.Fatal(e)}
 for _,badLabel:=range []string{"","bad\n[Peer]","a b","../private","a;rm"}{
  if _,e:=NewDevice(badLabel,2);e==nil{t.Fatalf("accepted unsafe label %q",badLabel)}
 }
 for _,host:=range []int{-1,0,1,255,256}{
  if _,e:=NewDevice("ok",host);e==nil{t.Fatalf("accepted invalid host %d",host)}
 }
 bad:=s;bad.Endpoint="host\nAllowedIPs = 0.0.0.0/0"
 if _,e:=ClientConfig(bad,d);e==nil{t.Fatal("endpoint injection accepted")}
 bad=s;bad.Mask.HeaderProtectionKey="short"
 if _,e:=ClientConfig(bad,d);e==nil{t.Fatal("short obfuscation key accepted")}
 bad=s;bad.Mask.S4=10
 if _,e:=ClientConfig(bad,d);e==nil{t.Fatal("unsafe insufficient S4 header padding accepted")}
 bad=s;bad.Port=80
 if _,e:=ClientConfig(bad,d);e==nil{t.Fatal("reserved port accepted")}
 badPeer:=d;badPeer.PrivateKey="not-base64"
 if _,e:=ClientConfig(s,badPeer);e==nil{t.Fatal("invalid private key accepted")}
}
