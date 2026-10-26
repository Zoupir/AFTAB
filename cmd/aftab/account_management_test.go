package main

import (
 "net"
 "os"
 "path/filepath"
 "strings"
 "testing"
 "time"
)

func TestAccountLifecycleAndNoTokenDisclosure(t *testing.T){
 storePath:=filepath.Join(t.TempDir(),"users.json")
 s,e:=load(storePath);if e!=nil{t.Fatal(e)}
 b:=accountBackend{s:s}
 token,e:=b.CreateUser("mobileUser",30,30);if e!=nil{t.Fatal(e)}
 raw,e:=os.ReadFile(storePath);if e!=nil{t.Fatal(e)}
 if strings.Contains(string(raw),token){t.Fatal("raw account token persisted")}
 if s.userFor(token)!="mobileUser"{t.Fatal("new account cannot log in")}
 s.credit("mobileUser",256)
 if e:=b.ResetUsage("mobileUser");e!=nil{t.Fatal(e)}
 if s.db.Users["mobileUser"].UsedBytes!=0{t.Fatal("usage not reset")}
 prevQuota:=s.db.Users["mobileUser"].QuotaBytes
 prevExpiry,_:=time.Parse(time.RFC3339,s.db.Users["mobileUser"].Expires)
 if e:=b.ExtendUser("mobileUser",10,5);e!=nil{t.Fatal(e)}
 if s.db.Users["mobileUser"].QuotaBytes!=prevQuota+5*gib{t.Fatal("quota not extended")}
 newExpiry,_:=time.Parse(time.RFC3339,s.db.Users["mobileUser"].Expires)
 if !newExpiry.After(prevExpiry){t.Fatal("expiry not extended")}
 if e:=b.UpdateUser("mobileUser","renamed",60,40);e!=nil{t.Fatal(e)}
 if s.userFor(token)!="renamed"{t.Fatal("rename broke authorization")}
 if s.db.Users["renamed"].DurationDays!=60{t.Fatal("duration not updated")}
 if e:=b.ResetTime("renamed");e!=nil{t.Fatal(e)}
 if e:=b.SetUserEnabled("renamed",false);e!=nil{t.Fatal(e)}
 if s.userFor(token)!=""{t.Fatal("disabled account accepted")}
 if e:=b.SetUserEnabled("renamed",true);e!=nil{t.Fatal(e)}
 if s.userFor(token)!="renamed"{t.Fatal("resumed user rejected")}
 rotated,e:=b.RotateToken("renamed");if e!=nil{t.Fatal(e)}
 if rotated==token||s.userFor(token)!=""||s.userFor(rotated)!="renamed"{t.Fatal("token rotation failed")}
 if e:=b.DeleteUser("renamed");e!=nil{t.Fatal(e)}
 if s.userFor(rotated)!=""{t.Fatal("deleted user accepted")}
 fresh,e:=load(storePath);if e!=nil{t.Fatal(e)}
 if len(fresh.db.Users)!=0{t.Fatal("deletion was not persisted")}
}

func TestDisablingAndRotatingDisconnectsActiveAccount(t *testing.T){
 s,e:=load(filepath.Join(t.TempDir(),"users.json"));if e!=nil{t.Fatal(e)}
 b:=accountBackend{s:s}
 if _,e=b.CreateUser("u1",30,30);e!=nil{t.Fatal(e)}
 a,peer:=net.Pipe();defer peer.Close()
 if !s.trackUserConn("u1",a){t.Fatal("could not track client")}
 if e=b.SetUserEnabled("u1",false);e!=nil{t.Fatal(e)}
 if _,e=peer.Write([]byte("hello"));e==nil{t.Fatal("disabled account connection remained open")}
 if e=b.SetUserEnabled("u1",true);e!=nil{t.Fatal(e)}
 other,peer2:=net.Pipe();defer peer2.Close()
 if !s.trackUserConn("u1",other){t.Fatal("could not track second client")}
 if _,e=b.RotateToken("u1");e!=nil{t.Fatal(e)}
 if _,e=peer2.Write([]byte("hello"));e==nil{t.Fatal("rotated account kept an active connection")}
}
