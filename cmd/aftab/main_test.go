package main

import (
 "encoding/hex"
 "os"
 "path/filepath"
 "testing"
 "time"
)

func TestLoopbackOnly(t *testing.T) {
 allowed:=[]string{"127.0.0.1:18443","[::1]:18443"}
 blocked:=[]string{":18443","0.0.0.0:18443","[::]:18443","192.168.1.1:18443","example.com:18443","localhost:18443"}
 for _,addr:=range allowed {if !loopback(addr){t.Errorf("wanted accepted: %s",addr)}}
 for _,addr:=range blocked {if loopback(addr){t.Errorf("wanted rejected: %s",addr)}}
}
func TestTokenGeneration(t *testing.T){
 a,b:=newToken(),newToken()
 if len(a)!=64||a==b{t.Fatal("token generation failed")}
 if _,e:=hex.DecodeString(a);e!=nil{t.Fatal(e)}
}
func TestStorePersistsAndDisablesUser(t *testing.T){
 p:=filepath.Join(t.TempDir(),"state","users.json")
 s,e:=load(p);if e!=nil{t.Fatal(e)}
 tok:=newToken()
 s.mu.Lock()
 s.db.Users["tester"]=&User{Name:"tester",Token:tok,Expires:time.Now().Add(time.Hour).UTC().Format(time.RFC3339),QuotaBytes:1024}
 e=s.save();s.mu.Unlock();if e!=nil{t.Fatal(e)}
 fresh,e:=load(p);if e!=nil{t.Fatal(e)}
 if fresh.userFor(tok)!="tester"{t.Fatal("active token not accepted")}
 fresh.credit("tester",128)
 if fresh.db.Users["tester"].UsedBytes!=128{t.Fatal("usage not accounted")}
 fresh.mu.Lock();fresh.db.Users["tester"].Disabled=true;e=fresh.save();fresh.mu.Unlock()
 if e!=nil{t.Fatal(e)}
 if fresh.userFor(tok)!=""{t.Fatal("disabled user accepted")}
 info,e:=os.Stat(p);if e!=nil{t.Fatal(e)}
 if info.Mode().Perm()&0077!=0{t.Fatal("state file is accessible by other users")}
}
func TestExpiredAndExhaustedUsers(t *testing.T){
 s:=&store{db:database{Users:map[string]*User{}}}
 past:=newToken()
 s.db.Users["expired"]=&User{Token:past,Expires:time.Now().Add(-time.Hour).Format(time.RFC3339)}
 if s.userFor(past)!=""{t.Fatal("expired accepted")}
 quota:=newToken()
 s.db.Users["quota"]=&User{Token:quota,QuotaBytes:100,UsedBytes:100}
 if s.userFor(quota)!=""{t.Fatal("exhausted accepted")}
}
