package main

import (
 "bytes"
 "errors"
 "path/filepath"
 "sync"
 "testing"
 "time"
)

func TestHardQuotaEnforcedDuringWrites(t *testing.T){
 s,e:=load(filepath.Join(t.TempDir(),"users.json"));if e!=nil{t.Fatal(e)}
 s.mu.Lock()
 s.db.Users["test"]=&User{Name:"test",Token:newToken(),QuotaBytes:100,Expires:time.Now().Add(time.Hour).Format(time.RFC3339)}
 s.mu.Unlock()
 var out bytes.Buffer
 w:=accountedWriter{writer:&out,store:s,id:"test"}
 n,e:=w.Write(make([]byte,90));if n!=90||e!=nil{t.Fatalf("first write: %d %v",n,e)}
 n,e=w.Write(make([]byte,30))
 if n!=10||!errors.Is(e,errUsageLimit){t.Fatalf("quota bypass: %d %v",n,e)}
 n,e=w.Write([]byte("x"))
 if n!=0||!errors.Is(e,errUsageLimit){t.Fatal("write accepted after quota exhausted")}
 s.flushTraffic()
 reloaded,e:=load(s.path);if e!=nil{t.Fatal(e)}
 if reloaded.db.Users["test"].UsedBytes!=100||out.Len()!=100{t.Fatal("quota usage not accurate after reload")}
}
func TestConcurrentQuotaCannotBeExceeded(t *testing.T){
 s,e:=load(filepath.Join(t.TempDir(),"users.json"));if e!=nil{t.Fatal(e)}
 s.mu.Lock()
 s.db.Users["many"]=&User{Name:"many",Token:newToken(),QuotaBytes:8192,Expires:time.Now().Add(time.Hour).Format(time.RFC3339)}
 s.mu.Unlock()
 var wg sync.WaitGroup
 for i:=0;i<20;i++{
  wg.Add(1)
  go func(){
   defer wg.Done()
   _=func()error{
    writer:=accountedWriter{writer:&bytes.Buffer{},store:s,id:"many"}
    for j:=0;j<20;j++{if _,e:=writer.Write(make([]byte,256));e!=nil{return e}}
    return nil
   }()
  }()
 }
 wg.Wait();s.flushTraffic()
 s.mu.Lock();used:=s.db.Users["many"].UsedBytes;s.mu.Unlock()
 if used!=8192{t.Fatalf("expected exactly 8192 bytes, got %d",used)}
}
func TestDisabledOrExpiredConnectionCannotContinue(t *testing.T){
 s,e:=load(filepath.Join(t.TempDir(),"users.json"));if e!=nil{t.Fatal(e)}
 s.mu.Lock()
 s.db.Users["disabled"]=&User{Name:"disabled",Disabled:true}
 s.db.Users["expired"]=&User{Name:"expired",Expires:time.Now().Add(-time.Second).Format(time.RFC3339)}
 s.mu.Unlock()
 for _,id:=range []string{"disabled","expired"}{
  writer:=accountedWriter{writer:&bytes.Buffer{},store:s,id:id}
  if n,e:=writer.Write([]byte("blocked"));n!=0||!errors.Is(e,errUsageLimit){t.Fatalf("%s bypassed controls",id)}
 }
}
