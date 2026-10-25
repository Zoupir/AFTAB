package main

import (
 "errors"
 "io"
 "net"
 "sync"
 "time"
)

var errUsageLimit=errors.New("account_expired_disabled_or_quota_exhausted")

// Traffic is reserved before delivery across both directions, so
// concurrent streams cannot bypass a shared account quota.
func(s *store) reserveTraffic(id string,requested int)(int,error){
 if requested<=0{return 0,nil}
 s.mu.Lock();defer s.mu.Unlock()
 u:=s.db.Users[id]
 if u==nil||u.Disabled{return 0,errUsageLimit}
 if u.Expires!=""{
  expires,e:=time.Parse(time.RFC3339,u.Expires)
  if e!=nil||!time.Now().Before(expires){return 0,errUsageLimit}
 }
 granted:=requested
 if u.QuotaBytes>0{
  left:=u.QuotaBytes-u.UsedBytes
  if left<=0{return 0,errUsageLimit}
  if int64(granted)>left{granted=int(left)}
 }
 u.UsedBytes+=int64(granted)
 s.pendingBytes+=int64(granted)
 if s.pendingBytes>=1024*1024||time.Since(s.lastSave)>=time.Second{
  if e:=s.save();e!=nil{
   u.UsedBytes-=int64(granted);s.pendingBytes-=int64(granted)
   return 0,e
  }
  s.pendingBytes=0;s.lastSave=time.Now()
 }
 return granted,nil
}
func(s *store)refundTraffic(id string,refunded int){
 if refunded<=0{return}
 s.mu.Lock();defer s.mu.Unlock()
 if u:=s.db.Users[id];u!=nil{
  u.UsedBytes-=int64(refunded)
  if u.UsedBytes<0{u.UsedBytes=0}
  s.pendingBytes+=int64(refunded)
 }
}
func(s *store)flushTraffic(){
 s.mu.Lock();defer s.mu.Unlock()
 if s.pendingBytes!=0{
  if e:=s.save();e!=nil{event("error","quota","persist_failed","store_error")
  }else{s.pendingBytes=0;s.lastSave=time.Now()}
 }
}
type accountedWriter struct{
 writer io.Writer
 store *store
 id string
}
func(w accountedWriter)Write(p []byte)(int,error){
 reserved,e:=w.store.reserveTraffic(w.id,len(p))
 if e!=nil{return 0,e}
 if reserved==0{return 0,errUsageLimit}
 n,e:=w.writer.Write(p[:reserved])
 if n<0||n>reserved{return 0,io.ErrShortWrite}
 if n<reserved{w.store.refundTraffic(w.id,reserved-n)}
 if e!=nil{return n,e}
 if n<len(p){return n,errUsageLimit}
 return n,nil
}
func relayAccounted(c net.Conn,reader io.Reader,up net.Conn,s *store,id string){
 var wg sync.WaitGroup
 wg.Add(2)
 forward:=func(dst net.Conn,src io.Reader){
  defer wg.Done()
  _,e:=io.Copy(accountedWriter{writer:dst,store:s,id:id},src)
  if e!=nil&&errors.Is(e,errUsageLimit){
   event("info","quota","stream_closed","limit_reached")
   _=c.Close();_ =up.Close()
  }else if w,ok:=dst.(interface{CloseWrite()error});ok{_ =w.CloseWrite()}
 }
 go forward(up,reader)
 go forward(c,up)
 wg.Wait()
 s.flushTraffic()
}
