package main

import (
 "errors"
 "time"

 "github.com/Zoupir/AFTAB/internal/dashboard"
)

type accountBackend struct{ s *store }
func(b accountBackend) ListUsers()[]dashboard.User{
 b.s.mu.Lock();defer b.s.mu.Unlock()
 out:=make([]dashboard.User,0,len(b.s.db.Users))
 for _,u:=range b.s.db.Users{
  out=append(out,dashboard.User{Name:u.Name,Expires:u.Expires,QuotaBytes:u.QuotaBytes,UsedBytes:u.UsedBytes,Disabled:u.Disabled})
 }
 return out
}
func(b accountBackend) CreateUser(name string,days int,gb int64)(string,error){
 b.s.mu.Lock();defer b.s.mu.Unlock()
 if _,ok:=b.s.db.Users[name];ok{return "",errors.New("duplicate account")}
 token:=newToken()
 b.s.db.Users[name]=&User{Name:name,Token:token,Expires:time.Now().Add(time.Duration(days)*24*time.Hour).UTC().Format(time.RFC3339),QuotaBytes:gb*1073741824}
 if e:=b.s.save();e!=nil{delete(b.s.db.Users,name);return "",e}
 return token,nil
}
func(b accountBackend) DisableUser(name string)error{
 b.s.mu.Lock();defer b.s.mu.Unlock()
 u,ok:=b.s.db.Users[name]
 if !ok{return errors.New("user not found")}
 old:=u.Disabled;u.Disabled=true
 if e:=b.s.save();e!=nil{u.Disabled=old;return e}
 return nil
}
func newDashboard(addr,state,diagnostics string,s *store)(*dashboard.App,error){
 a,e:=dashboard.New(dashboard.Config{
  CredentialsPath:state,
  DiagnosticsPath:diagnostics,
  Backend:accountBackend{s:s},
  OnEvent:func(name,code string){event("info","dashboard",name,code)},
 })
 if e!=nil{return nil,e}
 return a,nil
}
