package main

import (
 "errors"
 "sort"
 "time"

 "github.com/Zoupir/AFTAB/internal/dashboard"
)

const gib = int64(1073741824)

type accountBackend struct{ s *store }
func(b accountBackend) ListUsers()[]dashboard.User{
 b.s.mu.Lock();defer b.s.mu.Unlock()
 out:=make([]dashboard.User,0,len(b.s.db.Users))
 for _,u:=range b.s.db.Users{
  out=append(out,dashboard.User{Name:u.Name,Expires:u.Expires,QuotaBytes:u.QuotaBytes,UsedBytes:u.UsedBytes,Disabled:u.Disabled,DurationDays:u.DurationDays})
 }
 sort.Slice(out,func(i,j int)bool{return out[i].Name<out[j].Name})
 return out
}
func(b accountBackend) CreateUser(name string,days int,gb int64)(string,error){
 if days<1||days>3650||gb<1||gb>100000{return "",errors.New("invalid plan")}
 b.s.mu.Lock();defer b.s.mu.Unlock()
 if _,ok:=b.s.db.Users[name];ok{return "",errors.New("duplicate account")}
 token:=newToken()
 b.s.db.Users[name]=&User{Name:name,Token:tokenDigest(token),Expires:time.Now().Add(time.Duration(days)*24*time.Hour).UTC().Format(time.RFC3339),QuotaBytes:gb*gib,DurationDays:days}
 if e:=b.s.save();e!=nil{delete(b.s.db.Users,name);return "",e}
 return token,nil
}
// mutate preserves the last durable state if persistence fails.
func(b accountBackend)mutate(name string,fn func(*User)error,disconnect bool)error{
 b.s.mu.Lock();defer b.s.mu.Unlock()
 u,ok:=b.s.db.Users[name];if !ok{return errors.New("user not found")}
 previous:=*u
 if e:=fn(u);e!=nil{return e}
 if e:=b.s.save();e!=nil{*u=previous;return e}
 if disconnect{b.s.disconnectUserLocked(name)}
 return nil
}
func(b accountBackend) SetUserEnabled(name string,enabled bool)error{
 return b.mutate(name,func(u *User)error{u.Disabled=!enabled;return nil},!enabled)
}
func(b accountBackend) DisableUser(name string)error{return b.SetUserEnabled(name,false)}
func(b accountBackend) UpdateUser(name,newName string,days int,gb int64)error{
 if days<1||days>3650||gb<1||gb>100000{return errors.New("invalid plan")}
 if newName==""{return errors.New("empty account")}
 s:=b.s;s.mu.Lock();defer s.mu.Unlock()
 u,ok:=s.db.Users[name];if !ok{return errors.New("user not found")}
 if newName!=name{if _,exists:=s.db.Users[newName];exists{return errors.New("duplicate account")}}
 previous:=*u
 u.Name=newName;u.DurationDays=days;u.Expires=time.Now().Add(time.Duration(days)*24*time.Hour).UTC().Format(time.RFC3339);u.QuotaBytes=gb*gib
 if newName!=name{delete(s.db.Users,name);s.db.Users[newName]=u}
 if e:=s.save();e!=nil{
  *u=previous
  if newName!=name{delete(s.db.Users,newName);s.db.Users[name]=u}
  return e
 }
 if newName!=name{s.disconnectUserLocked(name)}
 return nil
}
func(b accountBackend) ExtendUser(name string,days int,gb int64)error{
 if days<0||days>3650||gb<0||gb>100000||(days==0&&gb==0){return errors.New("invalid extension")}
 return b.mutate(name,func(u *User)error{
  if days>0{
   base:=time.Now().UTC()
   if expiry,e:=time.Parse(time.RFC3339,u.Expires);e==nil&&expiry.After(base){base=expiry}
   u.Expires=base.Add(time.Duration(days)*24*time.Hour).Format(time.RFC3339)
  }
  if gb>0{
   if u.QuotaBytes>100000*gib-gb*gib{return errors.New("quota limit exceeded")}
   u.QuotaBytes+=gb*gib
  }
  return nil
 },false)
}
func(b accountBackend) ResetUsage(name string)error{
 return b.mutate(name,func(u *User)error{u.UsedBytes=0;return nil},false)
}
func(b accountBackend) ResetTime(name string)error{
 return b.mutate(name,func(u *User)error{
  days:=u.DurationDays
  if days<=0{days=30}
  u.Expires=time.Now().Add(time.Duration(days)*24*time.Hour).UTC().Format(time.RFC3339)
  u.DurationDays=days
  return nil
 },false)
}
func(b accountBackend) DeleteUser(name string)error{
 s:=b.s;s.mu.Lock();defer s.mu.Unlock()
 u,ok:=s.db.Users[name];if !ok{return errors.New("user not found")}
 delete(s.db.Users,name)
 if e:=s.save();e!=nil{s.db.Users[name]=u;return e}
 s.disconnectUserLocked(name)
 return nil
}
func(b accountBackend) RotateToken(name string)(string,error){
 s:=b.s;s.mu.Lock();defer s.mu.Unlock()
 u,ok:=s.db.Users[name];if !ok{return "",errors.New("user not found")}
 old:=u.Token
 fresh:=newToken();u.Token=tokenDigest(fresh)
 if e:=s.save();e!=nil{u.Token=old;return "",e}
 s.disconnectUserLocked(name)
 return fresh,nil
}
func newDashboard(addr,state,diagnostics string,s *store,gateway dashboard.GatewayController)(*dashboard.App,error){
 a,e:=dashboard.New(dashboard.Config{
  CredentialsPath:state,
  Gateway:gateway,
  DiagnosticsPath:diagnostics,
  Backend:accountBackend{s:s},
  OnEvent:func(name,code string){event("info","dashboard",name,code)},
 })
 if e!=nil{return nil,e}
 return a,nil
}
