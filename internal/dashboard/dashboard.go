// Package dashboard implements AFTAB's loopback-only multilingual lab administration UI.
package dashboard

import (
 "crypto/hmac"
 "crypto/rand"
 "crypto/sha256"
 "crypto/subtle"
 "embed"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "html/template"
 "io"
 "net"
 "net/http"
 "os"
 "path/filepath"
 "regexp"
 "strconv"
 "strings"
 "sync"
 "time"
)

//go:embed ui/*
var assets embed.FS

type User struct {
 Name string
 Expires string
 QuotaBytes int64
 UsedBytes int64
 Disabled bool
}
type Backend interface {
 ListUsers() []User
 CreateUser(name string, days int, gb int64)(string,error)
 DisableUser(name string) error
}
type GatewayStatus struct {Running, Public bool; Listen, Fingerprint, LastError string}
type GatewayController interface {Status() GatewayStatus; Start(port int,public bool) error; Stop() error; Test() error}
type Config struct {
 Gateway GatewayController
 CredentialsPath string
 DiagnosticsPath string
 Backend Backend
 OnEvent func(event,code string)
}
type credential struct {
 Username string `json:"username"`
 Salt string `json:"salt"`
 Hash string `json:"hash"`
 Iterations int `json:"iterations"`
 Language string `json:"language"`
}
type session struct{ CSRF string; Expires time.Time }
type App struct {
 mu sync.Mutex
 state credential
 config Config
 sessions map[string]session
 loginFailures int
 lockedUntil time.Time
}
func randomHex(n int)string{b:=make([]byte,n);if _,e:=rand.Read(b);e!=nil{panic(e)};return hex.EncodeToString(b)}
func derive(password string,salt []byte,rounds int)[]byte{
 block:=make([]byte,len(salt)+4);copy(block,salt);block[len(salt)+3]=1
 mac:=hmac.New(sha256.New,[]byte(password));_,_=mac.Write(block)
 u:=mac.Sum(nil);result:=append([]byte(nil),u...)
 for i:=1;i<rounds;i++{
  mac.Reset();_,_=mac.Write(u);u=mac.Sum(nil)
  for j:=range result{result[j]^=u[j]}
 }
 return result
}
func New(c Config)(*App,error){
 if c.Backend==nil||c.CredentialsPath==""{return nil,errors.New("dashboard backend and credential path required")}
 a:=&App{config:c,sessions:make(map[string]session)}
 b,e:=os.ReadFile(c.CredentialsPath)
 if errors.Is(e,os.ErrNotExist){return a,nil}
 if e!=nil{return nil,e}
 if e=json.Unmarshal(b,&a.state);e!=nil{return nil,e}
 if a.state.Username==""||a.state.Hash==""||a.state.Salt==""||a.state.Iterations!=600000{return nil,errors.New("invalid dashboard credential file")}
 return a,nil
}
func (a *App) saveLocked()error{
 if e:=os.MkdirAll(filepath.Dir(a.config.CredentialsPath),0700);e!=nil{return e}
 b,e:=json.MarshalIndent(a.state,"","  ");if e!=nil{return e}
 tmp:=a.config.CredentialsPath+".tmp"
 if e=os.WriteFile(tmp,b,0600);e!=nil{return e}
 return os.Rename(tmp,a.config.CredentialsPath)
}
func(a *App) emit(event,code string){if a.config.OnEvent!=nil{a.config.OnEvent(event,code)}}
func validLang(l string)string{switch l{case "fa","en","de","ar":return l};return "en"}
func(a *App) language(w http.ResponseWriter,r *http.Request)string{
 lang:=r.URL.Query().Get("lang")
 if lang!="" {
  lang=validLang(lang)
  http.SetCookie(w,&http.Cookie{Name:"aftab_lang",Value:lang,Path:"/",MaxAge:31536000,SameSite:http.SameSiteStrictMode})
  return lang
 }
 if c,e:=r.Cookie("aftab_lang");e==nil{return validLang(c.Value)}
 a.mu.Lock();defer a.mu.Unlock()
 if a.state.Language!=""{return validLang(a.state.Language)}
 browser:=strings.ToLower(r.Header.Get("Accept-Language"))
 if strings.HasPrefix(browser,"fa"){return "fa"}
 if strings.HasPrefix(browser,"ar"){return "ar"}
 if strings.HasPrefix(browser,"de"){return "de"}
 return "en"
}
func remoteLoopback(addr string)bool{host,_,e:=net.SplitHostPort(addr);if e!=nil{return false};ip:=net.ParseIP(host);return ip!=nil&&ip.IsLoopback()}
func randomCookie(w http.ResponseWriter,name string)string{
 token:=randomHex(32)
 http.SetCookie(w,&http.Cookie{Name:name,Value:token,Path:"/",HttpOnly:true,SameSite:http.SameSiteStrictMode,MaxAge:1200})
 return token
}
func csrfEqual(a,b string)bool{return len(a)==64&&len(b)==64&&subtle.ConstantTimeCompare([]byte(a),[]byte(b))==1}
func sameOrigin(r *http.Request)bool{
 origin:=r.Header.Get("Origin")
 if origin==""{return true} // Form CSRF tokens are also required.
 return origin=="http://"+r.Host||origin=="https://"+r.Host
}
func(a *App) newSession(w http.ResponseWriter,r *http.Request)session{
 raw:=randomHex(32);sum:=sha256.Sum256([]byte(raw))
 s:=session{CSRF:randomHex(32),Expires:time.Now().Add(12*time.Hour)}
 a.mu.Lock();for k,v:=range a.sessions{if time.Now().After(v.Expires){delete(a.sessions,k)}};a.sessions[hex.EncodeToString(sum[:])]=s;a.mu.Unlock()
 http.SetCookie(w,&http.Cookie{Name:"aftab_sid",Value:raw,Path:"/",HttpOnly:true,Secure:r.TLS!=nil,SameSite:http.SameSiteStrictMode,MaxAge:43200})
 return s
}
func(a *App) authenticated(r *http.Request)(session,bool){
 c,e:=r.Cookie("aftab_sid");if e!=nil||len(c.Value)!=64{return session{},false}
 sum:=sha256.Sum256([]byte(c.Value))
 a.mu.Lock();defer a.mu.Unlock()
 s,ok:=a.sessions[hex.EncodeToString(sum[:])]
 if !ok||time.Now().After(s.Expires){return session{},false}
 return s,true
}
func(a *App) revoke(w http.ResponseWriter,r *http.Request){
 c,e:=r.Cookie("aftab_sid")
 if e==nil{sum:=sha256.Sum256([]byte(c.Value));a.mu.Lock();delete(a.sessions,hex.EncodeToString(sum[:]));a.mu.Unlock()}
 http.SetCookie(w,&http.Cookie{Name:"aftab_sid",Value:"",Path:"/",HttpOnly:true,Secure:r.TLS!=nil,MaxAge:-1,SameSite:http.SameSiteStrictMode})
}
func(a *App) installed()bool{a.mu.Lock();defer a.mu.Unlock();return a.state.Username!=""}
type eventRow struct {Time,Level,Component,Event,Code string}
type page struct{
 Lang,Dir,Section,CSRF,Username,Error,Notice,CreatedToken,CreatedName string
 Users []User
 Events []eventRow
 Total,Active int
 LogEnabled bool
 Gateway GatewayStatus
 TestResult string
}
func translate(lang,key string)string {
 if words,ok:=translations[lang];ok {if t,ok:=words[key];ok{return t}}
 if t,ok:=translations["en"][key];ok{return t}
 return key
}
func(a *App) render(w http.ResponseWriter,r *http.Request,p page){
 w.Header().Set("Content-Type","text/html; charset=utf-8")
 w.Header().Set("Cache-Control","no-store")
 p.Lang=a.language(w,r)
 p.Dir="ltr";if p.Lang=="fa"||p.Lang=="ar"{p.Dir="rtl"}
 t,e:=template.New("index.html").Funcs(template.FuncMap{"tr":func(k string)string{return translate(p.Lang,k)},"gib":func(n int64)string{return fmt.Sprintf("%.2f",float64(n)/1073741824)}}).ParseFS(assets,"ui/index.html")
 if e!=nil{http.Error(w,"template error",500);return}
 if e=t.Execute(w,p);e!=nil{a.emit("template_error","render_failed")}
}
func(a *App) ServeHTTP(w http.ResponseWriter,r *http.Request){
 if !remoteLoopback(r.RemoteAddr){http.Error(w,"local access only",403);return}
 if r.Method=="POST"{r.Body=http.MaxBytesReader(w,r.Body,16*1024)}
 if r.URL.Path=="/assets/style.css"{
  b,e:=assets.ReadFile("ui/style.css");if e!=nil{http.NotFound(w,r);return}
  w.Header().Set("Content-Type","text/css; charset=utf-8");w.Header().Set("Cache-Control","public, max-age=3600");_,_=w.Write(b);return
 }
 path:=r.URL.Path
 allowed:=map[string]bool{"/":true,"/setup":true,"/login":true,"/logout":true,"/users":true,"/users/create":true,"/users/disable":true,"/diagnostics":true,"/settings":true,"/settings/start":true,"/settings/stop":true,"/settings/test":true,"/account":true,"/account/password":true}
 if !allowed[path]{http.NotFound(w,r);return}
 isInstalled:=a.installed()
 if !isInstalled&&path!="/setup"{http.Redirect(w,r,"/setup",http.StatusSeeOther);return}
 if isInstalled&&path=="/setup"{http.Redirect(w,r,"/login",http.StatusSeeOther);return}
 lang:=a.language(w,r)
 if path=="/setup"{a.setup(w,r,lang);return}
 if path=="/login"{a.login(w,r,lang);return}
 s,ok:=a.authenticated(r)
 if !ok{http.Redirect(w,r,"/login",http.StatusSeeOther);return}
 if path=="/logout"{
  if r.Method!="POST"||!sameOrigin(r)||!csrfEqual(s.CSRF,r.FormValue("csrf")){http.Error(w,"forbidden",403);return}
  a.revoke(w,r);http.Redirect(w,r,"/login",http.StatusSeeOther);return
 }
 if r.Method=="POST"&&(!sameOrigin(r)||!csrfEqual(s.CSRF,r.FormValue("csrf"))){http.Error(w,"forbidden",403);return}
 a.mu.Lock();currentUsername:=a.state.Username;a.mu.Unlock()
 p:=page{Section:"home",Username:currentUsername,CSRF:s.CSRF}
 if path=="/users"||path=="/users/create"||path=="/users/disable"{p.Section="users"}
 if path=="/diagnostics"{p.Section="diagnostics"}
 if path=="/settings"||path=="/settings/start"||path=="/settings/stop"||path=="/settings/test"{p.Section="settings"}
 if path=="/account"||path=="/account/password"{p.Section="account"}
 if r.Method=="POST"{
  switch path{
  case "/users/create":
   name:=strings.TrimSpace(r.FormValue("name"))
   days,e1:=strconv.Atoi(r.FormValue("days"));gb,e2:=strconv.ParseInt(r.FormValue("gb"),10,64)
   if !validUser(name)||e1!=nil||e2!=nil||days<1||days>3650||gb<1||gb>100000 {p.Error=translate(lang,"invalidUser")}else{
    token,e:=a.config.Backend.CreateUser(name,days,gb)
    if e!=nil{p.Error=translate(lang,"createFailed")}else{p.CreatedToken=token;p.CreatedName=name;a.emit("user_created","ok")}
   }
  case "/account/password":
   oldPassword:=r.FormValue("old_password")
   newPassword:=r.FormValue("new_password")
   repeat:=r.FormValue("confirm")
   if len([]rune(newPassword))<12||len([]rune(newPassword))>128||newPassword!=repeat{
    p.Error=translate(lang,"passwordInvalid")
   }else{
    a.mu.Lock();state:=a.state;a.mu.Unlock()
    salt,e:=hex.DecodeString(state.Salt);if e!=nil{p.Error=translate(lang,"passwordFailed")}else{
     actual,_:=hex.DecodeString(state.Hash)
     guess:=derive(oldPassword,salt,state.Iterations)
     if subtle.ConstantTimeCompare(guess,actual)!=1{p.Error=translate(lang,"passwordWrong")}else{
      nextSalt:=randomHex(16);newRaw,_:=hex.DecodeString(nextSalt)
      nextHash:=hex.EncodeToString(derive(newPassword,newRaw,600000))
      a.mu.Lock();oldState:=a.state
      a.state.Salt=nextSalt;a.state.Hash=nextHash;a.state.Iterations=600000
      e=a.saveLocked()
      if e!=nil{a.state=oldState}else{a.sessions=make(map[string]session)}
      a.mu.Unlock()
      if e!=nil{p.Error=translate(lang,"passwordFailed")}else{
       a.emit("password_changed","ok");a.revoke(w,r);http.Redirect(w,r,"/login",http.StatusSeeOther);return
      }
     }
    }
   }
  case "/settings/start":
   port,e:=strconv.Atoi(r.FormValue("port"))
   if e!=nil||port<1024||port>65535||a.config.Gateway==nil{p.Error=translate(lang,"gatewayInvalid")}else if e=a.config.Gateway.Start(port,r.FormValue("public")=="yes");e!=nil{p.Error=translate(lang,"gatewayFailed")}else{p.Notice=translate(lang,"gatewayStarted");a.emit("gateway_start_requested","ok")}
  case "/settings/stop":
   if a.config.Gateway==nil{p.Error=translate(lang,"gatewayFailed")}else if e:=a.config.Gateway.Stop();e!=nil{p.Error=translate(lang,"gatewayFailed")}else{p.Notice=translate(lang,"gatewayStopped");a.emit("gateway_stop_requested","ok")}
  case "/settings/test":
   if a.config.Gateway==nil{p.Error=translate(lang,"gatewayFailed")}else if e:=a.config.Gateway.Test();e!=nil{p.Error=translate(lang,"gatewayTestFailed")}else{p.Notice=translate(lang,"gatewayTestOK");a.emit("gateway_self_test","ok")}
  case "/users/disable":
   if e:=a.config.Backend.DisableUser(r.FormValue("name"));e!=nil{p.Error=translate(lang,"disableFailed")}else{p.Notice=translate(lang,"disabled");a.emit("user_disabled","ok")}
  default:http.Error(w,"method not allowed",405);return
  }
 }else if r.Method!="GET"{http.Error(w,"method not allowed",405);return}
 p.Users=a.config.Backend.ListUsers();p.Total=len(p.Users)
 now:=time.Now()
 for _,u:=range p.Users{if !u.Disabled{expiry,e:=time.Parse(time.RFC3339,u.Expires);if e==nil&&now.Before(expiry)&&(u.QuotaBytes<=0||u.UsedBytes<u.QuotaBytes){p.Active++}}}
 if p.Section=="diagnostics"{p.Events=readEvents(a.config.DiagnosticsPath);p.LogEnabled=a.config.DiagnosticsPath!=""}
 if a.config.Gateway!=nil{p.Gateway=a.config.Gateway.Status()}
 a.render(w,r,p)
}
var usernamePattern=regexp.MustCompile(`^[a-zA-Z0-9._-]{3,48}$`)
var userPattern=regexp.MustCompile(`^[a-zA-Z0-9._-]{1,80}$`)
func validUser(v string)bool{return userPattern.MatchString(v)}
func(a *App) setup(w http.ResponseWriter,r *http.Request,lang string){
 if r.Method=="GET"{
  nonce:=randomCookie(w,"aftab_setup")
  a.render(w,r,page{Section:"setup",CSRF:nonce});return
 }
 if r.Method!="POST"{http.Error(w,"method not allowed",405);return}
 cookie,e:=r.Cookie("aftab_setup")
 if e!=nil||!sameOrigin(r)||!csrfEqual(cookie.Value,r.FormValue("csrf")){http.Error(w,"forbidden",403);return}
 name:=strings.TrimSpace(r.FormValue("username"));pass:=r.FormValue("password");confirm:=r.FormValue("confirm")
 if !usernamePattern.MatchString(name)||len([]rune(pass))<12||len([]rune(pass))>128||pass!=confirm{
  a.render(w,r,page{Section:"setup",CSRF:cookie.Value,Error:translate(lang,"invalidSetup")});return
 }
 lang=validLang(r.FormValue("language"))
 salt:=randomHex(16);raw,_:=hex.DecodeString(salt);hash:=hex.EncodeToString(derive(pass,raw,600000))
 a.mu.Lock()
 if a.state.Username!=""{a.mu.Unlock();http.Error(w,"setup already complete",409);return}
 a.state=credential{Username:name,Salt:salt,Hash:hash,Iterations:600000,Language:lang}
 e=a.saveLocked()
 if e!=nil{a.state=credential{}}
 a.mu.Unlock()
 if e!=nil{http.Error(w,"could not save credentials",500);return}
 a.emit("setup_completed","ok")
 http.SetCookie(w,&http.Cookie{Name:"aftab_lang",Value:lang,Path:"/",SameSite:http.SameSiteStrictMode,MaxAge:31536000})
 a.newSession(w,r)
 http.Redirect(w,r,"/",http.StatusSeeOther)
}
func(a *App) login(w http.ResponseWriter,r *http.Request,lang string){
 if r.Method=="GET"{
  if _,ok:=a.authenticated(r);ok{http.Redirect(w,r,"/",http.StatusSeeOther);return}
  nonce:=randomCookie(w,"aftab_login");a.render(w,r,page{Section:"login",CSRF:nonce});return
 }
 if r.Method!="POST"{http.Error(w,"method not allowed",405);return}
 cookie,e:=r.Cookie("aftab_login")
 if e!=nil||!sameOrigin(r)||!csrfEqual(cookie.Value,r.FormValue("csrf")){http.Error(w,"forbidden",403);return}
 a.mu.Lock()
 if time.Now().Before(a.lockedUntil){a.mu.Unlock();http.Error(w,"temporarily locked",429);return}
 state:=a.state;a.mu.Unlock()
 salt,e:=hex.DecodeString(state.Salt);if e!=nil{http.Error(w,"invalid credentials storage",500);return}
 hash,_:=hex.DecodeString(state.Hash)
 guess:=derive(r.FormValue("password"),salt,state.Iterations)
 ok:=subtle.ConstantTimeCompare(guess,hash)==1&&subtle.ConstantTimeCompare([]byte(r.FormValue("username")),[]byte(state.Username))==1
 a.mu.Lock()
 if !ok{
  a.loginFailures++
  if a.loginFailures>=6{a.lockedUntil=time.Now().Add(15*time.Minute);a.loginFailures=0}
 }else{a.loginFailures=0;a.lockedUntil=time.Time{}}
 a.mu.Unlock()
 if !ok{a.emit("login_rejected","invalid_credentials");a.render(w,r,page{Section:"login",CSRF:cookie.Value,Error:translate(lang,"loginFailed")});return}
 a.emit("login_success","ok")
 a.newSession(w,r)
 http.Redirect(w,r,"/",http.StatusSeeOther)
}
func readEvents(path string)[]eventRow{
 if path==""{return nil}
 f,e:=os.Open(path);if e!=nil{return nil};defer f.Close()
 stat,e:=f.Stat();if e!=nil{return nil}
 start:=stat.Size()-1024*1024;if start<0{start=0}
 _,_ =f.Seek(start,io.SeekStart)
 b,e:=io.ReadAll(io.LimitReader(f,1024*1024));if e!=nil{return nil}
 lines:=strings.Split(string(b),"\n")
 if start>0&&len(lines)>0{lines=lines[1:]}
 out:=make([]eventRow,0,100)
 for i:=len(lines)-1;i>=0&&len(out)<100;i--{
  var v map[string]any
  if json.Unmarshal([]byte(lines[i]),&v)!=nil{continue}
  str:=func(k string)string{v,ok:=v[k].(string);if !ok{return ""};if len(v)>120{return v[:120]};return v}
  out=append(out,eventRow{Time:str("time"),Level:str("level"),Component:str("component"),Event:str("event"),Code:str("code")})
 }
 return out
}
func(a *App) ListenAndServe(addr string)error{
 if !loopbackAddress(addr){return errors.New("dashboard is restricted to numeric loopback addresses")}
 server:=&http.Server{Addr:addr,Handler:a,ReadHeaderTimeout:5*time.Second,ReadTimeout:10*time.Second,WriteTimeout:15*time.Second,IdleTimeout:60*time.Second,MaxHeaderBytes:8192}
 return server.ListenAndServe()
}
func loopbackAddress(addr string)bool{host,_,err:=net.SplitHostPort(addr);if err!=nil{return false};ip:=net.ParseIP(host);return ip!=nil&&ip.IsLoopback()}
