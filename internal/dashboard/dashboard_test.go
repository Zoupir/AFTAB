package dashboard

import (
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "net/http"
 "net/http/httptest"
 "net/url"
 "os"
 "path/filepath"
 "strings"
 "sync"
 "testing"
)
type fakeBackend struct{mu sync.Mutex;users map[string]User}
func(b *fakeBackend)ListUsers()[]User{
 b.mu.Lock();defer b.mu.Unlock();out:=[]User{};for _,u:=range b.users{out=append(out,u)};return out
}
func(b *fakeBackend)CreateUser(name string,days int,gb int64)(string,error){
 b.mu.Lock();defer b.mu.Unlock();b.users[name]=User{Name:name,QuotaBytes:gb*1073741824};return "secret-user-token",nil
}
func(b *fakeBackend)DisableUser(name string)error{
 b.mu.Lock();defer b.mu.Unlock();u:=b.users[name];u.Disabled=true;b.users[name]=u;return nil
}
func request(method,path,form string,cookies ...*http.Cookie)*http.Request{
 r:=httptest.NewRequest(method,path,strings.NewReader(form));r.RemoteAddr="127.0.0.1:12345"
 r.Header.Set("Content-Type","application/x-www-form-urlencoded")
 for _,c:=range cookies{r.AddCookie(c)}
 return r
}
func cookieNamed(w *httptest.ResponseRecorder,name string)*http.Cookie{
 for _,c:=range w.Result().Cookies(){if c.Name==name{return c}}
 return nil
}
func newFixture(t *testing.T)(*App,string){
 t.Helper();p:=filepath.Join(t.TempDir(),"state","admin.json")
 a,e:=New(Config{CredentialsPath:p,Backend:&fakeBackend{users:map[string]User{}}})
 if e!=nil{t.Fatal(e)}
 return a,p
}
func setupFixture(t *testing.T,a *App){
 t.Helper()
 first:=httptest.NewRecorder()
 a.ServeHTTP(first,request("GET","http://localhost/setup",""))
 csrf:=cookieNamed(first,"aftab_setup");if csrf==nil{t.Fatal("missing setup CSRF cookie")}
 form:=url.Values{"username":{"owner"},"password":{"correct-horse-battery-aftab"},"confirm":{"correct-horse-battery-aftab"},"language":{"fa"},"csrf":{csrf.Value}}
 r:=request("POST","http://localhost/setup",form.Encode(),csrf)
 response:=httptest.NewRecorder();a.ServeHTTP(response,r)
 if response.Code!=http.StatusSeeOther{t.Fatalf("setup code %d %s",response.Code,response.Body.String())}
}
func TestFirstRunWizardAndPasswordStorage(t *testing.T){
 a,p:=newFixture(t)
 w:=httptest.NewRecorder();a.ServeHTTP(w,request("GET","http://localhost/",""))
 if w.Code!=http.StatusSeeOther||w.Header().Get("Location")!="/setup"{t.Fatal("first-run wizard was not required")}
 setupFixture(t,a)
 data,e:=os.ReadFile(p);if e!=nil{t.Fatal(e)}
 if strings.Contains(string(data),"correct-horse-battery-aftab"){t.Fatal("password stored in cleartext")}
 var creds credential
 if e=json.Unmarshal(data,&creds);e!=nil{t.Fatal(e)}
 if creds.Username!="owner"||creds.Language!="fa"||len(creds.Hash)!=64{t.Fatal("incorrect saved credentials")}
 stat,e:=os.Stat(p);if e!=nil{t.Fatal(e)}
 if stat.Mode().Perm()&0077!=0{t.Fatal("credentials readable by other users")}
 a2,e:=New(a.config);if e!=nil{t.Fatal(e)}
 if !a2.installed(){t.Fatal("setup lost after restart")}
 w2:=httptest.NewRecorder();a2.ServeHTTP(w2,request("GET","http://localhost/setup",""))
 if w2.Code!=http.StatusSeeOther{t.Fatal("second setup allowed")}
}
func TestLoginAndCSRF(t *testing.T){
 a,_:=newFixture(t);setupFixture(t,a)
 w:=httptest.NewRecorder();a.ServeHTTP(w,request("GET","http://localhost/login",""))
 cookie:=cookieNamed(w,"aftab_login");if cookie==nil{t.Fatal("login CSRF cookie missing")}
 wrong:=url.Values{"username":{"owner"},"password":{"incorrect-password"},"csrf":{cookie.Value}}
 fail:=httptest.NewRecorder();a.ServeHTTP(fail,request("POST","http://localhost/login",wrong.Encode(),cookie))
 if fail.Code!=http.StatusOK{t.Fatal("wrong login unexpectedly accepted")}
 form:=url.Values{"username":{"owner"},"password":{"correct-horse-battery-aftab"},"csrf":{cookie.Value}}
 ok:=httptest.NewRecorder();a.ServeHTTP(ok,request("POST","http://localhost/login",form.Encode(),cookie))
 if ok.Code!=http.StatusSeeOther{t.Fatalf("correct login rejected: %d",ok.Code)}
 sid:=cookieNamed(ok,"aftab_sid");if sid==nil||!sid.HttpOnly||sid.SameSite!=http.SameSiteStrictMode{t.Fatal("session cookie not protected")}
 noCSRF:=httptest.NewRecorder();a.ServeHTTP(noCSRF,request("POST","http://localhost/users/create",url.Values{"name":{"example"},"days":{"30"},"gb":{"30"}}.Encode(),sid))
 if noCSRF.Code!=http.StatusForbidden{t.Fatal("CSRF protection missing")}
 a.mu.Lock();sum:=shaKey(sid.Value);csrf:=a.sessions[sum].CSRF;a.mu.Unlock()
 create:=httptest.NewRecorder()
 a.ServeHTTP(create,request("POST","http://localhost/users/create",url.Values{"name":{"example"},"days":{"30"},"gb":{"30"},"csrf":{csrf}}.Encode(),sid))
 if create.Code!=http.StatusOK||!strings.Contains(create.Body.String(),"secret-user-token"){t.Fatal("authenticated user creation failed")}
 outside:=request("GET","http://localhost/users","",sid);outside.RemoteAddr="192.0.2.1:4321"
 denied:=httptest.NewRecorder();a.ServeHTTP(denied,outside)
 if denied.Code!=http.StatusForbidden{t.Fatal("non-loopback request accepted")}
}
func shaKey(token string)string{sum:=sha256.Sum256([]byte(token));return hex.EncodeToString(sum[:])}
func TestLocales(t *testing.T){
 a,_:=newFixture(t)
 for _,lang:=range []string{"fa","en","de","ar"}{
  w:=httptest.NewRecorder();a.ServeHTTP(w,request("GET","http://localhost/setup?lang="+lang,""))
  if !strings.Contains(w.Body.String(),`lang="`+lang+`"`){t.Fatalf("locale %s ignored",lang)}
  if (lang=="fa"||lang=="ar")&&!strings.Contains(w.Body.String(),`dir="rtl"`){t.Fatalf("%s should be RTL",lang)}
 }
}

func TestPBKDF2SHA256KnownVectors(t *testing.T){
 cases:=[]struct{rounds int;expected string}{
  {1,"120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"},
  {2,"ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"},
 }
 for _,tc:=range cases{
  got:=hex.EncodeToString(derive("password",[]byte("salt"),tc.rounds))
  if got!=tc.expected{t.Fatalf("PBKDF2 vector at %d rounds: %s",tc.rounds,got)}
 }
}
func TestNoUnauthenticatedDashboardAccess(t *testing.T){
 a,_:=newFixture(t);setupFixture(t,a)
 for _,path:=range []string{"/","/users","/settings","/diagnostics"}{
  w:=httptest.NewRecorder();a.ServeHTTP(w,request("GET","http://localhost"+path,""))
  if w.Code!=http.StatusSeeOther||w.Header().Get("Location")!="/login"{t.Fatalf("unauthenticated %s allowed",path)}
 }
}
