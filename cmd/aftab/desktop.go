package main

// Browser-based local desktop controller for the AFTAB TCP research client.
// It deliberately does not change operating-system routes or create a VPN.
import (
 "crypto/rand"
 "crypto/sha256"
 "crypto/subtle"
 "crypto/tls"
 "crypto/x509"
 "encoding/binary"
 "io"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "html/template"
 "net"
 "net/http"
 "os"
 "os/exec"
 "path/filepath"
 "runtime"
 "strconv"
 "strings"
 "sync"
 "time"
)

type desktopApp struct {
 mu sync.Mutex
 configFile string
 logFile string
 cfg clientConfig
 ln net.Listener
 httpLn net.Listener
 httpServer *http.Server
 proxyApplied bool
 tracker *socksTracker
 secret, session, csrf string
 bootUsed bool
 msg, errCode string
}
func desktopRandom()string{var b [32]byte;if _,e:=rand.Read(b[:]);e!=nil{panic(e)};return hex.EncodeToString(b[:])}
func defaultDesktopConfig()string{
 dir,e:=os.UserConfigDir()
 if e!=nil||dir==""{dir="."}
 return filepath.Join(dir,"AFTAB","desktop.json")
}
func newDesktop(configFile string)(*desktopApp,error){
 a:=&desktopApp{configFile:configFile,secret:desktopRandom(),session:desktopRandom(),csrf:desktopRandom()}
 a.cfg.Listen="127.0.0.1:10808"
 b,e:=os.ReadFile(configFile)
 if errors.Is(e,os.ErrNotExist){return a,nil}
 if e!=nil{return nil,e}
 if e=json.Unmarshal(b,&a.cfg);e!=nil{return nil,errors.New("invalid desktop configuration")}
 a.cfg.Token,e=unprotectToken(a.cfg.Token)
 if e!=nil{return nil,errors.New("could not unlock saved account token")}
 return a,nil
}
func(a *desktopApp) persist(c clientConfig)error{
 if e:=os.MkdirAll(filepath.Dir(a.configFile),0700);e!=nil{return e}
 persisted:=c
 var e error
 persisted.Token,e=protectToken(c.Token)
 if e!=nil{return e}
 b,e:=json.MarshalIndent(persisted,"","  ");if e!=nil{return e}
 tmp:=a.configFile+".tmp"
 if e=os.WriteFile(tmp,b,0600);e!=nil{return e}
 if e=os.Rename(tmp,a.configFile);e!=nil{_ =os.Remove(tmp);return e}
 return nil
}
func desktopConfigValid(c clientConfig)error{
 if c.Listen==""{c.Listen="127.0.0.1:10808"}
 if !loopback(c.Listen){return errors.New("proxy_must_be_loopback")}
 host,port,e:=net.SplitHostPort(c.Server)
 if e!=nil||host==""||len(host)>253{return errors.New("invalid_server")}
 n,e:=strconv.Atoi(port);if e!=nil||n<1||n>65535{return errors.New("invalid_server_port")}
 if strings.ContainsAny(host,"\r\n\t /\\"){return errors.New("invalid_server")}
 if len(c.Token)<16||len(c.Token)>128||strings.ContainsAny(c.Token,"\r\n"){return errors.New("invalid_token")}
 pin,e:=hex.DecodeString(strings.ReplaceAll(strings.ToLower(c.Pin),":",""))
 if e!=nil||len(pin)!=sha256.Size{return errors.New("invalid_fingerprint")}
 return nil
}
func desktopPinnedConfig(c clientConfig)*tls.Config{
 p,_:=hex.DecodeString(strings.ReplaceAll(strings.ToLower(c.Pin),":",""))
 return &tls.Config{
  MinVersion:tls.VersionTLS13,
  InsecureSkipVerify:true, // Certificate trust is established through the pinned digest below.
  VerifyPeerCertificate:func(raw [][]byte,_ [][]*x509.Certificate)error{
   if len(raw)==0{return errors.New("missing_certificate")}
   got:=sha256.Sum256(raw[0])
   if subtle.ConstantTimeCompare(got[:],p)!=1{return errors.New("fingerprint_mismatch")}
   return nil
  },
 }
}
func desktopProbe(c clientConfig)error{
 if e:=desktopConfigValid(c);e!=nil{return e}
 conn,e:=tls.DialWithDialer(&net.Dialer{Timeout:4*time.Second},"tcp",c.Server,desktopPinnedConfig(c))
 if e!=nil{return errors.New("tls_unreachable_or_mismatch")}
 return conn.Close()
}
func desktopTunnelProbe(c clientConfig,target string,port uint16)error{
 if e:=desktopConfigValid(c);e!=nil{return e}
 conn,e:=tls.DialWithDialer(&net.Dialer{Timeout:5*time.Second},"tcp",c.Server,desktopPinnedConfig(c))
 if e!=nil{return errors.New("tls_unreachable_or_mismatch")}
 defer conn.Close()
 _=conn.SetDeadline(time.Now().Add(8*time.Second))
 if strings.ContainsAny(target,"\r\n")||target==""||port==0{return errors.New("invalid_test_destination")}
 if _,e=fmt.Fprintf(conn,"%s\n%s\n",c.Token,target);e!=nil{return errors.New("gateway_write_failed")}
 var b [2]byte;binary.BigEndian.PutUint16(b[:],port)
 if _,e=conn.Write(b[:]);e!=nil{return errors.New("gateway_write_failed")}
 var result [1]byte
 if _,e=io.ReadFull(conn,result[:]);e!=nil{return errors.New("account_or_gateway_rejected")}
 if result[0]!=0{return errors.New("destination_unreachable")}
 return nil
}
func(a *desktopApp) start()error{
 a.mu.Lock()
 defer a.mu.Unlock()
 if a.ln!=nil{return errors.New("already_running")}
 if e:=desktopConfigValid(a.cfg);e!=nil{return e}
 if e:=desktopProbe(a.cfg);e!=nil{return e}
 pin,e:=hex.DecodeString(strings.ReplaceAll(strings.ToLower(a.cfg.Pin),":",""))
 if e!=nil{return e}
 ln,e:=net.Listen("tcp",a.cfg.Listen)
 if e!=nil{return errors.New("local_socks_port_unavailable")}
 httpLn,e:=net.Listen("tcp","127.0.0.1:10809")
 if e!=nil{_ =ln.Close();return errors.New("local_http_proxy_port_unavailable")}
 cfg:=a.cfg
 tracker:=newSOCKSTracker()
 server:=newLocalHTTPProxyServer(cfg,tracker)
 if cfg.UseSystemProxy{
  if e=applySystemProxy(a.configFile+".system-proxy-backup");e!=nil{
   _=ln.Close();_ =httpLn.Close()
   return e
  }
  a.proxyApplied=true
 }
 a.ln=ln;a.httpLn=httpLn;a.httpServer=server;a.tracker=tracker
 go func(){
  e:=serveSOCKSTracked(ln,cfg,pin,tracker)
  if e!=nil&&!errors.Is(e,net.ErrClosed){event("error","desktop","socks_stopped","listener_error")}
 }()
 go func(){
  e:=serveLocalHTTPProxy(httpLn,server)
  if e!=nil&&!errors.Is(e,net.ErrClosed){event("error","desktop","http_proxy_stopped","listener_error")}
 }()
 return nil
}
func(a *desktopApp) stop(){
 a.mu.Lock()
 ln,httpLn,server,tracker:=a.ln,a.httpLn,a.httpServer,a.tracker
 applied:=a.proxyApplied
 a.ln=nil;a.httpLn=nil;a.httpServer=nil;a.tracker=nil;a.proxyApplied=false
 a.mu.Unlock()
 // Restore Windows settings before closing the local endpoints.
 if applied{
  if e:=recoverSystemProxy(a.configFile+".system-proxy-backup");e!=nil{
   event("error","desktop","system_proxy_restore_failed","recovery_required")
  }
 }
 if server!=nil{_ =server.Close()}
 if httpLn!=nil{_ =httpLn.Close()}
 if ln!=nil{_ =ln.Close()}
 if tracker!=nil{tracker.closeAll()}
}

func(a *desktopApp) authorized(r *http.Request)bool{
 cookie,e:=r.Cookie("aftab_desktop")
 if e!=nil{return false}
 a.mu.Lock();expected:=a.session;a.mu.Unlock()
 return len(cookie.Value)==len(expected)&&subtle.ConstantTimeCompare([]byte(cookie.Value),[]byte(expected))==1
}
func(a *desktopApp) view(w http.ResponseWriter,r *http.Request){
  if lang:=r.URL.Query().Get("lang");lang=="fa"||lang=="en"||lang=="de"||lang=="ar"{
   http.SetCookie(w,&http.Cookie{Name:"aftab_desktop_lang",Value:lang,Path:"/",SameSite:http.SameSiteStrictMode,MaxAge:31536000})
  }
 a.mu.Lock()
 d:=desktopView{Lang:desktopLocale(r),Running:a.ln!=nil,Server:a.cfg.Server,Listen:a.cfg.Listen,Pin:a.cfg.Pin,HasToken:a.cfg.Token!="",SystemProxy:a.cfg.UseSystemProxy,AutoProxyActive:a.proxyApplied,IsWindows:runtime.GOOS=="windows",CSRF:a.csrf,Message:a.msg,Error:a.errCode}
 logFile:=a.logFile
 a.mu.Unlock()
 d.Events=readDesktopEvents(logFile)
 if d.Lang=="fa"||d.Lang=="ar"{d.Dir="rtl"}else{d.Dir="ltr"}
 t,e:=template.New("desktop").Funcs(template.FuncMap{"tr":func(key string)string{return desktopTranslation(d.Lang,key)}}).Parse(desktopHTML)
 if e!=nil{http.Error(w,"template failure",500);return}
 w.Header().Set("Content-Type","text/html; charset=utf-8")
 w.Header().Set("Cache-Control","no-store")
 _=t.Execute(w,d)
}
func(a *desktopApp) note(message,errorCode string){
 a.mu.Lock();a.msg=message;a.errCode=errorCode;a.mu.Unlock()
}
func(a *desktopApp) ServeHTTP(w http.ResponseWriter,r *http.Request){
 host,_,e:=net.SplitHostPort(r.RemoteAddr)
 if e!=nil||net.ParseIP(host)==nil||!net.ParseIP(host).IsLoopback(){http.Error(w,"local only",403);return}
 requestHost,_,e:=net.SplitHostPort(r.Host)
 if e!=nil||net.ParseIP(requestHost)==nil||!net.ParseIP(requestHost).IsLoopback(){http.Error(w,"invalid host",403);return}
 w.Header().Set("X-Content-Type-Options","nosniff")
 w.Header().Set("Referrer-Policy","no-referrer")
 w.Header().Set("X-Frame-Options","DENY")
 w.Header().Set("Content-Security-Policy","default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
 if r.URL.Path=="/open"&&r.Method=="GET"{
  a.mu.Lock()
  ok:=!a.bootUsed&&len(r.URL.Query().Get("ticket"))==len(a.secret)&&subtle.ConstantTimeCompare([]byte(r.URL.Query().Get("ticket")),[]byte(a.secret))==1
  if ok{a.bootUsed=true}
  cookie:=a.session
  a.mu.Unlock()
  if !ok{http.Error(w,"invalid launch session",403);return}
  http.SetCookie(w,&http.Cookie{Name:"aftab_desktop",Value:cookie,Path:"/",HttpOnly:true,SameSite:http.SameSiteStrictMode,MaxAge:43200})
  http.Redirect(w,r,"/",http.StatusSeeOther);return
 }
 if !a.authorized(r){http.Error(w,"open the application from its launcher",403);return}
 if r.URL.Path=="/"&&r.Method=="GET"{a.view(w,r);return}
 if r.Method!="POST"{http.NotFound(w,r);return}
 r.Body=http.MaxBytesReader(w,r.Body,8192)
 if e:=r.ParseForm();e!=nil{http.Error(w,"invalid form",400);return}
 a.mu.Lock();csrf:=a.csrf;a.mu.Unlock()
 if r.Header.Get("Origin")!=""&&r.Header.Get("Origin")!="http://"+r.Host{http.Error(w,"origin rejected",403);return}
 if len(r.FormValue("csrf"))!=len(csrf)||subtle.ConstantTimeCompare([]byte(r.FormValue("csrf")),[]byte(csrf))!=1{http.Error(w,"invalid csrf",403);return}
 switch r.URL.Path{
 case "/save":
  a.mu.Lock();running:=a.ln!=nil;prior:=a.cfg;a.mu.Unlock()
  if running{a.note("","disconnect_first");break}
  c:=clientConfig{Server:strings.TrimSpace(r.FormValue("server")),Pin:strings.TrimSpace(r.FormValue("pin")),Listen:"127.0.0.1:10808",Token:r.FormValue("token"),UseSystemProxy:r.FormValue("system_proxy")=="yes"}
  if c.Token==""{c.Token=prior.Token}
  if e:=desktopConfigValid(c);e!=nil{a.note("","invalid_config");break}
  if e:=a.persist(c);e!=nil{a.note("","save_failed");break}
  a.mu.Lock();a.cfg=c;a.mu.Unlock()
  a.note("saved","");event("info","desktop","settings_saved","ok")
 case "/test":
  a.mu.Lock();c:=a.cfg;a.mu.Unlock()
  if e:=desktopProbe(c);e!=nil{a.note("","test_failed");event("warn","desktop","connection_test_failed","tls_unavailable")}else{a.note("test_ok","");event("info","desktop","connection_test_ok","ok")}
 case "/test-tunnel":
  a.mu.Lock();c:=a.cfg;a.mu.Unlock()
  if e:=desktopTunnelProbe(c,"example.com",443);e!=nil{a.note("","tunnel_test_failed");event("warn","desktop","tunnel_test_failed","account_or_egress")}else{a.note("tunnel_test_ok","");event("info","desktop","tunnel_test_passed","ok")}
 case "/connect":
  if e:=a.start();e!=nil{a.note("","connect_failed");event("warn","desktop","connect_failed","connection_error")}else{a.note("connected","");event("info","desktop","proxy_started","ok")}
 case "/disconnect":
  a.stop();a.note("disconnected","");event("info","desktop","proxy_stopped","ok")
 default:http.NotFound(w,r);return
 }
 http.Redirect(w,r,"/",http.StatusSeeOther)
}
func desktopLocale(r *http.Request)string{
 switch r.URL.Query().Get("lang"){case "fa","en","de","ar":return r.URL.Query().Get("lang")}
 if c,e:=r.Cookie("aftab_desktop_lang");e==nil{switch c.Value{case "fa","en","de","ar":return c.Value}}
 pref:=strings.ToLower(r.Header.Get("Accept-Language"))
 switch{case strings.HasPrefix(pref,"fa"):return "fa";case strings.HasPrefix(pref,"de"):return "de";case strings.HasPrefix(pref,"ar"):return "ar"}
 return "en"
}
func startDesktop(configFile,addr,logFile string)error{
 if !loopback(addr){return errors.New("desktop UI must use numeric loopback")}
 if e:=recoverSystemProxy(configFile+".system-proxy-backup");e!=nil{return errors.New("system proxy recovery required before startup")}
 a,e:=newDesktop(configFile);if e!=nil{return e}
 a.logFile=logFile
 listener,e:=net.Listen("tcp",addr);if e!=nil{return e}
 defer listener.Close()
 ticketURL:="http://"+addr+"/open?ticket="+a.secret
 if runtime.GOOS=="windows"{
  go func(){time.Sleep(400*time.Millisecond);_ =exec.Command("rundll32.exe","url.dll,FileProtocolHandler",ticketURL).Start()}()
 }else{
  fmt.Println("AFTAB Desktop: open this local URL in your own browser:",ticketURL)
 }
 event("info","desktop","control_started","ok")
 server:=&http.Server{Handler:a,ReadHeaderTimeout:5*time.Second,ReadTimeout:10*time.Second,WriteTimeout:15*time.Second,IdleTimeout:60*time.Second}
 e=server.Serve(listener)
 a.stop()
 if errors.Is(e,http.ErrServerClosed){return nil}
 return e
}
type desktopView struct {Lang,Dir,Server,Listen,Pin,CSRF,Message,Error string;Running,HasToken,SystemProxy,AutoProxyActive,IsWindows bool;Events []desktopEvent}
var desktopDictionary=map[string]map[string]string{
 "en":{"systemProxy":"Automatically configure Windows browser proxy","proxyNote":"Use this for browser traffic. Some apps ignore system proxy settings.","httpProxy":"HTTP/HTTPS browser proxy: 127.0.0.1:10809","tunnelTest":"Test gateway and account","tunnel_test_ok":"Gateway accepted account and opened outbound TCP.","tunnel_test_failed":"Gateway, account or outbound connection failed.","tunnelTestHelp":"The gateway/account test checks example.com:443 from the server.","logs":"Recent diagnostics","logempty":"No diagnostic events available.","time":"Time","level":"Level","component":"Component","event":"Event","code":"Code","refresh":"Refresh","title":"AFTAB Desktop","subtitle":"Secure networking research","status":"Local proxy","running":"Running","stopped":"Stopped","server":"Gateway host:port","pin":"TLS certificate SHA-256 fingerprint","token":"Account token (leave blank to keep saved token)","save":"Save settings","test":"Test TLS","connect":"Connect","disconnect":"Disconnect","proxy":"Local SOCKS5 endpoint","warning":"Research preview only. This is a browser-managed SOCKS5 proxy, not a system-wide VPN.","saved":"Settings saved","test_ok":"Pinned TLS handshake succeeded","connected":"Local SOCKS proxy started","disconnected":"Proxy stopped","invalid_config":"Review host, token and certificate fingerprint","disconnect_first":"Disconnect before changing settings","save_failed":"Unable to save the configuration","test_failed":"Connection failed or certificate mismatch","connect_failed":"Could not start local proxy. Check the gateway and port.","security":"Client settings are stored in a local configuration file. Keep the computer and files secure.","help":"The gateway must already be reachable, and its certificate fingerprint must match."},
 "fa":{"systemProxy":"تنظیم خودکار پراکسی مرورگرهای ویندوز","proxyNote":"این گزینه ترافیک مرورگرها را پوشش می‌دهد؛ بعضی برنامه‌ها از پراکسی سیستم استفاده نمی‌کنند.","httpProxy":"پراکسی مرورگر HTTP/HTTPS: 127.0.0.1:10809","tunnelTest":"تست درگاه و حساب کاربری","tunnel_test_ok":"درگاه حساب را پذیرفت و اتصال اینترنتی TCP برقرار شد.","tunnel_test_failed":"درگاه، توکن حساب یا اتصال خروجی ناموفق بود.","tunnelTestHelp":"در تست حساب، سرور اتصال به example.com:443 را بررسی می‌کند.","logs":"گزارش خطاهای اخیر","logempty":"هنوز رویدادی ثبت نشده است.","time":"زمان","level":"سطح","component":"بخش","event":"رویداد","code":"کد خطا","refresh":"به‌روزرسانی","title":"آفتاب | کلاینت","subtitle":"پژوهش شبکه امن","status":"پراکسی محلی","running":"فعال","stopped":"متوقف","server":"نشانی سرور و پورت","pin":"اثر انگشت SHA-256 گواهی TLS","token":"توکن حساب (برای حفظ توکن قبلی خالی بگذارید)","save":"ذخیره تنظیمات","test":"تست اتصال TLS","connect":"اتصال","disconnect":"قطع اتصال","proxy":"نشانی پراکسی SOCKS5","warning":"نسخه پژوهشی؛ این برنامه پراکسی SOCKS5 است و هنوز VPN سراسری نیست.","saved":"تنظیمات ذخیره شد","test_ok":"اتصال TLS با اثر انگشت معتبر برقرار شد","connected":"پراکسی محلی راه‌اندازی شد","disconnected":"پراکسی متوقف شد","invalid_config":"نشانی، توکن یا اثر انگشت گواهی را بررسی کنید","disconnect_first":"قبل از تغییر تنظیمات اتصال را قطع کنید","save_failed":"ذخیره تنظیمات ناموفق بود","test_failed":"اتصال ناموفق بود یا اثر انگشت گواهی مطابقت ندارد","connect_failed":"راه‌اندازی پراکسی ناموفق بود؛ سرور و پورت را بررسی کنید","security":"تنظیمات کلاینت در فایل محلی ذخیره می‌شود. از امنیت دستگاه و فایل‌ها اطمینان حاصل کنید.","help":"درگاه سرور باید از قبل قابل دسترس باشد و اثر انگشت گواهی مطابقت داشته باشد."},
 "de":{"systemProxy":"Windows-Browserproxy automatisch konfigurieren","proxyNote":"Für Browser-Verkehr; einige Apps ignorieren System-Proxy-Einstellungen.","httpProxy":"Browser-Proxy HTTP/HTTPS: 127.0.0.1:10809","tunnelTest":"Gateway und Konto testen","tunnel_test_ok":"Gateway hat Konto akzeptiert und TCP-Verbindung geöffnet.","tunnel_test_failed":"Gateway, Konto oder Verbindung fehlgeschlagen.","tunnelTestHelp":"Test prüft example.com:443 vom Server aus.","logs":"Letzte Diagnosen","logempty":"Keine Diagnoseereignisse verfügbar.","time":"Zeit","level":"Stufe","component":"Komponente","event":"Ereignis","code":"Fehlercode","refresh":"Aktualisieren","title":"AFTAB Desktop","subtitle":"Forschung zu sicheren Netzwerken","status":"Lokaler Proxy","running":"Aktiv","stopped":"Gestoppt","server":"Gateway-Adresse und Port","pin":"TLS-Zertifikat SHA-256 Fingerabdruck","token":"Benutzertoken (leer lassen zum Beibehalten)","save":"Einstellungen speichern","test":"TLS testen","connect":"Verbinden","disconnect":"Trennen","proxy":"Lokaler SOCKS5-Endpunkt","warning":"Forschungsversion: SOCKS5-Proxy, noch kein systemweites VPN.","saved":"Einstellungen gespeichert","test_ok":"TLS-Test mit Zertifikat-Pin erfolgreich","connected":"Lokaler Proxy gestartet","disconnected":"Proxy angehalten","invalid_config":"Server, Token und Zertifikat prüfen","disconnect_first":"Vor Änderung Verbindung trennen","save_failed":"Speichern fehlgeschlagen","test_failed":"Verbindung oder Zertifikatsprüfung fehlgeschlagen","connect_failed":"Proxy konnte nicht gestartet werden","security":"Einstellungen liegen in einer lokalen Datei. Schützen Sie Ihren Computer.","help":"Gateway muss erreichbar sein und Zertifikats-Fingerabdruck stimmen."},
 "ar":{"systemProxy":"ضبط وكيل متصفح ويندوز تلقائياً","proxyNote":"لحركة المتصفح؛ بعض التطبيقات تتجاهل إعدادات الوكيل.","httpProxy":"وكيل المتصفح HTTP/HTTPS: 127.0.0.1:10809","tunnelTest":"اختبار البوابة والحساب","tunnel_test_ok":"قبلت البوابة الحساب وفتحت اتصال TCP.","tunnel_test_failed":"فشل اختبار البوابة أو الحساب أو الاتصال.","tunnelTestHelp":"يفحص الاختبار اتصال example.com:443 من الخادم.","logs":"التشخيصات الأخيرة","logempty":"لا توجد أحداث تشخيصية.","time":"الوقت","level":"المستوى","component":"المكون","event":"الحدث","code":"رمز الخطأ","refresh":"تحديث","title":"آفتاب | العميل","subtitle":"أبحاث الشبكات الآمنة","status":"الوكيل المحلي","running":"نشط","stopped":"متوقف","server":"عنوان الخادم والمنفذ","pin":"بصمة شهادة TLS SHA-256","token":"رمز الحساب (اتركه فارغاً للاحتفاظ بالرمز)","save":"حفظ الإعدادات","test":"اختبار TLS","connect":"اتصال","disconnect":"قطع الاتصال","proxy":"وكيل SOCKS5 المحلي","warning":"نسخة بحثية: وكيل SOCKS5 وليس VPN شاملاً للنظام.","saved":"تم حفظ الإعدادات","test_ok":"نجح اختبار TLS مع بصمة الشهادة","connected":"تم تشغيل الوكيل المحلي","disconnected":"توقف الوكيل","invalid_config":"تحقق من الخادم والرمز وبصمة الشهادة","disconnect_first":"اقطع الاتصال قبل تغيير الإعدادات","save_failed":"تعذر حفظ الإعدادات","test_failed":"فشل الاتصال أو التحقق من الشهادة","connect_failed":"تعذر تشغيل الوكيل المحلي","security":"تخزن الإعدادات في ملف محلي. احم جهازك.","help":"يجب أن تكون البوابة متاحة وأن تتطابق بصمة الشهادة."},
}
func desktopTranslation(lang,key string)string{
 if d,ok:=desktopDictionary[lang];ok{if x,ok:=d[key];ok{return x}}
 if x,ok:=desktopDictionary["en"][key];ok{return x}
 return key
}
const desktopHTML=`<!doctype html><html lang="{{.Lang}}" dir="{{.Dir}}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><title>{{tr "title"}}</title><style>
:root{color-scheme:dark;font-family:system-ui,Segoe UI,Tahoma,sans-serif;background:#091126;color:#f0f6ff}*{box-sizing:border-box}body{margin:0;padding:2rem 1rem;background:radial-gradient(ellipse at 20% 10%,#253a67,transparent 48%),#091126;min-height:100vh}.shell{max-width:820px;margin:auto}.top{display:flex;justify-content:space-between;align-items:center;gap:1rem;flex-wrap:wrap}.logo{display:inline-flex;background:linear-gradient(120deg,#579aff,#54dbc3);padding:.3rem .7rem;border-radius:12px;color:#062135;font-weight:900;font-size:1.3rem}h1{font-size:1.5rem;margin:.6rem 0 0}.muted{color:#adbfdf;font-size:.88rem}.card{padding:1.45rem;background:#111d38;border:1px solid #2b4168;border-radius:18px;margin-top:1.4rem;box-shadow:0 18px 38px #0003}h2{font-size:1rem;margin:0 0 1rem}.status{display:flex;align-items:center;gap:.6rem;font-size:1.1rem;font-weight:700}.light{width:10px;height:10px;border-radius:50%;background:#fa8e97}.light.yes{background:#50e9b2;box-shadow:0 0 0 5px #50e9b220}.pill{color:#6de8c7;background:#204144;border-radius:100px;padding:.2rem .6rem;font-size:.7rem}.languages{display:flex;gap:.7rem}.languages a{color:#83cfff;text-decoration:none;font-size:.75rem}form{display:grid;gap:1.1rem}label{display:grid;gap:.4rem;font-size:.85rem;font-weight:600}input{background:#0b1530;border:1px solid #32466e;border-radius:10px;padding:.8rem;color:#fff;font:inherit;min-height:45px;width:100%;direction:ltr;text-align:start}input:focus{outline:2px solid #69c3ff}.actions{display:flex;flex-wrap:wrap;gap:.7rem;margin-top:.5rem}.actions form{display:inline-flex;gap:0}.button{background:#213857;color:#e5edff;border:1px solid #46648c;padding:.75rem 1.25rem;border-radius:10px;cursor:pointer;font-weight:700;font:inherit}.button.main{background:linear-gradient(100deg,#63a8ff,#48dbbf);border:0;color:#041a2b;font-weight:800}.button:disabled{cursor:not-allowed;opacity:.45}.alert{border:1px solid #3b6a72;background:#183d47;padding:.85rem 1rem;border-radius:10px;margin-top:1rem}.alert.bad{background:#4b263c;border-color:#a95676}.warn{font-size:.8rem;color:#a9bfde;padding:1rem 0}.mono{font-family:Consolas,monospace;font-size:.88rem;direction:ltr;overflow-wrap:anywhere}.logTable{overflow-x:auto;margin-top:1rem}table{width:100%;border-collapse:collapse;font-size:.76rem;min-width:560px}th,td{border-bottom:1px solid #324462;text-align:start;padding:.6rem .4rem}.systemProxy{display:flex;flex-direction:row;align-items:center;gap:.7rem}.systemProxy input{width:19px;min-height:19px;flex:none;accent-color:#56e4bb}footer{font-size:.75rem;color:#98accf;padding:1rem 0}@media(max-width:520px){body{padding:1rem}.card{padding:1.1rem}}
</style></head><body><div class="shell"><div class="top"><div><div class="logo">AFTAB</div><h1>{{tr "title"}}</h1><div class="muted">{{tr "subtitle"}}</div></div><div class="languages"><a href="/?lang=fa">FA</a><a href="/?lang=en">EN</a><a href="/?lang=de">DE</a><a href="/?lang=ar">AR</a></div></div>
<div class="card"><h2>{{tr "status"}}</h2><div class="status"><span class="light {{if .Running}}yes{{end}}"></span>{{if .Running}}{{tr "running"}}{{else}}{{tr "stopped"}}{{end}}</div><p class="muted">{{tr "proxy"}}: <span class="mono">{{.Listen}}</span></p><p class="muted">{{tr "httpProxy"}}</p>
{{if .Message}}<div class="alert">{{tr .Message}}</div>{{end}}{{if .Error}}<div class="alert bad" role="alert">{{tr .Error}}</div>{{end}}
<div class="actions"><form method="post" action="/test"><input type="hidden" name="csrf" value="{{.CSRF}}"><button class="button" type="submit">{{tr "test"}}</button></form><form method="post" action="/test-tunnel"><input type="hidden" name="csrf" value="{{.CSRF}}"><button class="button" type="submit">{{tr "tunnelTest"}}</button></form><form method="post" action="/connect"><input type="hidden" name="csrf" value="{{.CSRF}}"><button class="button main" type="submit" {{if .Running}}disabled{{end}}>{{tr "connect"}}</button></form><form method="post" action="/disconnect"><input type="hidden" name="csrf" value="{{.CSRF}}"><button class="button" type="submit" {{if not .Running}}disabled{{end}}>{{tr "disconnect"}}</button></form></div></div>
<div class="card"><h2>{{tr "save"}}</h2><p class="muted">{{tr "help"}}</p><form method="post" action="/save"><input type="hidden" name="csrf" value="{{.CSRF}}"><label>{{tr "server"}}<input name="server" required spellcheck="false" placeholder="127.0.0.1:18443" value="{{.Server}}"></label><label>{{tr "pin"}}<input name="pin" required spellcheck="false" autocomplete="off" value="{{.Pin}}"></label><label>{{tr "token"}}<input type="password" name="token" spellcheck="false" autocomplete="off" {{if not .HasToken}}required{{end}} placeholder="{{if .HasToken}}••••••••{{end}}"></label>{{if .IsWindows}}<label class="systemProxy"><input type="checkbox" name="system_proxy" value="yes" {{if .SystemProxy}}checked{{end}} {{if .Running}}disabled{{end}}><span>{{tr "systemProxy"}}</span></label><p class="muted">{{tr "proxyNote"}}</p>{{end}}<button class="button main" type="submit" {{if .Running}}disabled{{end}}>{{tr "save"}}</button></form></div>
<div class="card"><h2>{{tr "logs"}}</h2><a class="muted" href="/">{{tr "refresh"}}</a>{{if .Events}}<div class="logTable"><table><thead><tr><th>{{tr "time"}}</th><th>{{tr "level"}}</th><th>{{tr "component"}}</th><th>{{tr "event"}}</th><th>{{tr "code"}}</th></tr></thead><tbody>{{range .Events}}<tr><td>{{.Time}}</td><td>{{.Level}}</td><td>{{.Component}}</td><td>{{.Event}}</td><td>{{.Code}}</td></tr>{{end}}</tbody></table></div>{{else}}<p class="muted">{{tr "logempty"}}</p>{{end}}</div>
<footer>{{tr "tunnelTestHelp"}}<p>{{tr "warning"}}</p><p>{{tr "security"}}</p></footer></div></body></html>`
