//go:build windows

package main

import (
 "encoding/json"
 "errors"
 "fmt"
 "os"
 "os/exec"
 "strconv"
 "strings"
 "syscall"
)

const proxyKey = `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`
const aftabProxyAddress = "127.0.0.1:10809"

type proxyRegistryValue struct {
 Exists bool `json:"exists"`
 Value string `json:"value"`
}
type proxySnapshot struct {
 Enabled proxyRegistryValue `json:"enabled"`
 Server proxyRegistryValue `json:"server"`
 Generation string `json:"generation,omitempty"`
}

func regRead(name,typ string)(proxyRegistryValue,error){
 b,e:=exec.Command("reg.exe","query",proxyKey,"/v",name).CombinedOutput()
 if e!=nil{
  if ee,ok:=e.(*exec.ExitError);ok&&ee.ExitCode()==1{return proxyRegistryValue{},nil}
  return proxyRegistryValue{},errors.New("cannot inspect existing Windows proxy settings")
 }
 for _,line:=range strings.Split(string(b),"\n"){
  if !strings.Contains(line,name)||!strings.Contains(line,typ){continue}
  raw:=strings.TrimSpace(strings.SplitN(line,typ,2)[1])
  return proxyRegistryValue{Exists:true,Value:raw},nil
 }
 return proxyRegistryValue{},nil
}
func regSet(name,typ,value string)error{
 if e:=exec.Command("reg.exe","add",proxyKey,"/v",name,"/t",typ,"/d",value,"/f").Run();e!=nil{
  return fmt.Errorf("cannot write Windows proxy setting %s: %w",name,e)
 }
 return nil
}
func regRestore(name,typ string,v proxyRegistryValue)error{
 if v.Exists{return regSet(name,typ,v.Value)}
 out,e:=exec.Command("reg.exe","delete",proxyKey,"/v",name,"/f").CombinedOutput()
 if ee,ok:=e.(*exec.ExitError);ok&&ee.ExitCode()==1{return nil} // already absent
 if e!=nil{return fmt.Errorf("cannot delete Windows proxy setting %s: %w (%s)",name,e,strings.TrimSpace(string(out)))}
 return nil
}
var wininet=syscall.NewLazyDLL("wininet.dll")
var internetSetOption=wininet.NewProc("InternetSetOptionW")
func announceProxyChange(){
 internetSetOption.Call(0,39,0,0) // INTERNET_OPTION_SETTINGS_CHANGED
 internetSetOption.Call(0,37,0,0) // INTERNET_OPTION_REFRESH
}

func isAFTABProxy(v proxyRegistryValue)bool{
 return v.Exists&&strings.EqualFold(strings.TrimSpace(v.Value),aftabProxyAddress)
}
func isProxyEnabled(v proxyRegistryValue)bool{
 raw:=strings.TrimSpace(strings.ToLower(v.Value))
 return v.Exists&&(raw=="0x1"||raw=="1"||raw=="0x00000001")
}
// Windows can retain an orphaned AFTAB proxy from a previous crashed session.
// Never restore an enabled proxy targeting AFTAB's own closed listener.
func safePrevious(snapshot proxySnapshot)proxySnapshot{
 if isAFTABProxy(snapshot.Server)&&isProxyEnabled(snapshot.Enabled){
  snapshot.Enabled=proxyRegistryValue{Exists:true,Value:"0"}
 }
 return snapshot
}
func readProxySnapshot(restorePath string)(proxySnapshot,error){
 b,e:=os.ReadFile(restorePath)
 if e!=nil{return proxySnapshot{},e}
 var p proxySnapshot
 if e=json.Unmarshal(b,&p);e!=nil{return proxySnapshot{},e}
 return p,nil
}
// Safe fallback for an interrupted restore: only disable the proxy if it still
// points to AFTAB itself, never reset an unrelated third-party proxy.
func disableStaleAFTABProxy()error{
 current,e:=regRead("ProxyServer","REG_SZ")
 if e!=nil{return e}
 if !isAFTABProxy(current){return nil}
 if e=regSet("ProxyEnable","REG_DWORD","0");e!=nil{return e}
 announceProxyChange()
 return nil
}
func recoverSystemProxy(restorePath string)error{
 previous,e:=readProxySnapshot(restorePath)
 if errors.Is(e,os.ErrNotExist){return nil}
 if e!=nil{
  _=disableStaleAFTABProxy()
  return fmt.Errorf("invalid system proxy recovery snapshot: %w",e)
 }
 previous=safePrevious(previous)
 first:=regRestore("ProxyServer","REG_SZ",previous.Server)
 second:=regRestore("ProxyEnable","REG_DWORD",previous.Enabled)
 announceProxyChange()
 if first!=nil||second!=nil{
  _=disableStaleAFTABProxy()
  return errors.Join(first,second)
 }
 return os.Remove(restorePath)
}
func applySystemProxy(restorePath string)error{
 if _,e:=os.Stat(restorePath);e==nil{return errors.New("proxy recovery pending")}else if !errors.Is(e,os.ErrNotExist){return e}
 enabled,e:=regRead("ProxyEnable","REG_DWORD")
 if e!=nil{return e}
 server,e:=regRead("ProxyServer","REG_SZ")
 if e!=nil{return e}
 previous:=safePrevious(proxySnapshot{Enabled:enabled,Server:server,Generation:newToken()})
 snapshot,_:=json.Marshal(previous)
 // Save previous settings BEFORE enabling the local proxy.
 if e=os.WriteFile(restorePath,snapshot,0600);e!=nil{return e}
 if e=regSet("ProxyServer","REG_SZ",aftabProxyAddress);e!=nil{
  _=recoverSystemProxy(restorePath)
  return e
 }
 if e=regSet("ProxyEnable","REG_DWORD","1");e!=nil{
  _=recoverSystemProxy(restorePath)
  return e
 }
 announceProxyChange()
 return nil
}

func startSystemProxyWatchdog(configFile string)error{
 executable,e:=os.Executable()
 if e!=nil{return e}
 restorePath:=configFile+".system-proxy-backup"
 snapshot,e:=readProxySnapshot(restorePath)
 if e!=nil{return e}
 if len(snapshot.Generation)!=64{return errors.New("invalid system proxy recovery generation")}
 cmd:=exec.Command(executable,"-mode=proxy-watchdog","-watch-pid",strconv.Itoa(os.Getpid()),"-watch-generation",snapshot.Generation,"-config",configFile)
 cmd.SysProcAttr=&syscall.SysProcAttr{HideWindow:true}
 if e:=cmd.Start();e!=nil{return e}
 return cmd.Process.Release()
}
func runSystemProxyWatchdog(pid int,restorePath,generation string)error{
 if pid<=0||len(generation)!=64{return errors.New("invalid watchdog arguments")}
 open:=kernel32.NewProc("OpenProcess")
 wait:=kernel32.NewProc("WaitForSingleObject")
 closeHandle:=kernel32.NewProc("CloseHandle")
 h,_,e:=open.Call(uintptr(0x00100000),0,uintptr(pid)) // SYNCHRONIZE
 if h==0{return fmt.Errorf("could not monitor AFTAB parent: %w",e)}
 defer closeHandle.Call(h)
 for {
  current,err:=readProxySnapshot(restorePath)
  if errors.Is(err,os.ErrNotExist){return nil} // normal Disconnect
  if err!=nil{return err}
  if current.Generation!=generation{return nil} // another Connect cycle
  result,_,_:=wait.Call(h,750)
  if result==0{ // WAIT_OBJECT_0, original parent has exited
   current,err=readProxySnapshot(restorePath)
   if errors.Is(err,os.ErrNotExist){return nil}
   if err!=nil{return err}
   if current.Generation!=generation{return nil}
   return recoverSystemProxy(restorePath)
  }
  if result!=0x102{return errors.New("watchdog wait failed")} // WAIT_TIMEOUT
 }
}
