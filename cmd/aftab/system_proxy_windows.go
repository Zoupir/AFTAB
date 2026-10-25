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

const proxyKey=`HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`
type proxyRegistryValue struct {
 Exists bool `json:"exists"`
 Value string `json:"value"`
}
type proxySnapshot struct{
 Enabled proxyRegistryValue `json:"enabled"`
 Server proxyRegistryValue `json:"server"`
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
 _=exec.Command("reg.exe","delete",proxyKey,"/v",name,"/f").Run()
 return nil
}
var wininet=syscall.NewLazyDLL("wininet.dll")
var internetSetOption=wininet.NewProc("InternetSetOptionW")
func announceProxyChange(){
 internetSetOption.Call(0,39,0,0) // INTERNET_OPTION_SETTINGS_CHANGED
 internetSetOption.Call(0,37,0,0) // INTERNET_OPTION_REFRESH
}
func recoverSystemProxy(restorePath string)error{
 raw,e:=os.ReadFile(restorePath)
 if errors.Is(e,os.ErrNotExist){return nil}
 if e!=nil{return e}
 var previous proxySnapshot
 if e=json.Unmarshal(raw,&previous);e!=nil{return e}
 first:=regRestore("ProxyServer","REG_SZ",previous.Server)
 second:=regRestore("ProxyEnable","REG_DWORD",previous.Enabled)
 announceProxyChange()
 if first!=nil{return first}
 if second!=nil{return second}
 return os.Remove(restorePath)
}
func applySystemProxy(restorePath string)error{
 if _,e:=os.Stat(restorePath);e==nil{return errors.New("proxy recovery pending")}
 enabled,e:=regRead("ProxyEnable","REG_DWORD")
 if e!=nil{return e}
 server,e:=regRead("ProxyServer","REG_SZ")
 if e!=nil{return e}
 snapshot,_:=json.Marshal(proxySnapshot{Enabled:enabled,Server:server})
 // Save previous settings before applying changes, for crash recovery.
 if e=os.WriteFile(restorePath,snapshot,0600);e!=nil{return e}
 if e=regSet("ProxyServer","REG_SZ","127.0.0.1:10809");e!=nil{
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
 cmd:=exec.Command(executable,"-mode=proxy-watchdog","-watch-pid",strconv.Itoa(os.Getpid()),"-config",configFile)
 cmd.SysProcAttr=&syscall.SysProcAttr{HideWindow:true}
 if e:=cmd.Start();e!=nil{return e}
 return cmd.Process.Release()
}
func runSystemProxyWatchdog(pid int,restorePath string)error{
 if pid<=0{return errors.New("invalid watchdog process")}
 open:=kernel32.NewProc("OpenProcess")
 wait:=kernel32.NewProc("WaitForSingleObject")
 closeHandle:=kernel32.NewProc("CloseHandle")
 h,_,_:=open.Call(uintptr(0x00100000),0,uintptr(pid))
 if h!=0{
  wait.Call(h,uintptr(0xFFFFFFFF))
  closeHandle.Call(h)
 }
 // If the parent terminates without a clean disconnect, restore the exact
 // proxy settings recorded before activation.
 return recoverSystemProxy(restorePath)
}
