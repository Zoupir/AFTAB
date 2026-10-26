//go:build windows

package main

import (
 "os"
 "path/filepath"
 "strings"
 "testing"
)

// This runs only on a throwaway Windows GitHub Actions runner.
// It restores the previous user proxy settings even on failure.
func TestWindowsProxyApplyAndRestore(t *testing.T){
 backup:=filepath.Join(t.TempDir(),"system-proxy-backup.json")
 enabledBefore,e:=regRead("ProxyEnable","REG_DWORD")
 if e!=nil{t.Fatal(e)}
 serverBefore,e:=regRead("ProxyServer","REG_SZ")
 if e!=nil{t.Fatal(e)}
 defer func(){
  if _,e:=os.Stat(backup);e==nil{
   if e:=recoverSystemProxy(backup);e!=nil{t.Errorf("cleanup failed: %v",e)}
  }
 }()
 if e:=applySystemProxy(backup);e!=nil{t.Fatal(e)}
 setEnabled,e:=regRead("ProxyEnable","REG_DWORD")
 if e!=nil{t.Fatal(e)}
 setServer,e:=regRead("ProxyServer","REG_SZ")
 if e!=nil{t.Fatal(e)}
 if !setEnabled.Exists||!strings.Contains(setEnabled.Value,"0x1"){t.Fatalf("WinINET proxy was not enabled: %+v",setEnabled)}
 if !setServer.Exists||setServer.Value!="127.0.0.1:10809"{t.Fatalf("wrong HTTP proxy: %+v",setServer)}
 if e:=recoverSystemProxy(backup);e!=nil{t.Fatal(e)}
 enabledAfter,e:=regRead("ProxyEnable","REG_DWORD")
 if e!=nil{t.Fatal(e)}
 serverAfter,e:=regRead("ProxyServer","REG_SZ")
 if e!=nil{t.Fatal(e)}
 if enabledAfter!=enabledBefore||serverAfter!=serverBefore{
  t.Fatalf("original system proxy not restored: before=%+v/%+v after=%+v/%+v",enabledBefore,serverBefore,enabledAfter,serverAfter)
 }
}


func TestSafePreviousDisablesOrphanedAFTABListener(t *testing.T){
 stale:=proxySnapshot{
  Enabled:proxyRegistryValue{Exists:true,Value:"0x1"},
  Server:proxyRegistryValue{Exists:true,Value:aftabProxyAddress},
  Generation:"abcdef",
 }
 cleaned:=safePrevious(stale)
 if !cleaned.Enabled.Exists||isProxyEnabled(cleaned.Enabled){t.Fatal("stale AFTAB proxy must not be restored enabled")}
 other:=proxySnapshot{
  Enabled:proxyRegistryValue{Exists:true,Value:"0x1"},
  Server:proxyRegistryValue{Exists:true,Value:"proxy.company.invalid:3128"},
 }
 if got:=safePrevious(other);got!=other{t.Fatal("unrelated Windows proxy settings were modified")}
}

func TestProxySnapshotHasPerConnectionGeneration(t *testing.T){
 path:=filepath.Join(t.TempDir(),"system-proxy-backup")
 originalEnable,e:=regRead("ProxyEnable","REG_DWORD");if e!=nil{t.Fatal(e)}
 originalServer,e:=regRead("ProxyServer","REG_SZ");if e!=nil{t.Fatal(e)}
 defer func(){
  _=regRestore("ProxyServer","REG_SZ",originalServer)
  _=regRestore("ProxyEnable","REG_DWORD",originalEnable)
  announceProxyChange()
 }()
 for i:=0;i<2;i++{
  if e=applySystemProxy(path);e!=nil{t.Fatal(e)}
  snap,err:=readProxySnapshot(path)
  if err!=nil||len(snap.Generation)!=64{t.Fatalf("missing per-session recovery generation: %v",err)}
  if e=recoverSystemProxy(path);e!=nil{t.Fatal(e)}
 }
}

func TestRecoveryNeverReenablesStaleAFTABProxy(t *testing.T){
 path:=filepath.Join(t.TempDir(),"system-proxy-backup")
 originalEnable,e:=regRead("ProxyEnable","REG_DWORD");if e!=nil{t.Fatal(e)}
 originalServer,e:=regRead("ProxyServer","REG_SZ");if e!=nil{t.Fatal(e)}
 defer func(){
  _=regRestore("ProxyServer","REG_SZ",originalServer)
  _=regRestore("ProxyEnable","REG_DWORD",originalEnable)
  announceProxyChange()
 }()
 if e=regSet("ProxyServer","REG_SZ",aftabProxyAddress);e!=nil{t.Fatal(e)}
 if e=regSet("ProxyEnable","REG_DWORD","1");e!=nil{t.Fatal(e)}
 if e=applySystemProxy(path);e!=nil{t.Fatal(e)}
 if e=recoverSystemProxy(path);e!=nil{t.Fatal(e)}
 enabled,e:=regRead("ProxyEnable","REG_DWORD");if e!=nil{t.Fatal(e)}
 if isProxyEnabled(enabled){t.Fatal("Disconnect restored a stale and unusable AFTAB proxy")}
}
