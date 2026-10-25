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
