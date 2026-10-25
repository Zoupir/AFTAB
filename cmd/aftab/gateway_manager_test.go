package main

import (
 "errors"
 "net"
 "os"
 "path/filepath"
 "testing"
)

func vacantPort(t *testing.T)int{
 t.Helper()
 ln,e:=net.Listen("tcp","127.0.0.1:0")
 if e!=nil{t.Fatal(e)}
 defer ln.Close()
 return ln.Addr().(*net.TCPAddr).Port
}
func TestGraphicalGatewayStartTestStopAndRestore(t *testing.T){
 folder:=t.TempDir()
 dbPath:=filepath.Join(folder,"account.json")
 s,e:=load(dbPath)
 if e!=nil{t.Fatal(e)}
 mgr:=newGatewayManager(s,dbPath)
 port:=vacantPort(t)
 if e=mgr.Start(port,false);e!=nil{t.Fatal("start: ",e)}
 defer mgr.Stop()
 st:=mgr.Status()
 if !st.Running||st.Public||len(st.Fingerprint)!=64{t.Fatalf("wrong gateway status: %+v",st)}
 if e=mgr.Test();e!=nil{t.Fatal("local TLS handshake: ",e)}
 if _,e=os.Stat(mgr.settingsPath);e!=nil{t.Fatal("missing persisted gateway settings:",e)}
 if e=mgr.Stop();e!=nil{t.Fatal(e)}
 if mgr.Status().Running{t.Fatal("gateway did not stop")}
 if _,e=os.Stat(mgr.settingsPath);!errors.Is(e,os.ErrNotExist){t.Fatal("shutdown did not disable autostart")}
 if e=mgr.Boot();e!=nil{t.Fatal(e)}
 if mgr.Status().Running{t.Fatal("stopped gateway restarted unexpectedly")}
 if e=mgr.Start(port,false);e!=nil{t.Fatal("restart: ",e)}
 _=mgr.listener.Close() // Simulate service termination while retaining settings.
 reloaded:=newGatewayManager(s,dbPath)
 if e=reloaded.Boot();e!=nil{t.Fatal("boot persisted gateway: ",e)}
 defer reloaded.Stop()
 if e=reloaded.Test();e!=nil{t.Fatal("restored TLS probe: ",e)}
}
