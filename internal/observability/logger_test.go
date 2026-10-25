package observability

import (
 "runtime"
 "bytes"
 "encoding/json"
 "errors"
 "os"
 "path/filepath"
 "strings"
 "testing"
)

func TestStructuredLogsRedactSecrets(t *testing.T){
 p:=filepath.Join(t.TempDir(),"events.jsonl")
 l,e:=New("debug",p);if e!=nil{t.Fatal(e)}
 l.Log("error","gateway","connection_rejected","abc123","auth_failed","token","very-secret-value","destination_host","example.com","attempt",1)
 if e=l.Close();e!=nil{t.Fatal(e)}
 b,e:=os.ReadFile(p);if e!=nil{t.Fatal(e)}
 if bytes.Contains(b,[]byte("very-secret-value"))||bytes.Contains(b,[]byte("example.com")){t.Fatal("secret leaked into logs")}
 var entry map[string]any;if e=json.Unmarshal(bytes.TrimSpace(b),&entry);e!=nil{t.Fatal(e)}
 if entry["component"]!="gateway"||entry["event"]!="connection_rejected"||entry["code"]!="auth_failed"{t.Fatal("missing diagnostic fields")}
 if entry["token"]!="[REDACTED]"||entry["destination_host"]!="[REDACTED]"{t.Fatal("redaction missing")}
 info,e:=os.Stat(p);if e!=nil{t.Fatal(e)}
 if runtime.GOOS!="windows"&&info.Mode().Perm()&0077!=0{t.Fatal("log file permissions too open")}
}
func TestLevelFiltering(t *testing.T){
 p:=filepath.Join(t.TempDir(),"events.jsonl")
 l,e:=New("warn",p);if e!=nil{t.Fatal(e)}
 l.Log("debug","client","start","1","none")
 l.Log("info","client","ready","1","none")
 l.Log("warn","client","retry","1","timeout")
 if e=l.Close();e!=nil{t.Fatal(e)}
 b,e:=os.ReadFile(p);if e!=nil{t.Fatal(e)}
 if strings.Count(string(b),"\n")!=1||!bytes.Contains(b,[]byte("retry")){t.Fatalf("unexpected records: %s",b)}
}
func TestInvalidLevel(t *testing.T){
 _,e:=New("verbose","")
 if !errors.Is(e,ErrInvalidLevel){t.Fatal("invalid level accepted")}
}
