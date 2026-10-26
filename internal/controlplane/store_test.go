package controlplane

import (
 "context"
 "errors"
 "os"
 "path/filepath"
 "strings"
 "testing"
 "time"
)

func TestCreateListPersistDisable(t *testing.T){
 db:=filepath.Join(t.TempDir(),"secure","aftab.sqlite")
 s,e:=Open(db);if e!=nil{t.Fatal(e)}
 ctx:=context.Background()
 a,token,e:=s.Create(ctx,"ali-phone","android",30,20)
 if e!=nil{t.Fatal(e)}
 if len(token)!=64||len(a.UUID)!=36||a.UsedBytes!=0||a.QuotaBytes!=20*1073741824{t.Fatalf("invalid created account: %+v",a)}
 fi,e:=os.Stat(db);if e!=nil{t.Fatal(e)}
 if fi.Mode().Perm()!=0600{t.Fatalf("SQLite database is not private: %o",fi.Mode().Perm())}
 rows,e:=s.List(ctx);if e!=nil{t.Fatal(e)}
 if len(rows)!=1||rows[0].Name!="ali-phone"{t.Fatalf("unexpected list %+v",rows)}
 if strings.Contains(strings.Join([]string{rows[0].UUID,rows[0].ID,rows[0].Name}," "),token){t.Fatal("leaked subscription secret in list")}
 if _,_,e:=s.Create(ctx,"ali-phone","windows",30,5);!errors.Is(e,ErrExists){t.Fatalf("duplicate not rejected: %v",e)}
 if _,e:=s.LookupSubscription(ctx,token);e!=nil{t.Fatal(e)}
 if _,e:=s.LookupSubscription(ctx,"not-a-token");!errors.Is(e,ErrMissing){t.Fatal(e)}
 if e:=s.Close();e!=nil{t.Fatal(e)}
 s,e=Open(db);if e!=nil{t.Fatal(e)}
 defer s.Close()
 if _,e:=s.LookupSubscription(ctx,token);e!=nil{t.Fatalf("account did not survive restart: %v",e)}
 if e:=s.Disable(ctx,a.ID);e!=nil{t.Fatal(e)}
 if _,e:=s.LookupSubscription(ctx,token);!errors.Is(e,ErrInactive){t.Fatalf("disabled token remained valid: %v",e)}
}
func TestAccountValidationAndQuota(t *testing.T){
 s,e:=Open(filepath.Join(t.TempDir(),"test.db"));if e!=nil{t.Fatal(e)}
 defer s.Close()
 ctx:=context.Background()
 for _,name:=range []string{"","../private","bad name","bad\nname","⚡"}{
  if _,_,e:=s.Create(ctx,name,"windows",30,1);e==nil{t.Fatalf("accepted unsafe name %q",name)}
 }
 if _,_,e:=s.Create(ctx,"valid","ios",30,1);e==nil{t.Fatal("unsupported device accepted")}
 if _,_,e:=s.Create(ctx,"valid","windows",0,1);e==nil{t.Fatal("zero duration accepted")}
 a,token,e:=s.Create(ctx,"valid","windows",30,1);if e!=nil{t.Fatal(e)}
 if a.ExpiresAt==""{t.Fatal("expiry omitted")}
 if _,e:=time.Parse(time.RFC3339,a.ExpiresAt);e!=nil{t.Fatal(e)}
 if e:=s.SetUsage(ctx,a.ID,1073741824);e!=nil{t.Fatal(e)}
 if _,e:=s.LookupSubscription(ctx,token);!errors.Is(e,ErrInactive){t.Fatalf("overquota account accepted %v",e)}
 if e:=s.SetUsage(ctx,a.ID,10);e!=nil{t.Fatal(e)}
 rows,e:=s.List(ctx);if e!=nil{t.Fatal(e)}
 if rows[0].UsedBytes!=1073741824{t.Fatal("usage must be monotonic")}
}
