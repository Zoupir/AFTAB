package controlplane

import (
 "context"
 "crypto/rand"
 "crypto/sha256"
 "database/sql"
 "encoding/hex"
 "errors"
 "fmt"
 "path/filepath"
 "regexp"
 "strings"
 "time"

 _ "modernc.org/sqlite"
)

var (
 ErrExists = errors.New("account already exists")
 ErrMissing = errors.New("account not found")
 ErrInactive = errors.New("account disabled, expired or over quota")
 safeName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$`)
)

type Account struct {
 ID string `json:"id"`
 Name string `json:"name"`
 Device string `json:"device"`
 UUID string `json:"uuid"`
 QuotaBytes int64 `json:"quota_bytes"`
 UsedBytes int64 `json:"used_bytes"`
 ExpiresAt string `json:"expires_at"`
 Disabled bool `json:"disabled"`
 CreatedAt string `json:"created_at"`
}
type Store struct{ db *sql.DB }
func Open(path string)(*Store,error){
 if strings.TrimSpace(path)==""{return nil,errors.New("database path required")}
 absolute,e:=filepath.Abs(path);if e!=nil{return nil,e}
 db,e:=sql.Open("sqlite",absolute);if e!=nil{return nil,e}
 db.SetMaxOpenConns(1)
 statements:=[]string{
  "PRAGMA journal_mode=WAL",
  "PRAGMA busy_timeout=5000",
  "PRAGMA foreign_keys=ON",
  `CREATE TABLE IF NOT EXISTS accounts (
     id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, device TEXT NOT NULL,
     uuid TEXT NOT NULL UNIQUE, subscription_hash TEXT NOT NULL UNIQUE,
     quota_bytes INTEGER NOT NULL, used_bytes INTEGER NOT NULL DEFAULT 0,
     expires_at TEXT NOT NULL, disabled INTEGER NOT NULL DEFAULT 0,
     created_at TEXT NOT NULL
   )`,
  "CREATE INDEX IF NOT EXISTS accounts_expires_idx ON accounts(expires_at)",
 }
 for _,q:=range statements{
  if _,e=db.Exec(q);e!=nil{_=db.Close();return nil,fmt.Errorf("sqlite migration: %w",e)}
 }
 return &Store{db:db},nil
}
func(s *Store)Close()error{return s.db.Close()}
func randomBytes(n int)[]byte{b:=make([]byte,n);if _,e:=rand.Read(b);e!=nil{panic(e)};return b}
func UUID()string{
 b:=randomBytes(16);b[6]=(b[6]&0x0f)|0x40;b[8]=(b[8]&0x3f)|0x80
 return fmt.Sprintf("%x-%x-%x-%x-%x",b[:4],b[4:6],b[6:8],b[8:10],b[10:16])
}
func Token()string{return hex.EncodeToString(randomBytes(32))}
func tokenHash(t string)string{h:=sha256.Sum256([]byte(t));return hex.EncodeToString(h[:])}
func validToken(t string)bool{if len(t)!=64{return false};_,e:=hex.DecodeString(t);return e==nil}
func(s *Store)Create(ctx context.Context,name,device string,days int,gb int64)(Account,string,error){
 if !safeName.MatchString(name)||device!="windows"&&device!="android"&&device!="other"||days<1||days>3650||gb<1||gb>100000 {return Account{},"",errors.New("invalid account specification")}
 now:=time.Now().UTC()
 a:=Account{ID:UUID(),Name:name,Device:device,UUID:UUID(),QuotaBytes:gb*1073741824,ExpiresAt:now.AddDate(0,0,days).Format(time.RFC3339),CreatedAt:now.Format(time.RFC3339)}
 token:=Token()
 _,e:=s.db.ExecContext(ctx,`INSERT INTO accounts(id,name,device,uuid,subscription_hash,quota_bytes,expires_at,created_at)
 VALUES(?,?,?,?,?,?,?,?)`,a.ID,a.Name,a.Device,a.UUID,tokenHash(token),a.QuotaBytes,a.ExpiresAt,a.CreatedAt)
 if e!=nil{
  if strings.Contains(strings.ToLower(e.Error()),"unique"){return Account{},"",ErrExists}
  return Account{},"",e
 }
 return a,token,nil
}
func scanAccount(scanner interface{Scan(...any)error})(Account,error){
 var a Account;var disabled int
 e:=scanner.Scan(&a.ID,&a.Name,&a.Device,&a.UUID,&a.QuotaBytes,&a.UsedBytes,&a.ExpiresAt,&disabled,&a.CreatedAt)
 a.Disabled=disabled!=0;return a,e
}
const fields="id,name,device,uuid,quota_bytes,used_bytes,expires_at,disabled,created_at"
func(s *Store)List(ctx context.Context)([]Account,error){
 rows,e:=s.db.QueryContext(ctx,"SELECT "+fields+" FROM accounts ORDER BY created_at DESC,name ASC")
 if e!=nil{return nil,e}
 defer rows.Close()
 accounts:=[]Account{}
 for rows.Next(){a,e:=scanAccount(rows);if e!=nil{return nil,e};accounts=append(accounts,a)}
 return accounts,rows.Err()
}
func(s *Store)Disable(ctx context.Context,id string)error{
 r,e:=s.db.ExecContext(ctx,"UPDATE accounts SET disabled=1 WHERE id=?",id)
 if e!=nil{return e}
 n,e:=r.RowsAffected();if e!=nil{return e}
 if n==0{return ErrMissing};return nil
}
func(s *Store)LookupSubscription(ctx context.Context,token string)(Account,error){
 if !validToken(token){return Account{},ErrMissing}
 a,e:=scanAccount(s.db.QueryRowContext(ctx,"SELECT "+fields+" FROM accounts WHERE subscription_hash=?",tokenHash(token)))
 if errors.Is(e,sql.ErrNoRows){return Account{},ErrMissing}
 if e!=nil{return Account{},e}
 expiry,e:=time.Parse(time.RFC3339,a.ExpiresAt)
 if e!=nil||a.Disabled||!expiry.After(time.Now().UTC())||a.UsedBytes>=a.QuotaBytes{return Account{},ErrInactive}
 return a,nil
}
func(s *Store)SetUsage(ctx context.Context,id string,used int64)error{
 if used<0{return errors.New("negative usage")}
 r,e:=s.db.ExecContext(ctx,"UPDATE accounts SET used_bytes=MAX(used_bytes, ?) WHERE id=?",used,id)
 if e!=nil{return e};n,e:=r.RowsAffected();if e!=nil{return e};if n==0{return ErrMissing};return nil
}
