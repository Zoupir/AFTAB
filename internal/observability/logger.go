// Package observability provides privacy-preserving structured diagnostics.
package observability

import (
 "crypto/rand"
 "encoding/hex"
 "errors"
 "io"
 "log/slog"
 "os"
 "strings"
 "sync"
)

var ErrInvalidLevel=errors.New("invalid log level")
type Logger struct {
 log *slog.Logger
 mu sync.Mutex
 out io.Closer
}
func New(level,filename string)(*Logger,error){
 var parsed slog.Level
 switch strings.ToLower(level) {
 case "debug": parsed=slog.LevelDebug
 case "info","": parsed=slog.LevelInfo
 case "warn": parsed=slog.LevelWarn
 case "error": parsed=slog.LevelError
 default:return nil,ErrInvalidLevel
 }
 var output io.Writer=os.Stderr
 var closer io.Closer
 if filename!=""{
  f,e:=os.OpenFile(filename,os.O_APPEND|os.O_CREATE|os.O_WRONLY,0600)
  if e!=nil{return nil,e}
  output=f;closer=f
 }
 opts:=&slog.HandlerOptions{Level:parsed,ReplaceAttr:func(groups []string,a slog.Attr)slog.Attr{
  // Eliminate accidental secret fields, including on error paths.
  name:=strings.ToLower(a.Key)
  for _,s:=range []string{"token","password","secret","key","authorization","cookie","payload","host","destination","ip","address"}{
   if strings.Contains(name,s){return slog.String(a.Key,"[REDACTED]")}
  }
  return a
 }}
 return &Logger{log:slog.New(slog.NewJSONHandler(output,opts)),out:closer},nil
}
func(l *Logger) Close()error{l.mu.Lock();defer l.mu.Unlock();if l.out!=nil{return l.out.Close()};return nil}
func(l *Logger) Log(level,component,event,requestID,code string,fields ...any){
 args:=[]any{"component",component,"event",event,"request_id",requestID,"code",code}
 args=append(args,fields...)
 switch level{
 case "debug":l.log.Debug("aftab",args...)
 case "warn":l.log.Warn("aftab",args...)
 case "error":l.log.Error("aftab",args...)
 default:l.log.Info("aftab",args...)
 }
}
func ID()string{var b [12]byte;if _,err:=rand.Read(b[:]);err!=nil{return "unavailable"};return hex.EncodeToString(b[:])}
