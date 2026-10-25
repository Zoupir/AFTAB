package main

import (
 "encoding/json"
 "io"
 "os"
 "strings"
)

type desktopEvent struct{Time,Level,Component,Event,Code string}

func readDesktopEvents(path string)[]desktopEvent{
 if path==""{return nil}
 f,e:=os.Open(path);if e!=nil{return nil}
 defer f.Close()
 info,e:=f.Stat();if e!=nil{return nil}
 offset:=info.Size()-512*1024
 if offset<0{offset=0}
 if _,e=f.Seek(offset,io.SeekStart);e!=nil{return nil}
 data,e:=io.ReadAll(io.LimitReader(f,512*1024));if e!=nil{return nil}
 lines:=strings.Split(string(data),"\n")
 if offset>0&&len(lines)>0{lines=lines[1:]}
 out:=make([]desktopEvent,0,30)
 for i:=len(lines)-1;i>=0&&len(out)<30;i--{
  if len(lines[i])==0||len(lines[i])>4096{continue}
  var m map[string]any
  if json.Unmarshal([]byte(lines[i]),&m)!=nil{continue}
  val:=func(key string)string{
   s,_:=m[key].(string)
   if len(s)>100{return s[:100]}
   return s
  }
  out=append(out,desktopEvent{Time:val("time"),Level:val("level"),Component:val("component"),Event:val("event"),Code:val("code")})
 }
 return out
}
