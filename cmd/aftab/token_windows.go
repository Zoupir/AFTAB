//go:build windows

package main

import (
 "encoding/base64"
 "errors"
 "fmt"
 "syscall"
 "unsafe"
)

type dpapiBlob struct{
 Size uint32
 Data *byte
}
var (
 crypt32=syscall.NewLazyDLL("crypt32.dll")
 protectProc=crypt32.NewProc("CryptProtectData")
 unprotectProc=crypt32.NewProc("CryptUnprotectData")
 kernel32=syscall.NewLazyDLL("kernel32.dll")
 freeProc=kernel32.NewProc("LocalFree")
)
func dataBlob(b []byte)dpapiBlob{
 if len(b)==0{return dpapiBlob{}}
 return dpapiBlob{Size:uint32(len(b)),Data:&b[0]}
}
func callDPAPI(proc *syscall.LazyProc,data []byte)([]byte,error){
 input:=dataBlob(data)
 var output dpapiBlob
 success,_,err:=proc.Call(
  uintptr(unsafe.Pointer(&input)),0,0,0,0,
  uintptr(1),
  uintptr(unsafe.Pointer(&output)),
 )
 if success==0{
  if err!=nil&&err!=syscall.Errno(0){return nil,err}
  return nil,errors.New("Windows credential protection failed")
 }
 defer freeProc.Call(uintptr(unsafe.Pointer(output.Data)))
 if output.Size==0||output.Data==nil{return nil,errors.New("empty protected credential")}
 result:=make([]byte,int(output.Size))
 copy(result,unsafe.Slice(output.Data,int(output.Size)))
 return result,nil
}
func protectToken(raw string)(string,error){
 if raw==""{return "",nil}
 protected,e:=callDPAPI(protectProc,[]byte(raw))
 if e!=nil{return "",fmt.Errorf("protecting Windows account token: %w",e)}
 return "dpapi:"+base64.StdEncoding.EncodeToString(protected),nil
}
func unprotectToken(raw string)(string,error){
 if raw==""{return "",nil}
 if len(raw)<6||raw[:6]!="dpapi:"{return "",errors.New("unprotected Windows token rejected")}
 decoded,e:=base64.StdEncoding.DecodeString(raw[6:]);if e!=nil{return "",e}
 plain,e:=callDPAPI(unprotectProc,decoded)
 if e!=nil{return "",fmt.Errorf("reading Windows account token: %w",e)}
 return string(plain),nil
}
