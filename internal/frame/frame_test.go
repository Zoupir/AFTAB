package frame

import (
 "bytes"
 "encoding/binary"
 "errors"
 "io"
 "testing"
)

func TestRoundTrip(t *testing.T){
 original:=Frame{Session:42,Sequence:7,Payload:[]byte("aftab")}
 var b bytes.Buffer
 if e:=Write(&b,original);e!=nil{t.Fatal(e)}
 got,e:=Read(&b);if e!=nil{t.Fatal(e)}
 if got.Session!=original.Session||got.Sequence!=original.Sequence||!bytes.Equal(got.Payload,original.Payload){t.Fatalf("roundtrip mismatch: %+v",got)}
}
func TestBoundaries(t *testing.T){
 var b bytes.Buffer
 if e:=Write(&b,Frame{Payload:make([]byte,MaxPayload)});e!=nil{t.Fatal(e)}
 if _,e:=Read(&b);e!=nil{t.Fatal(e)}
 if e:=Write(io.Discard,Frame{Payload:make([]byte,MaxPayload+1)});!errors.Is(e,ErrTooLarge){t.Fatal("oversize was not rejected")}
}
func TestRejectMalformed(t *testing.T){
 var b bytes.Buffer
 _=Write(&b,Frame{Payload:[]byte("abcdef")})
 original:=b.Bytes()
 cases:=[][]byte{nil,original[:2],append([]byte{},original[:len(original)-1]...)}
 badVersion:=append([]byte{},original...);badVersion[2]=2
 cases=append(cases,badVersion)
 badLength:=append([]byte{},original...);binary.BigEndian.PutUint32(badLength[HeaderSize:],MaxPayload+1)
 cases=append(cases,badLength)
 for i,data:=range cases{if _,e:=Read(bytes.NewReader(data));e==nil{t.Fatalf("case %d accepted",i)}}
}
func FuzzRead(f *testing.F){
 var b bytes.Buffer
 _=Write(&b,Frame{Session:1,Sequence:2,Payload:[]byte("seed")})
 f.Add(b.Bytes());f.Add([]byte("bad"))
 f.Fuzz(func(t *testing.T, data []byte){_,_ =Read(bytes.NewReader(data))})
}
