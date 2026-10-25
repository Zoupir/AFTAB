// Package frame defines bounded, versioned AFTAB research frames.
// This is framing only, not encryption, authentication, or anti-replay.
package frame

import (
 "encoding/binary"
 "errors"
 "io"
)

const Version byte = 1
const HeaderSize = 15
const MaxPayload = 65536

var ErrInvalid = errors.New("invalid AFTAB frame")
var ErrTooLarge = errors.New("AFTAB frame too large")

type Frame struct {
 Session uint64
 Sequence uint32
 Payload []byte
}

func Write(w io.Writer, f Frame) error {
 if len(f.Payload)>MaxPayload {return ErrTooLarge}
 var header [HeaderSize]byte
 header[0]='A'; header[1]='F'; header[2]=Version
 binary.BigEndian.PutUint64(header[3:11],f.Session)
 binary.BigEndian.PutUint32(header[11:15],f.Sequence)
 // The payload length is encoded in a separate 4-byte field.
 var size [4]byte
 binary.BigEndian.PutUint32(size[:],uint32(len(f.Payload)))
 if e:=writeAll(w,header[:]);e!=nil{return e}
 if e:=writeAll(w,size[:]);e!=nil{return e}
 return writeAll(w,f.Payload)
}

func Read(r io.Reader)(Frame,error){
 var f Frame
 var header [HeaderSize]byte
 if _,e:=io.ReadFull(r,header[:]);e!=nil{return f,e}
 if header[0]!='A'||header[1]!='F'||header[2]!=Version{return f,ErrInvalid}
 var size [4]byte
 if _,e:=io.ReadFull(r,size[:]);e!=nil{return f,e}
 n:=binary.BigEndian.Uint32(size[:])
 if n>MaxPayload {return f,ErrTooLarge}
 f.Session=binary.BigEndian.Uint64(header[3:11])
 f.Sequence=binary.BigEndian.Uint32(header[11:15])
 f.Payload=make([]byte,n)
 _,e:=io.ReadFull(r,f.Payload)
 return f,e
}

func writeAll(w io.Writer, p []byte) error {
 for len(p)>0 {
  n,e:=w.Write(p)
  if n<0||n>len(p){return io.ErrShortWrite}
  p=p[n:]
  if e!=nil{return e}
  if n==0{return io.ErrShortWrite}
 }
 return nil
}
