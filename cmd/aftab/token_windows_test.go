//go:build windows

package main

import (
 "strings"
 "testing"
)

func TestWindowsDPAPICredentialRoundTrip(t *testing.T){
 original:="private-research-token-0123456789"
 stored,e:=protectToken(original)
 if e!=nil{t.Fatal(e)}
 if !strings.HasPrefix(stored,"dpapi:")||strings.Contains(stored,original){t.Fatal("Windows token was not encrypted")}
 got,e:=unprotectToken(stored)
 if e!=nil{t.Fatal(e)}
 if got!=original{t.Fatal("Windows credential could not be recovered")}
 if _,e:=unprotectToken(original);e==nil{t.Fatal("plaintext credential silently accepted")}
}
