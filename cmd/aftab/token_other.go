//go:build !windows

package main

// Non-Windows preview stores the user token in a private-permission (0600)
// configuration file. Replace this with an OS credential store before release.
func protectToken(raw string)(string,error){return raw,nil}
func unprotectToken(raw string)(string,error){return raw,nil}
