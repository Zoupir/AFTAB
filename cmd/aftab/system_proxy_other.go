//go:build !windows

package main

import "errors"

func recoverSystemProxy(string)error{return nil}
func applySystemProxy(string)error{return errors.New("automatic system proxy is supported only on Windows")}

func startSystemProxyWatchdog(string)error{return nil}
func runSystemProxyWatchdog(int,string,string)error{return errors.New("Windows-only watchdog")}
