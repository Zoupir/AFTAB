package main

import (
 "net"
 "sync"
)

// gatewaySessions ensures shutdown waits until all accepted connections
// have released their sockets and completed usage accounting.
type gatewaySessions struct{
 mu sync.Mutex
 clients map[net.Conn]struct{}
 wg sync.WaitGroup
 closed bool
}
func newGatewaySessions()*gatewaySessions{
 return &gatewaySessions{clients:make(map[net.Conn]struct{})}
}
func(t *gatewaySessions) add(c net.Conn)bool{
 t.mu.Lock();defer t.mu.Unlock()
 if t.closed{return false}
 t.clients[c]=struct{}{}
 t.wg.Add(1)
 return true
}
func(t *gatewaySessions) done(c net.Conn){
 defer t.wg.Done()
 t.mu.Lock();delete(t.clients,c);t.mu.Unlock()
}
func(t *gatewaySessions) shutdown(){
 t.mu.Lock()
 t.closed=true
 for c:=range t.clients{_ =c.Close()}
 t.mu.Unlock()
 t.wg.Wait()
}
