package dc

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

// dnsRelay forwards DNS queries from 127.0.0.1:53 to upstream (UDP and
// TCP) while it runs. The DC container resolves through itself
// (resolv.conf: 127.0.0.1), but during a join nothing answers there yet and
// samba-tool must resolve the existing DCs: the relay sends those queries
// to SC_JOIN_DC for the duration of the join.
type dnsRelay struct {
	udp *net.UDPConn
	tcp *net.TCPListener
	wg  sync.WaitGroup
}

func startDNSRelay(ctx context.Context, listen, upstream string) (*dnsRelay, error) {
	return startDNSRelayPort(ctx, listen, upstream, 53)
}

func startDNSRelayPort(ctx context.Context, listen, upstream string, port int) (*dnsRelay, error) {
	ua, err := net.ResolveUDPAddr("udp", listen)
	if err != nil {
		return nil, err
	}
	uc, err := net.ListenUDP("udp", ua)
	if err != nil {
		return nil, err
	}
	ta, _ := net.ResolveTCPAddr("tcp", listen)
	tl, err := net.ListenTCP("tcp", ta)
	if err != nil {
		_ = uc.Close()
		return nil, err
	}
	r := &dnsRelay{udp: uc, tcp: tl}
	r.wg.Add(2)
	up := net.JoinHostPort(upstream, strconv.Itoa(port))
	go r.serveUDP(up)
	go r.serveTCP(up)
	go func() { <-ctx.Done(); r.Close() }()
	return r, nil
}

func (r *dnsRelay) serveUDP(upstream string) {
	defer r.wg.Done()
	buf := make([]byte, 65535)
	for {
		n, from, err := r.udp.ReadFromUDP(buf)
		if err != nil {
			return
		}
		q := append([]byte(nil), buf[:n]...)
		go func() {
			c, err := net.DialTimeout("udp", upstream, 5*time.Second)
			if err != nil {
				return
			}
			defer func() { _ = c.Close() }()
			_ = c.SetDeadline(time.Now().Add(5 * time.Second))
			if _, err := c.Write(q); err != nil {
				return
			}
			resp := make([]byte, 65535)
			m, err := c.Read(resp)
			if err != nil {
				return
			}
			_, _ = r.udp.WriteToUDP(resp[:m], from)
		}()
	}
}

func (r *dnsRelay) serveTCP(upstream string) {
	defer r.wg.Done()
	for {
		c, err := r.tcp.Accept()
		if err != nil {
			return
		}
		go func() {
			defer func() { _ = c.Close() }()
			u, err := net.DialTimeout("tcp", upstream, 5*time.Second)
			if err != nil {
				return
			}
			defer func() { _ = u.Close() }()
			deadline := time.Now().Add(30 * time.Second)
			_ = c.SetDeadline(deadline)
			_ = u.SetDeadline(deadline)
			done := make(chan struct{}, 2)
			go func() { _, _ = io.Copy(u, c); done <- struct{}{} }()
			go func() { _, _ = io.Copy(c, u); done <- struct{}{} }()
			<-done
		}()
	}
}

// Close stops the relay.
func (r *dnsRelay) Close() {
	err1 := r.udp.Close()
	err2 := r.tcp.Close()
	if errors.Join(err1, err2) == nil {
		r.wg.Wait()
	}
}
