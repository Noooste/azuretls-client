package azuretls

import (
	"context"
	"crypto/x509"
	"errors"
	"github.com/Noooste/fhttp/http2"
	tls "github.com/Noooste/utls"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"
)

type Conn struct {
	TLS   *tls.UConn        // tls connection
	HTTP2 *http2.ClientConn // http2 connection
	h2tr  *http2.Transport

	Conn net.Conn // Tcp connection

	PinManager *PinManager // pin manager

	TimeOut            time.Duration
	InsecureSkipVerify bool

	ClientHelloSpec func() *tls.ClientHelloSpec

	mu *sync.RWMutex

	ctx    context.Context
	cancel context.CancelFunc
}

/*
NewConn allocate a new empty connection struct
*/
func NewConn() *Conn {
	return NewConnWithContext(context.Background())
}

func NewConnWithContext(ctx context.Context) *Conn {
	return &Conn{
		mu:  new(sync.RWMutex),
		ctx: ctx,
	}
}

func (c *Conn) SetContext(ctx context.Context) {
	c.ctx = ctx
}

func (c *Conn) GetContext() context.Context {
	return c.ctx
}

type ConnPool struct {
	hosts map[string]*Conn
	mu    *sync.RWMutex

	ctx context.Context
}

func NewRequestConnPool(ctx context.Context) *ConnPool {
	return &ConnPool{
		hosts: make(map[string]*Conn),
		mu:    &sync.RWMutex{},
		ctx:   ctx,
	}
}

func (cp *ConnPool) SetContext(ctx context.Context) {
	cp.ctx = ctx
}

func (cp *ConnPool) Close() {
	cp.mu.Lock()
	defer cp.mu.Unlock()

	for _, c := range cp.hosts {
		c.Close()
	}
	cp.hosts = nil
	cp.mu = nil
}

func getHost(u *url.URL) string {
	addr := u.Hostname()
	if v, err := idnaASCII(addr); err == nil {
		addr = v
	}
	port := u.Port()
	if port == "" {
		port = portMap[u.Scheme]
	}
	return net.JoinHostPort(addr, port)
}

func (cp *ConnPool) Get(u *url.URL) (c *Conn) {
	var (
		ok       bool
		hostName = getHost(u)
	)

	cp.mu.RLock()
	c, ok = cp.hosts[hostName]
	cp.mu.RUnlock()

	if !ok {
		cp.mu.Lock()
		c, ok = cp.hosts[hostName]
		if !ok {
			c = NewConn()
			c.SetContext(cp.ctx)
			cp.hosts[hostName] = c
		}
		cp.mu.Unlock()
	}
	return
}

func (cp *ConnPool) Set(u *url.URL, c *Conn) {
	var (
		ok       bool
		hostName = getHost(u)
	)

	cp.mu.Lock()
	defer cp.mu.Unlock()

	_, ok = cp.hosts[hostName]
	if !ok {
		cp.hosts[hostName] = c
	}
}

func (cp *ConnPool) Remove(u *url.URL) {
	var (
		ok       bool
		hostName = getHost(u)
		c        *Conn
	)

	cp.mu.Lock()
	defer cp.mu.Unlock()

	c, ok = cp.hosts[hostName]
	if ok {
		c.Close()
		delete(cp.hosts, hostName)
	}
}

func (c *Conn) makeTLS(addr string) error {
	if c.checkTLS() {
		return nil
	}
	if c.TLS == nil {
		return c.NewTLS(addr)
	}
	return nil
}

func (c *Conn) checkTLS() bool {
	if c.TLS == nil {
		return false
	} else if c.TLS.ConnectionState().VerifiedChains != nil {
		state := c.TLS.ConnectionState()
		for _, peerCert := range state.PeerCertificates {
			if time.Now().After(peerCert.NotAfter) {
				// the certificate is expired, so we need to create a new connection
				return false
			}
		}
	}

	return true
}

func (c *Conn) tryUpgradeHTTP2(tr *http2.Transport) bool {
	if c.HTTP2 != nil && c.HTTP2.CanTakeNewRequest() {
		return true
	}

	if c.TLS.ConnectionState().NegotiatedProtocol == http2.NextProtoTLS {
		var err error
		c.HTTP2, err = tr.NewClientConn(c.TLS)
		return err == nil
	}

	return false
}

func (c *Conn) Close() {
	if c.TLS != nil {
		_ = c.TLS.Close()
		c.TLS = nil
	}
	if c.Conn != nil {
		_ = c.Conn.Close()
		c.Conn = nil
	}
	if c.HTTP2 != nil {
		_ = c.HTTP2.Close()
		c.HTTP2 = nil
	}

	if c.cancel != nil {
		c.cancel()
		c.cancel = nil
	}
	c.PinManager = nil
}

func (s *Session) getProxyConn(conn *Conn, host string) (err error) {
	ctx, cancel := context.WithCancel(s.ctx)
	defer cancel()

	s.ProxyDialer.ForceHTTP2 = s.H2Proxy
	s.ProxyDialer.tr = s.HTTP2Transport
	s.ProxyDialer.Dialer.Timeout = conn.TimeOut

	timer := time.NewTimer(conn.TimeOut)
	defer timer.Stop()

	connChan := make(chan net.Conn, 1)
	errChan := make(chan error, 1)

	go func() {
		defer close(connChan)
		defer close(errChan)

		proxyConn, dialErr := s.ProxyDialer.DialContext(ctx, "tcp", host)
		if dialErr != nil {
			select {
			case errChan <- dialErr:
			case <-ctx.Done():
			}
			return
		}

		select {
		case connChan <- proxyConn:
		case <-ctx.Done():
		}
	}()

	select {
	case <-timer.C:
		return errors.New("proxy connection timeout")
	case c := <-connChan:
		conn.Conn = c
		conn.cancel = cancel
	case err = <-errChan:
		return err
	}

	return nil
}

func (s *Session) initConn(req *Request) (conn *Conn, err error) {
	// get connection from pool
	conn = s.Connections.Get(req.parsedUrl)

	host := getHost(req.parsedUrl)

	if conn.ClientHelloSpec == nil {
		conn.ClientHelloSpec = s.GetClientHelloSpec
	}

	if conn.TimeOut == 0 {
		conn.TimeOut = req.TimeOut
	}

	if conn.InsecureSkipVerify == false {
		conn.InsecureSkipVerify = req.InsecureSkipVerify
	}

	conn.SetContext(s.ctx)

	conn.mu.Lock()
	defer conn.mu.Unlock()

	if conn.Conn == nil {
		if s.ProxyDialer != nil {
			if err = s.getProxyConn(conn, host); err != nil {
				return nil, err
			}
		} else {
			conn.Conn, err = (&net.Dialer{Timeout: conn.TimeOut}).DialContext(s.ctx, "tcp", host)
		}
	}

	// init tls connection if needed
	switch req.parsedUrl.Scheme {
	case "":
		return nil, errors.New("scheme is empty")

	case SchemeHttps, SchemeWss:
		// for secured http we need to make tls connection first
		if err = conn.makeTLS(host); err != nil {
			conn.Close()
			return

		}

		if req.parsedUrl.Scheme != SchemeWss {
			// if tls connection is established, we can try to upgrade it to http2
			conn.tryUpgradeHTTP2(s.HTTP2Transport)
		}

	case SchemeHttp, SchemeWs:
		return

	default:
		return nil, errors.New("unsupported scheme")
	}

	return
}

func (c *Conn) NewTLS(addr string) (err error) {
	do := false

	if c.PinManager == nil && !c.InsecureSkipVerify {
		c.PinManager = NewPinManager()
		do = true
	}

	if !c.InsecureSkipVerify && (do || c.PinManager.redo) {
		if err = c.PinManager.New(addr); err != nil {
			return errors.New("pin verification failed")
		}
	}

	var hostname = strings.Split(addr, ":")[0]

	config := tls.Config{
		ServerName:         hostname,
		InsecureSkipVerify: c.InsecureSkipVerify,
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			if c.PinManager == nil {
				return nil
			}

			for _, chain := range verifiedChains {
				for _, cert := range chain {
					if c.PinManager.Verify(cert) {
						return nil
					}
				}
			}

			return errors.New("pin verification failed")
		},
	}

	c.TLS = tls.UClient(c.Conn, &config, tls.HelloCustom)
	if err = c.TLS.ApplyPreset(c.ClientHelloSpec()); err != nil {
		return
	}
	return c.TLS.HandshakeContext(c.ctx)
}
