package azuretls

import (
	"context"
	"crypto/x509"
	"errors"
	"github.com/Noooste/fhttp/http2"
	tls "github.com/Noooste/utls"
	"golang.org/x/net/proxy"
	"net"
	"net/url"
	"sync"
	"time"
)

type Conn struct {
	TLS   *tls.UConn
	HTTP2 *http2.ClientConn
	Conn  net.Conn

	mu *sync.RWMutex

	Pins *PinManager

	ctx context.Context
}

func NewConn() *Conn {
	return &Conn{
		mu:  new(sync.RWMutex),
		ctx: context.Background(),
	}
}

func (c *Conn) SetContext(ctx context.Context) {
	c.ctx = ctx
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
	for _, c := range cp.hosts {
		c.Close()
	}
	cp.hosts = make(map[string]*Conn)
	cp.mu.Unlock()
}

func getHost(u *url.URL) string {
	host := u.Host
	if u.Port() == "" {
		switch u.Scheme {
		case SchemeHttps, SchemeWss:
			host = net.JoinHostPort(host, "443")
		case SchemeHttp, SchemeWs:
			host = net.JoinHostPort(host, "80")
		}
	}
	return host
}

func (cp *ConnPool) Get(u *url.URL) (c *Conn, err error) {
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

func (c *Conn) makeTLS(req *Request, verifyPins bool, clientSpec func() *tls.ClientHelloSpec) error {
	if c.checkTLS() {
		return nil
	}
	if c.TLS == nil {
		return c.NewConn(req, verifyPins, clientSpec)
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

	} else if c.TLS.ConnectionState().NegotiatedProtocol == http2.NextProtoTLS {
		var err error
		if c.HTTP2 != nil {
			return true
		}
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
	c.Pins = nil
}

func (s *Session) initConn(req *Request) (rConn *Conn, err error) {
	// get connection from pool
	rConn, err = s.Connections.Get(req.parsedUrl)

	rConn.mu.Lock()
	defer rConn.mu.Unlock()

	if err != nil {
		return
	}

	// init tls connection if needed
	switch req.parsedUrl.Scheme {
	case SchemeHttps, SchemeWss:
		// for secured http we need to make tls connection first
		if err = rConn.makeTLS(req, !req.InsecureSkipVerify, s.GetClientHelloSpec); err != nil {
			rConn.Close()
			return

		} else if req.parsedUrl.Scheme != SchemeWss {
			// if tls connection is established, we can try to upgrade it to http2
			rConn.tryUpgradeHTTP2(s.tr2)
		}

	case SchemeHttp, SchemeWs:
		// for http we need to make tcp connection first
		if rConn.Conn == nil {
			if rConn.Conn == nil {
				if err = rConn.NewConn(req, false, nil); err != nil {
					rConn.Close()
					return
				}
			}
		}

	default:
		err = errors.New("unknown scheme")
	}

	return
}

func (c *Conn) NewConn(req *Request, doPins bool, getSpec func() *tls.ClientHelloSpec) (err error) {
	addr := req.parsedUrl.Host

	if req.parsedUrl.Port() != "" {
		addr += ":" + req.parsedUrl.Port()
	} else {
		if req.parsedUrl.Scheme == SchemeHttps {
			addr += ":443"
		} else {
			addr += ":80"
		}
	}

	var done chan bool

	if req.parsedUrl.Scheme == SchemeHttps || req.parsedUrl.Scheme == SchemeWss {
		done = make(chan bool, 1)
		defer close(done)

		go func() {
			defer func() {
				recover()
			}()

			if doPins && req.parsedUrl.Scheme == SchemeHttps && c.Pins == nil {
				c.Pins = NewPinManager()
				if err = c.Pins.New(addr); err != nil {
					done <- false
					return
				}
			}

			//check if channel is closed
			done <- true
		}()
	}

	if req.Proxy != "" {
		var dialer proxy.ContextDialer
		dialer, err = newConnectDialer(req.Proxy)
		if err != nil {
			return
		}

		dialer.(*connectDialer).Dialer.Timeout = req.TimeOut

		c.Conn, err = dialer.DialContext(req.ctx, "tcp", addr)
		if err != nil {
			return
		}

	} else {
		c.Conn, err = (&net.Dialer{
			Timeout: req.TimeOut,
		}).DialContext(req.ctx, "tcp", addr)

		if err != nil {
			return
		}
	}

	if req.parsedUrl.Scheme != SchemeWss && req.parsedUrl.Scheme != SchemeHttps {
		// we are done for http and ws
		return
	}

	if !<-done {
		return errors.New("pin verification failed")
	}

	config := tls.Config{
		ServerName:         req.parsedUrl.Hostname(),
		InsecureSkipVerify: req.InsecureSkipVerify,
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			if c.Pins == nil {
				return nil
			}

			for _, chain := range verifiedChains {
				for _, cert := range chain {
					if c.Pins.Verify(cert) {
						return nil
					}
				}
			}

			return errors.New("pin verification failed")
		},
	}

	c.TLS = tls.UClient(c.Conn, &config, tls.HelloCustom)
	if err = c.TLS.ApplyPreset(getSpec()); err != nil {
		return
	}
	err = c.TLS.Handshake()

	return
}
