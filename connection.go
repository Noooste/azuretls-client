package azuretls

import (
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

type RequestConn struct {
	TLS   *tls.UConn
	HTTP2 *http2.ClientConn
	Conn  net.Conn

	mu *sync.RWMutex

	Pins *PinManager
}

func NewRequestConn() *RequestConn {
	return &RequestConn{mu: new(sync.RWMutex)}
}

type RequestConnPool struct {
	hosts map[string]*RequestConn
	mu    *sync.RWMutex
}

func NewRequestConnPool() *RequestConnPool {
	return &RequestConnPool{
		hosts: make(map[string]*RequestConn),
		mu:    &sync.RWMutex{},
	}
}

func (p *RequestConnPool) Close() {
	p.mu.Lock()
	for _, c := range p.hosts {
		c.Close()
	}
	p.hosts = make(map[string]*RequestConn)
	p.mu.Unlock()
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

func (p *RequestConnPool) Get(u *url.URL) (c *RequestConn, err error) {
	var (
		ok       bool
		hostName = getHost(u)
	)

	p.mu.RLock()
	c, ok = p.hosts[hostName]
	p.mu.RUnlock()

	if !ok {
		p.mu.Lock()
		c, ok = p.hosts[hostName]
		if !ok {
			c = NewRequestConn()
			p.hosts[hostName] = c
		}
		p.mu.Unlock()
	}
	return
}

func (p *RequestConnPool) Set(u *url.URL, c *RequestConn) {
	var (
		ok       bool
		hostName = getHost(u)
	)

	p.mu.Lock()
	defer p.mu.Unlock()

	_, ok = p.hosts[hostName]
	if !ok {
		p.hosts[hostName] = c
	}
}

func (p *RequestConnPool) Remove(u *url.URL) {
	var (
		ok       bool
		hostName = getHost(u)
		c        *RequestConn
	)

	p.mu.Lock()
	defer p.mu.Unlock()

	c, ok = p.hosts[hostName]
	if ok {
		c.Close()
		delete(p.hosts, hostName)
	}
}

func (rc *RequestConn) makeTLS(req *Request, verifyPins bool, clientSpec func() *tls.ClientHelloSpec) error {
	if rc.checkTLS() {
		return nil
	}
	if rc.TLS == nil {
		return rc.NewConn(req, verifyPins, clientSpec)
	}
	return nil
}

func (rc *RequestConn) checkTLS() bool {
	if rc.TLS == nil {
		return false
	} else if rc.TLS.ConnectionState().VerifiedChains != nil {
		state := rc.TLS.ConnectionState()
		for _, peerCert := range state.PeerCertificates {
			if time.Now().After(peerCert.NotAfter) {
				// the certificate is expired, so we need to create a new connection
				return false
			}
		}
	}

	return true
}

func (rc *RequestConn) tryUpgradeHTTP2(tr *http2.Transport) bool {
	if rc.HTTP2 != nil && rc.HTTP2.CanTakeNewRequest() {
		return true

	} else if rc.TLS.ConnectionState().NegotiatedProtocol == http2.NextProtoTLS {
		var err error
		if rc.HTTP2 != nil {
			return true
		}

		rc.HTTP2, err = tr.NewClientConn(rc.TLS)
		return err == nil
	}

	return false
}

func (rc *RequestConn) Close() {
	if rc.TLS != nil {
		_ = rc.TLS.Close()
		rc.TLS = nil
	}
	if rc.Conn != nil {
		_ = rc.Conn.Close()
		rc.Conn = nil
	}
	if rc.HTTP2 != nil {
		_ = rc.HTTP2.Close()
		rc.HTTP2 = nil
	}
	rc.Pins = nil
}

func (s *Session) initConn(req *Request) (rConn *RequestConn, err error) {
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

func (rc *RequestConn) NewConn(req *Request, doPins bool, getSpec func() *tls.ClientHelloSpec) (err error) {
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

	if doPins && req.parsedUrl.Scheme == SchemeHttps && rc.Pins == nil {
		rc.Pins = NewPinManager()
		if err = rc.Pins.New(addr); err != nil {
			return
		}
	}

	if req.Proxy != "" {
		var dialer proxy.ContextDialer
		dialer, err = newConnectDialer(req.Proxy)
		if err != nil {
			return
		}

		dialer.(*connectDialer).Dialer.Timeout = req.TimeOut

		rc.Conn, err = dialer.DialContext(req.ctx, "tcp", addr)
		if err != nil {
			return
		}

	} else {
		rc.Conn, err = (&net.Dialer{
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

	config := tls.Config{
		ServerName:         req.parsedUrl.Hostname(),
		InsecureSkipVerify: req.InsecureSkipVerify,
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			if rc.Pins == nil {
				return nil
			}

			for _, chain := range verifiedChains {
				for _, cert := range chain {
					if rc.Pins.Verify(cert) {
						return nil
					}
				}
			}

			return errors.New("pin verification failed")
		},
	}

	rc.TLS = tls.UClient(rc.Conn, &config, tls.HelloCustom)
	if err = rc.TLS.ApplyPreset(getSpec()); err != nil {
		return
	}
	if err = rc.TLS.SetDeadline(time.Now().Add(req.TimeOut)); err != nil {
		return
	}
	err = rc.TLS.Handshake()

	return
}
