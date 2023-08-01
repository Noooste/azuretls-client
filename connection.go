package azuretls

import (
	"errors"
	"github.com/Noooste/fhttp/http2"
	tls "github.com/Noooste/utls"
	"golang.org/x/net/proxy"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"
)

type requestConn struct {
	tlsConn   *tls.UConn
	http2Conn *http2.ClientConn
	conn      net.Conn
	mu        *sync.RWMutex

	pins []string
}

func newRequestConn() *requestConn {
	return &requestConn{mu: new(sync.RWMutex)}
}

type requestConnPool struct {
	hosts map[string]*requestConn
	mu    *sync.RWMutex
}

func newRequestConnPool() *requestConnPool {
	return &requestConnPool{
		hosts: make(map[string]*requestConn),
		mu:    &sync.RWMutex{},
	}
}

func (p *requestConnPool) close() {
	p.mu.Lock()
	for _, c := range p.hosts {
		c.close()
	}
	p.hosts = make(map[string]*requestConn)
	p.mu.Unlock()
}

func (p *requestConnPool) get(u *url.URL) (c *requestConn, err error) {
	var (
		ok       bool
		hostName string
	)

	if u.Port() == "" {
		switch u.Scheme {
		case SchemeHttps, SchemeWss:
			hostName = net.JoinHostPort(u.Host, "443")
		case SchemeHttp, SchemeWs:
			hostName = net.JoinHostPort(u.Host, "80")
		default:
			err = errors.New("unknown scheme")
			return
		}
	} else {
		hostName = u.Host
	}

	p.mu.RLock()
	c, ok = p.hosts[hostName]
	p.mu.RUnlock()

	if !ok {
		p.mu.Lock()
		c, ok = p.hosts[hostName]
		if !ok {
			c = newRequestConn()
			p.hosts[hostName] = c
		}
		p.mu.Unlock()
	}
	return
}

func (rc *requestConn) makeTLS(req *Request, s *Session) error {
	if rc.checkTLS() {
		return nil
	}
	rc.mu.Lock()
	defer rc.mu.Unlock()
	if rc.conn == nil {
		return rc.getConn(req, s.VerifyPins, s.GetClientHelloSpec)
	}
	return nil
}

func (rc *requestConn) checkTLS() bool {
	if rc.tlsConn == nil {
		return false
	} else if rc.tlsConn.ConnectionState().VerifiedChains != nil {
		state := rc.tlsConn.ConnectionState()
		for _, peerCert := range state.PeerCertificates {
			if time.Now().After(peerCert.NotAfter) {
				// the certificate is expired, so we need to create a new connection
				return false
			}
		}
	}

	return true
}

func (rc *requestConn) tryUpgradeHTTP2(tr *http2.Transport) bool {
	if rc.http2Conn != nil && rc.http2Conn.CanTakeNewRequest() {
		return true
	} else if rc.tlsConn.ConnectionState().NegotiatedProtocol == http2.NextProtoTLS {
		var err error
		rc.mu.Lock()
		if rc.http2Conn == nil || !rc.http2Conn.CanTakeNewRequest() {
			rc.http2Conn, err = tr.NewClientConn(rc.tlsConn)
		}
		rc.mu.Unlock()
		return err == nil
	}

	return false
}

func (rc *requestConn) close() {
	if rc.tlsConn != nil {
		rc.tlsConn.Close()
	}
	if rc.conn != nil {
		rc.conn.Close()
	}
}

func (s *Session) initConn(req *Request) (rConn *requestConn, err error) {
	// get connection from pool
	rConn, err = s.conns.get(req.parsedUrl)

	if err != nil {
		return
	}

	// init tls connection if needed
	switch req.parsedUrl.Scheme {
	case SchemeHttps:
		// for secured http we need to make tls connection first
		if err = rConn.makeTLS(req, s); err == nil {
			// if tls connection is established, we can try to upgrade it to http2
			if rConn.tryUpgradeHTTP2(s.tr2) {
				return
			}
		} else {
			rConn.close()
		}
		break

	case SchemeWss:
		// for secured websocket we need to make tls connection first
		if err = rConn.makeTLS(req, s); err != nil {
			rConn.close()
		}

	case SchemeHttp, SchemeWs:
		// for http and websocket we need to make tcp connection first
		if rConn.conn == nil {
			rConn.mu.Lock()
			if rConn.conn == nil {
				if err = rConn.getConn(req, false, nil); err != nil {
					rConn.close()
				}
			}
			rConn.mu.Unlock()
		}

	default:
		err = errors.New("unknown scheme")
	}

	return
}

func (rc *requestConn) getConn(req *Request, doPins bool, getSpec func() *tls.ClientHelloSpec) (err error) {
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

	if doPins && req.parsedUrl.Scheme == SchemeHttps {
		if rc.pins == nil {
			rc.pins, err = generatePins(addr)
			if err != nil {
				return
			}
		}
	}

	for i := 0; i < 10; i++ {
		if req.Proxy != "" {
			var dialer proxy.ContextDialer
			dialer, err = newConnectDialer(req.Proxy)
			dialer.(*connectDialer).Dialer.Timeout = req.TimeOut

			if err != nil {
				return err
			}
			rc.conn, err = dialer.DialContext(req.ctx, "tcp", addr)
			if err != nil {
				continue
			}
		} else {
			rc.conn, err = (&net.Dialer{
				Timeout: req.TimeOut,
			}).DialContext(req.ctx, "tcp", addr)

			if err != nil {
				continue
			}
		}

		if req.parsedUrl.Scheme != SchemeWss && req.parsedUrl.Scheme != SchemeHttps {
			return
		}

		config := tls.Config{
			ServerName: strings.Split(addr, ":")[0],
		}

		rc.tlsConn = tls.UClient(rc.conn, &config, tls.HelloCustom)

		if err = rc.tlsConn.ApplyPreset(getSpec()); err != nil {
			return
		}

		colonPos := strings.LastIndex(addr, ":")
		if colonPos == -1 {
			colonPos = len(addr)
		}

		_ = rc.tlsConn.SetDeadline(time.Now().Add(req.TimeOut))
		err = rc.tlsConn.Handshake()

		if err != nil {
			continue
		}

		if doPins && !verifyPins(rc.tlsConn, rc.pins) {
			_ = rc.tlsConn.Close()
			return errors.New("pin verification failed")
		}

		return
	}

	return
}
