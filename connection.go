package azuretls

import (
	"context"
	"fmt"
	"github.com/Noooste/fhttp/http2"
	tls "github.com/Noooste/utls"
	"net"
	"strings"
	"time"
)

func (s *Session) initConn(req *Request) (sConn *sessionConn, err error) {
	sConn = &sessionConn{}

	if req.parsedUrl.Scheme != "https" {
		return
	}

	if !s.RotateProxy && req.Proxy == s.Proxy {
		s.mu.Lock()
		for _, c := range s.conns {
			if c == nil {
				continue
			}

			if c.tlsConn != nil && c.tlsConn.VerifyHostname(req.parsedUrl.Host) == nil {
				if c.conn != nil && c.conn.CanTakeNewRequest() {
					s.mu.Unlock()
					return c, nil

				} else if c.tlsConn.ConnectionState().NegotiatedProtocol == http2.NextProtoTLS {
					s.mu.Unlock()
					c.conn, _ = s.tr2.NewClientConn(c.tlsConn)
					// downgrade to HTTP/1.1 connection if error occurs
					return c, nil
				}
			}
		}
		// cases : no tls connection
		s.mu.Unlock()
	}

	if !s.RotateProxy {
		s.mu.Lock()
		s.conns = append(s.conns, sConn)
		s.mu.Unlock()
	}

	sConn.tlsConn, sConn.pins, err = s.getConn(req)
	if err != nil {
		return
	}

	if sConn.tlsConn.ConnectionState().NegotiatedProtocol == http2.NextProtoTLS {
		sConn.conn, _ = s.tr2.NewClientConn(sConn.tlsConn)
	}

	return sConn, nil
}

func (s *Session) getConn(req *Request) (tConn *tls.UConn, pins []string, err error) {
	var conn net.Conn

	addr := req.parsedUrl.Host

	if req.parsedUrl.Port() != "" {
		addr += ":" + req.parsedUrl.Port()
	} else {
		if req.parsedUrl.Scheme == "https" {
			addr += ":443"
		} else {
			addr += ":80"
		}
	}

	if s.VerifyPins && req.parsedUrl.Scheme == "https" {
		pins = s.generatePins(addr)
	}

	for i := 0; i < 10; i++ {
		if req.Proxy != "" {
			conn, err = getProxyConn(req.Proxy, addr)
			if err != nil {
				continue
			}

		} else {
			conn, err = net.DialTimeout("tcp", addr, time.Duration(30)*time.Second)
			if err != nil {
				continue
			}
		}

		config := tls.Config{
			ServerName: strings.Split(addr, ":")[0],
		}

		tConn = tls.UClient(conn, &config, tls.HelloCustom)

		if err = tConn.ApplyPreset(s.GetClientHelloSpec()); err != nil {
			return
		}

		colonPos := strings.LastIndex(addr, ":")
		if colonPos == -1 {
			colonPos = len(addr)
		}

		_ = tConn.SetDeadline(time.Now().Add(req.TimeOut))
		err = tConn.Handshake()

		if err != nil {
			continue
		}

		if s.VerifyPins && !s.verifyPins(tConn, pins) {
			_ = tConn.Close()
			return nil, nil, fmt.Errorf("pin verification failed")
		}

		return
	}

	return
}

func getProxyConn(proxy string, addr string) (net.Conn, error) {
	dialer, err := newConnectDialer(proxy)
	if err != nil {
		return nil, err
	}
	return dialer.DialContext(context.Background(), "tcp", addr)
}
