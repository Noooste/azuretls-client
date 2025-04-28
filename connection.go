package azuretls

import (
	"context"
	"crypto/x509"
	"errors"
	http "github.com/Noooste/fhttp"
	"github.com/Noooste/fhttp/http2"
	tls "github.com/Noooste/utls"
	"net"
	"time"
)

func (s *Session) dialTLS(ctx context.Context, network, addr string) (net.Conn, error) {
	conn, err := s.dial(ctx, network, addr)
	if err != nil {
		return nil, errors.New("failed to dial: " + err.Error())
	}

	return s.upgradeTLS(ctx, conn, addr)
}

func (s *Session) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	if s.ProxyDialer != nil {
		var userAgent = s.UserAgent
		if ctx.Value(userAgentKey) != nil {
			userAgent = ctx.Value(userAgentKey).(string)
		}
		return s.ProxyDialer.DialContext(ctx, userAgent, network, addr)
	}

	dialer := &net.Dialer{
		Timeout:   s.TimeOut,
		KeepAlive: 30 * time.Second,
	}

	if s.ModifyDialer != nil {
		if err := s.ModifyDialer(dialer); err != nil {
			return nil, err
		}
	}

	return dialer.DialContext(ctx, network, addr)
}

func (s *Session) upgradeTLS(ctx context.Context, conn net.Conn, addr string) (net.Conn, error) {
	// Split addr and port
	hostname, _, err := net.SplitHostPort(addr)

	if err != nil {
		return nil, errors.New("failed to split addr and port: " + err.Error())
	}

	if !s.InsecureSkipVerify {
		if err = s.PinManager.AddHost(addr); err != nil {
			return nil, errors.New("failed to pin: " + err.Error())
		}
	}

	config := tls.Config{
		ServerName:         hostname,
		InsecureSkipVerify: s.InsecureSkipVerify,
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			if s.InsecureSkipVerify {
				return nil
			}

			now := time.Now()
			for _, chain := range verifiedChains {
				for _, cert := range chain {
					if now.Before(cert.NotBefore) {
						return errors.New("certificate is not valid yet")
					}
					if now.After(cert.NotAfter) {
						return errors.New("certificate is expired")
					}
					if cert.IsCA {
						continue
					}
					if err = cert.VerifyHostname(hostname); err != nil {
						return err
					}
				}
			}

			pins := s.PinManager.GetHost(addr)
			if pins == nil {
				return errors.New("no pins found for " + addr)
			}

			for _, chain := range verifiedChains {
				for _, cert := range chain {
					if pins.Verify(cert) {
						return nil
					}
				}
			}
			return errors.New("pin verification failed")
		},
	}

	tlsConn := tls.UClient(conn, &config, tls.HelloCustom)

	var fn = s.GetClientHelloSpec
	if fn == nil {
		fn = GetBrowserClientHelloFunc(s.Browser)
	}

	specs := fn()

	if v, k := ctx.Value(forceHTTP1Key).(bool); k && v {
		for _, ext := range specs.Extensions {
			switch ext.(type) {
			case *tls.ALPNExtension:
				ext.(*tls.ALPNExtension).AlpnProtocols = []string{"http/1.1"}
			}
		}

		config.NextProtos = []string{"http/1.1"}
	}

	if err = tlsConn.ApplyPreset(specs); err != nil {
		return nil, errors.New("failed to apply preset: " + err.Error())
	}

	if err = tlsConn.Handshake(); err != nil {
		return nil, errors.New("failed to handshake: " + err.Error())
	}

	req := ctx.Value("request").(*Request)
	if tlsConn.ConnectionState().NegotiatedProtocol != http2.NextProtoTLS {
		req.HttpRequest.Header.Del(http.PHeaderOrderKey)
		req.HttpRequest.Header.Del(http.HeaderOrderKey)
	}

	return tlsConn.Conn, nil
}
