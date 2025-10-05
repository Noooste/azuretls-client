package azuretls

import (
	"context"
	"crypto/x509"
	"errors"
	"github.com/Noooste/utls"
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
	if s.Dial != nil {
		return s.Dial(ctx, network, addr)
	}

	if s.ProxyDialer != nil {
		var userAgent = s.UserAgent
		if ctx.Value(userAgentKey) != nil {
			userAgent = ctx.Value(userAgentKey).(string)
		}
		conn, err := s.ProxyDialer.DialContext(ctx, userAgent, network, addr)
		return conn, err
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

	conn, err := dialer.DialContext(ctx, network, addr)
	return conn, err
}

func (s *Session) upgradeTLS(ctx context.Context, conn net.Conn, addr string) (net.Conn, error) {
	// Split addr and port
	hostname, _, err := net.SplitHostPort(addr)

	if err != nil {
		return nil, errors.New("failed to split addr and port: " + err.Error())
	}

	var config tls.Config

	// Check both session-level and request-level InsecureSkipVerify
	requestInsecureSkipVerify, _ := ctx.Value(insecureSkipVerifyKey).(bool)
	insecureSkipVerify := s.InsecureSkipVerify || requestInsecureSkipVerify

	if insecureSkipVerify {
		config = tls.Config{
			ServerName:         hostname,
			InsecureSkipVerify: true,
		}
	} else {
		if err = s.PinManager.AddHost(addr); err != nil {
			return nil, errors.New("failed to pin: " + err.Error())
		}

		config = tls.Config{
			ServerName:         hostname,
			InsecureSkipVerify: false,
			VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
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
	}

	if s.ModifyConfig != nil {
		if err := s.ModifyConfig(&config); err != nil {
			return nil, err
		}
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

	return tlsConn.Conn, nil
}
