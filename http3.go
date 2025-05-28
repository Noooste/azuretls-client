package azuretls

import (
	"errors"
	http "github.com/Noooste/fhttp"
	"github.com/Noooste/fhttp/http2"
	tls "github.com/Noooste/utls"
	"net/url"
	"sync"
	"time"

	"github.com/Noooste/quic-go"
	"github.com/Noooste/quic-go/http3"
)

// HTTP3Transport wraps the http3.RoundTripper with proxy support
type HTTP3Transport struct {
	*http3.Transport

	// Proxy configuration
	ProxyURL    *url.URL
	ProxyDialer *proxyDialer

	// Connection pool for proxy connections
	proxyConnPool sync.Map

	// Session reference
	sess *Session
}

// NewHTTP3Transport creates a new HTTP/3 transport
func (s *Session) NewHTTP3Transport() (*HTTP3Transport, error) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: s.InsecureSkipVerify,
		NextProtos:         []string{http2.NextProtoTLS, http3.NextProtoH3},
	}

	//if s.GetClientHelloSpec != nil {
	//	// Apply custom TLS configuration
	//	// Note: QUIC has different TLS requirements than TCP
	//	// specs := s.GetClientHelloSpec()
	//	// Apply relevant specs to tlsConfig
	//	// applySpecsToQUICTLS(tlsConfig, specs)
	//}

	quicConfig := &quic.Config{
		MaxIdleTimeout:                 90 * time.Second,
		HandshakeIdleTimeout:           s.TimeOut,
		KeepAlivePeriod:                30 * time.Second,
		InitialStreamReceiveWindow:     512 * 1024,
		InitialConnectionReceiveWindow: 1024 * 1024,
	}

	transport := &HTTP3Transport{
		Transport: &http3.Transport{
			TLSClientConfig: tlsConfig,
			QUICConfig:      quicConfig,
			Dial:            s.dialQUIC,
		},
		sess: s,
	}

	if s.ProxyDialer != nil {
		transport.ProxyURL = s.ProxyDialer.ProxyURL
		transport.ProxyDialer = s.ProxyDialer
	}

	return transport, nil
}

// RoundTrip implements the http.RoundTripper interface with proxy support
func (t *HTTP3Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Direct connection
	return t.Transport.RoundTrip(req)
}

// fallbackToHTTP2 falls back to HTTP/2 when HTTP/3 through proxy isn't available
func (t *HTTP3Transport) fallbackToHTTP2(req *http.Request) (*http.Response, error) {
	// Clone request and force HTTP/2
	newReq := req.Clone(req.Context())

	// Use the session's HTTP/2 transport
	if t.sess.HTTP2Transport != nil {
		return t.sess.HTTP2Transport.RoundTrip(newReq)
	}

	return nil, errors.New("HTTP/2 transport not available for fallback")
}
