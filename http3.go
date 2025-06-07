package azuretls

import (
	"context"
	"errors"
	"fmt"
	http "github.com/Noooste/fhttp"
	tls "github.com/Noooste/utls"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Noooste/quic-go"
	"github.com/Noooste/quic-go/http3"
)

// HTTP3Transport wraps the http3.RoundTripper with proxy support
type HTTP3Transport struct {
	*http3.Transport

	// Connection pool for proxy connections
	proxyConnPool sync.Map

	// Session reference
	sess *Session
}

// HTTP3Config holds HTTP/3 specific configuration
type HTTP3Config struct {
	// Enable HTTP/3 support
	Enabled bool

	// Force HTTP/3 for all requests (no fallback)
	ForceHTTP3 bool

	// Alt-Svc cache for HTTP/3 discovery
	altSvcCache sync.Map

	// HTTP/3 transport
	transport *HTTP3Transport
}

// NewHTTP3Transport creates a new HTTP/3 transport
func (s *Session) NewHTTP3Transport() (*HTTP3Transport, error) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: s.InsecureSkipVerify,
	}

	quicConfig := &quic.Config{
		MaxIdleTimeout:                 90 * time.Second,
		HandshakeIdleTimeout:           s.TimeOut,
		KeepAlivePeriod:                30 * time.Second,
		InitialStreamReceiveWindow:     512 * 1024,
		InitialConnectionReceiveWindow: 1024 * 1024,
		EnableDatagrams:                true,
	}

	settings, order := defaultHTTP3Settings(s.Browser)

	transport := &HTTP3Transport{
		Transport: &http3.Transport{
			AdditionalSettings:      settings,
			AdditionalSettingsOrder: order,
			TLSClientConfig:         tlsConfig,
			QUICConfig:              quicConfig,
			Dial:                    s.dialQUIC,
		},
		sess: s,
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

// EnableHTTP3 enables HTTP/3 support for the session
func (s *Session) EnableHTTP3() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.HTTP3Config == nil {
		s.HTTP3Config = &HTTP3Config{
			Enabled: true,
		}
	}

	transport, err := s.NewHTTP3Transport()
	if err != nil {
		return err
	}

	s.HTTP3Config.transport = transport
	return nil
}

// DisableHTTP3 disables HTTP/3 support
func (s *Session) DisableHTTP3() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.HTTP3Config != nil {
		s.HTTP3Config.Enabled = false
		if s.HTTP3Config.transport != nil {
			_ = s.HTTP3Config.transport.Close()
		}
	}
}

// selectTransport chooses the appropriate transport for a request
func (s *Session) selectTransport(req *Request) (rt http.RoundTripper, isHTTP3 bool, err error) {
	// Check if HTTP/3 is forced for this request
	if req.ForceHTTP3 {
		if s.HTTP3Config == nil {
			if err = s.EnableHTTP3(); err != nil {
				return nil, false, err
			}
		} else if !s.HTTP3Config.Enabled {
			return nil, false, errors.New("HTTP/3 is not enabled for this session")
		}

		rt = s.HTTP3Config.transport
		return rt, true, nil
	}

	// Check if HTTP/3 is available for this host
	if s.HTTP3Config != nil && s.HTTP3Config.Enabled {
		if s.shouldUseHTTP3(req.parsedUrl.Host) {
			rt = s.HTTP3Config.transport
			return rt, true, nil
		}
	}

	// Fall back to HTTP/2 or HTTP/1.1
	return s.Transport, false, nil
}

// shouldUseHTTP3 checks if HTTP/3 should be used for a host
func (s *Session) shouldUseHTTP3(host string) bool {
	if s.HTTP3Config == nil || !s.HTTP3Config.Enabled {
		return false
	}

	// Check Alt-Svc cache
	if _, ok := s.HTTP3Config.altSvcCache.Load(host); ok {
		return true
	}

	// Check if ForceHTTP3 is set globally
	return s.HTTP3Config.ForceHTTP3
}

// handleAltSvc processes Alt-Svc headers for HTTP/3 discovery
func (s *Session) handleAltSvc(resp *Response) {
	if s.HTTP3Config == nil || !s.HTTP3Config.Enabled {
		return
	}

	altSvc := resp.Header.Get("Alt-Svc")
	if altSvc == "" {
		return
	}

	if containsHTTP3(altSvc) {
		s.HTTP3Config.altSvcCache.Store(resp.Request.parsedUrl.Host, true)
	}
}

// containsHTTP3 checks if the Alt-Svc header contains HTTP/3
func containsHTTP3(altSvc string) bool {
	// Check for h3 or h3-xx versions
	return contains(altSvc, "h3") || contains(altSvc, "h3-")
}

// contains checks if a string contains a substring
func contains(str, substr string) bool {
	return len(str) >= len(substr) && str[:len(substr)] == substr
}

// dialQUIC establishes a QUIC connection
func (s *Session) dialQUIC(ctx context.Context, addr string, tlsConf *tls.Config, quicConf *quic.Config) (quic.EarlyConnection, error) {
	// Resolve address
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}

	// Apply custom dialer modifications if set
	if s.ModifyDialer != nil {
		// Note: ModifyDialer works with net.Dialer, need adaptation for UDP
		// This is a limitation of the current design
	}

	// Create UDP connection
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, err
	}

	// Handle proxy if configured
	if s.ProxyDialer != nil {
		return s.dialQUICViaProxy(ctx, udpConn, udpAddr, tlsConf, quicConf)
	}

	// Direct QUIC connection
	return quic.DialEarly(ctx, udpConn, udpAddr, tlsConf, quicConf)
}

// dialQUICViaProxy establishes a QUIC connection through a proxy
func (s *Session) dialQUICViaProxy(ctx context.Context, udpConn *net.UDPConn,
	remoteAddr *net.UDPAddr, tlsConf *tls.Config, quicConf *quic.Config) (quic.EarlyConnection, error) {

	switch s.ProxyDialer.ProxyURL.Scheme {
	case "socks5", "socks5h":
		// SOCKS5 UDP ASSOCIATE implementation
		return s.dialQUICViaSocks5(ctx, udpConn, remoteAddr, tlsConf, quicConf)

	case "http", "https":
		// HTTP proxy doesn't support UDP directly
		// Would need CONNECT-UDP or MASQUE protocol
		return nil, errors.New("HTTP proxy not supported for direct QUIC connections")

	default:
		return nil, errors.New("unsupported proxy type for QUIC")
	}
}

// ApplyHTTP3 applies HTTP3 settings to the session from a fingerprint.
// The fingerprint is in the format:
//
//	<SETTINGS>|<PSEUDO_HEADER>
//
// egs :
//
//	1:65536;6:262144;7:100;51:1;GREASE|m,a,s,p
//
// Any 0 value will be ignored.
func (s *Session) ApplyHTTP3(fp string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.HTTP3Config == nil {
		s.HTTP3Config = &HTTP3Config{
			Enabled: true,
		}
	}

	settings, settingsOrder, pseudoHeaders, err := parseHTTP3Fingerprint(fp)
	if err != nil {
		return err
	}

	if s.HTTP3Config.transport == nil {
		transport, err := s.NewHTTP3Transport()
		if err != nil {
			return err
		}
		s.HTTP3Config.transport = transport
	}

	s.HTTP3Config.transport.AdditionalSettings = settings
	s.HTTP3Config.transport.AdditionalSettingsOrder = settingsOrder

	s.PHeader = pseudoHeaders
	return nil
}

// parseHTTP3Fingerprint parses the HTTP/3 fingerprint string into settings and pseudo headers.
func parseHTTP3Fingerprint(fp string) (map[uint64]uint64, []uint64, []string, error) {
	parts := strings.Split(fp, "|")
	if len(parts) != 2 {
		return nil, nil, nil, errors.New("invalid HTTP/3 fingerprint format")
	}

	settingsStr := parts[0]
	pseudoHeadersStr := parts[1]

	settings, settingsOrder, err := parseHTTP3Settings(settingsStr)
	if err != nil {
		return nil, nil, nil, err
	}

	pseudoHeaders, err := parsePseudoHeaders(pseudoHeadersStr)
	if err != nil {
		return nil, nil, nil, err
	}

	return settings, settingsOrder, pseudoHeaders, nil
}

// parseHTTP3Settings parses the settings string into a map and order slice.
func parseHTTP3Settings(settingsStr string) (map[uint64]uint64, []uint64, error) {
	settings := make(map[uint64]uint64)
	var order []uint64

	pairs := strings.Split(settingsStr, ";")
	for _, pair := range pairs {
		var (
			key   uint64
			value uint64
			err   error
		)

		kv := strings.Split(pair, ":")
		if len(kv) == 1 {
			if kv[0] == "GREASE" {
				key = http3.SettingsGREASE
				value = 0
			}
		} else if len(kv) == 2 {
			key, err = strconv.ParseUint(kv[0], 10, 64)
			if err != nil {
				return nil, nil, err
			}

			value, err = strconv.ParseUint(kv[1], 10, 64)
			if err != nil {
				return nil, nil, err
			}
		} else {
			return nil, nil, errors.New("invalid settings format: " + pair)
		}

		settings[key] = value
		order = append(order, key)
	}

	return settings, order, nil
}

// parsePseudoHeaders parses the pseudo headers string into a slice.
func parsePseudoHeaders(pseudoHeadersStr string) ([]string, error) {
	var h = make([]string, 4) // m, p, s, a

	if pseudoHeadersStr != "0" {
		headers := strings.Split(pseudoHeadersStr, ",")
		if len(headers) != 4 {
			return nil, fmt.Errorf(invalidPseudo, pseudoHeadersStr)
		}

		for i, header := range headers {
			switch header {
			case "m":
				h[i] = Method
			case "p":
				h[i] = Path
			case "s":
				h[i] = Scheme
			case "a":
				h[i] = Authority
			default:
				return nil, fmt.Errorf(invalidPseudo, header)
			}
		}
	}

	return h, nil
}
