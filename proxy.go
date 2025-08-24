package azuretls

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"sync"

	http "github.com/Noooste/fhttp"
	"github.com/Noooste/fhttp/http2"
	tls "github.com/Noooste/utls"
	"golang.org/x/net/proxy"

	_ "github.com/Noooste/go-socks4"
)

// ProxyDialer interface for both single and chain proxy dialers
type ProxyDialer interface {
	Dial(userAgent, network, address string) (net.Conn, error)
	DialContext(ctx context.Context, userAgent, network, address string) (net.Conn, error)
}

// proxyDialer handles both single proxy and proxy chain connections
type proxyDialer struct {
	ProxyChain    []*url.URL // For chain mode, single proxy is [0]
	DefaultHeader http.Header
	Dialer        net.Dialer
	DialTLS       func(network string, address string) (net.Conn, string, error)

	// Cached connection info for HTTP/2 reuse
	h2Mu   sync.Mutex
	H2Conn *http2.ClientConn
	conn   net.Conn

	sess *Session
}

const (
	invalidProxy = "invalid proxy `%s`, %s"
)

// ContextKeyHeader for passing headers through context
type ContextKeyHeader struct{}

// SetProxy sets a single proxy for the session (original functionality)
func (s *Session) SetProxy(proxy string) error {
	if proxy == "" {
		return fmt.Errorf("proxy is empty")
	}

	proxy = strings.Trim(proxy, " \n\r")

	switch {
	case strings.Contains(proxy, "://"):
		s.Proxy = proxy
	default:
		s.Proxy = formatProxy(proxy)
	}

	if err := s.assignProxy(s.Proxy); err != nil {
		return err
	}

	if s.Transport != nil {
		s.Transport.CloseIdleConnections()
	}
	return nil
}

// SetProxyChain sets up a chain of proxies for the session
func (s *Session) SetProxyChain(proxies []string) error {
	if len(proxies) == 0 {
		return fmt.Errorf("proxy chain cannot be empty")
	}

	var parsedProxies []*url.URL
	for i, p := range proxies {
		if p == "" {
			return fmt.Errorf("proxy %d is empty", i)
		}

		p = strings.Trim(p, " \n\r")

		var parsed *url.URL
		var err error

		if strings.Contains(p, "://") {
			parsed, err = url.Parse(p)
		} else {
			parsed, err = url.Parse(formatProxy(p))
		}

		if err != nil {
			return fmt.Errorf("invalid proxy %d: %v", i, err)
		}

		if err := validateAndSetProxyPort(parsed, i); err != nil {
			return err
		}

		parsedProxies = append(parsedProxies, parsed)
	}

	s.ProxyDialer = &proxyDialer{
		ProxyChain:    parsedProxies,
		DefaultHeader: make(http.Header),
		sess:          s,
	}

	// Set up authentication for each proxy
	return s.setupProxyAuthentication(parsedProxies)
}

// assignProxy handles single proxy assignment (internal method)
func (s *Session) assignProxy(proxy string) error {
	parsed, err := url.Parse(proxy)
	if err != nil {
		return err
	}

	if err := validateAndSetProxyPort(parsed, 0); err != nil {
		return err
	}

	s.ProxyDialer = &proxyDialer{
		ProxyChain:    []*url.URL{parsed}, // Single proxy as chain of 1
		DefaultHeader: make(http.Header),
		sess:          s,
	}

	// Set up authentication
	return s.setupProxyAuthentication([]*url.URL{parsed})
}

// validateAndSetProxyPort validates proxy scheme and sets default port
func validateAndSetProxyPort(parsed *url.URL, index int) error {
	switch parsed.Scheme {
	case SchemeHttp:
		if parsed.Port() == "" {
			parsed.Host = net.JoinHostPort(parsed.Host, "80")
		}
	case SchemeHttps:
		if parsed.Port() == "" {
			parsed.Host = net.JoinHostPort(parsed.Host, "443")
		}
	case Socks4, Socks4A, Socks5, Socks5H:
		if parsed.Port() == "" {
			parsed.Host = net.JoinHostPort(parsed.Host, "1080")
		}
	default:
		return fmt.Errorf("unsupported proxy scheme %s for proxy %d", parsed.Scheme, index)
	}
	return nil
}

// setupProxyAuthentication sets up authentication for proxy chain
func (s *Session) setupProxyAuthentication(proxies []*url.URL) error {
	for i, parsed := range proxies {
		if parsed.User != nil {
			if parsed.User.Username() != "" {
				if password, ok := parsed.User.Password(); !ok {
					return fmt.Errorf("password is empty for proxy %d", i)
				} else {
					auth := parsed.User.Username() + ":" + password
					basicAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(auth))
					s.ProxyDialer.DefaultHeader.Add("Proxy-Authorization", basicAuth)
				}
			}
		}
	}
	return nil
}

// Dial establishes a connection (implements ProxyDialer interface)
func (c *proxyDialer) Dial(userAgent, network, address string) (net.Conn, error) {
	return c.DialContext(context.Background(), userAgent, network, address)
}

// DialContext establishes a connection with context (implements ProxyDialer interface)
func (c *proxyDialer) DialContext(ctx context.Context, userAgent, network, address string) (net.Conn, error) {
	if len(c.ProxyChain) == 0 {
		return nil, errors.New("proxy chain is empty")
	}

	// Check for SOCKS proxy (handle differently)
	if strings.HasPrefix(c.ProxyChain[0].Scheme, "socks") {
		return c.handleSOCKSProxy(ctx, network, address)
	}

	// Check if we can reuse an existing HTTP/2 connection
	if c.H2Conn != nil && c.conn != nil {
		c.h2Mu.Lock()
		if c.H2Conn.CanTakeNewRequest() {
			rc := c.conn
			cc := c.H2Conn
			c.h2Mu.Unlock()
			if proxyConn, err := c.connectThroughExistingH2(ctx, userAgent, address, rc, cc); err == nil {
				return proxyConn, nil
			}
		}
		c.h2Mu.Unlock()
	}

	// Establish connection through the proxy chain
	conn, negotiatedProtocol, err := c.establishChainConnection(ctx, userAgent, network)
	if err != nil {
		return nil, err
	}

	// Check if the target is HTTP (port 80) - no need to tunnel
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}

	if port == portMap[SchemeHttp] {
		return conn, nil
	}

	// Tunnel to the final destination
	return c.tunnelToDestination(ctx, userAgent, address, conn, negotiatedProtocol)
}

// handleSOCKSProxy handles SOCKS proxy connections
func (c *proxyDialer) handleSOCKSProxy(ctx context.Context, network, address string) (net.Conn, error) {
	if len(c.ProxyChain) > 1 {
		return nil, errors.New("SOCKS proxy chaining not supported")
	}

	dial, err := proxy.FromURL(c.ProxyChain[0], proxy.Direct)
	if err != nil {
		return nil, err
	}

	if fn, ok := dial.(proxy.ContextDialer); ok {
		return fn.DialContext(ctx, network, address)
	}

	// in case the dialer does not support context
	return dial.Dial(network, address)
}

// establishChainConnection establishes connection through all proxies in the chain
func (c *proxyDialer) establishChainConnection(ctx context.Context, userAgent, network string) (net.Conn, string, error) {
	var conn net.Conn
	var negotiatedProtocol string
	var err error

	// Connect to the first proxy
	firstProxy := c.ProxyChain[0]
	conn, negotiatedProtocol, err = c.connectToProxy(ctx, firstProxy, network)
	if err != nil {
		return nil, "", fmt.Errorf("failed to connect to first proxy: %w", err)
	}

	// For single proxy, we're done with initial connection
	if len(c.ProxyChain) == 1 {
		return conn, negotiatedProtocol, nil
	}

	// Tunnel through each subsequent proxy
	for i := 1; i < len(c.ProxyChain); i++ {
		p := c.ProxyChain[i]
		var tmpConn net.Conn
		tmpConn, negotiatedProtocol, err = c.tunnelThroughProxy(ctx, userAgent, conn, p, negotiatedProtocol)
		if err != nil {
			_ = conn.Close()
			return nil, "", fmt.Errorf("failed to tunnel through proxy %d: %w", i, err)
		}
		conn = tmpConn
	}

	return conn, negotiatedProtocol, nil
}

// connectToProxy establishes initial connection to a proxy
func (c *proxyDialer) connectToProxy(ctx context.Context, proxyURL *url.URL, network string) (net.Conn, string, error) {
	switch proxyURL.Scheme {
	case SchemeHttp:
		conn, err := c.Dialer.DialContext(ctx, network, proxyURL.Host)
		return conn, "", err

	case SchemeHttps:
		if c.DialTLS != nil {
			return c.DialTLS(network, proxyURL.Host)
		} else {
			tlsConf := tls.Config{
				NextProtos:         []string{"h2", "http/1.1"},
				ServerName:         proxyURL.Hostname(),
				InsecureSkipVerify: true,
			}
			tlsConn, err := tls.Dial(network, proxyURL.Host, &tlsConf)
			if err != nil {
				return nil, "", err
			}
			err = tlsConn.Handshake()
			if err != nil {
				return nil, "", err
			}
			negotiatedProtocol := tlsConn.ConnectionState().NegotiatedProtocol
			return tlsConn, negotiatedProtocol, nil
		}

	default:
		return nil, "", fmt.Errorf("unsupported proxy scheme: %s", proxyURL.Scheme)
	}
}

// tunnelThroughProxy tunnels through an intermediate proxy to reach the next proxy
func (c *proxyDialer) tunnelThroughProxy(ctx context.Context, userAgent string, conn net.Conn, nextProxy *url.URL, currentProtocol string) (net.Conn, string, error) {
	req := c.buildTunnelRequest(ctx, userAgent, nextProxy.Host)

	// Add authentication if needed
	if nextProxy.User != nil {
		username := nextProxy.User.Username()
		password, _ := nextProxy.User.Password()
		auth := username + ":" + password
		basicAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(auth))
		req.Header.Set("Proxy-Authorization", basicAuth)
	}

	// Handle HTTP/2 vs HTTP/1.1
	if currentProtocol == http2.NextProtoTLS {
		if h2clientConn, err := c.sess.HTTP2Transport.NewClientConn(conn); err == nil {
			return c.connectHTTP2Tunnel(req, conn, h2clientConn, nextProxy)
		}
	}

	// Fallback to HTTP/1.1
	if err := c.connectHTTP1Tunnel(req, conn); err != nil {
		return nil, "", err
	}

	// If next proxy is HTTPS, upgrade the connection
	if nextProxy.Scheme == SchemeHttps {
		return c.upgradeToTLS(conn, nextProxy)
	}

	return conn, "", nil
}

// tunnelToDestination establishes final tunnel to the destination
func (c *proxyDialer) tunnelToDestination(ctx context.Context, userAgent, address string, conn net.Conn, negotiatedProtocol string) (net.Conn, error) {
	req := c.buildTunnelRequest(ctx, userAgent, address)
	c.addSessionHeaders(req)

	if ctxHeader, ctxHasHeader := ctx.Value(ContextKeyHeader{}).(http.Header); ctxHasHeader {
		for k, v := range ctxHeader {
			req.Header[k] = v
		}
	}

	// Handle HTTP/2 vs HTTP/1.1
	if negotiatedProtocol == http2.NextProtoTLS {
		if h2clientConn, err := c.sess.HTTP2Transport.NewClientConn(conn); err == nil {
			if proxyConn, err := c.connectHTTP2Final(req, conn, h2clientConn); err == nil {
				c.h2Mu.Lock()
				c.H2Conn = h2clientConn
				c.conn = conn
				c.h2Mu.Unlock()
				return proxyConn, nil
			}
		}
	}

	// Fallback to HTTP/1.1
	if err := c.connectHTTP1Tunnel(req, conn); err != nil {
		return nil, err
	}

	return conn, nil
}

// buildTunnelRequest builds a CONNECT request for tunneling
func (c *proxyDialer) buildTunnelRequest(ctx context.Context, userAgent, address string) *http.Request {
	req := (&http.Request{
		Method: http.MethodConnect,
		URL: &url.URL{
			Host: address,
		},
		Header: make(http.Header),
		Host:   address,
	}).WithContext(ctx)

	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Connection", "keep-alive")

	// Copy default headers
	for k, v := range c.DefaultHeader {
		req.Header[k] = v
	}

	return req
}

// addSessionHeaders adds session-specific proxy headers
func (c *proxyDialer) addSessionHeaders(req *http.Request) {
	for k, v := range c.sess.ProxyHeader {
		if k == http.HeaderOrderKey {
			for _, vv := range v {
				req.Header[http.HeaderOrderKey] = append(req.Header[http.HeaderOrderKey], strings.ToLower(vv))
			}
		} else {
			req.Header[k] = v
		}
	}
}

// connectHTTP1Tunnel establishes HTTP/1.1 tunnel
func (c *proxyDialer) connectHTTP1Tunnel(req *http.Request, conn net.Conn) error {
	req.Proto = "HTTP/1.1"
	req.ProtoMajor = 1
	req.ProtoMinor = 1

	err := req.Write(conn)
	if err != nil {
		return err
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("proxy tunnel failed: %s", resp.Status)
	}

	return nil
}

// connectHTTP2Tunnel establishes HTTP/2 tunnel for intermediate proxy
func (c *proxyDialer) connectHTTP2Tunnel(req *http.Request, conn net.Conn, h2clientConn *http2.ClientConn, nextProxy *url.URL) (net.Conn, string, error) {
	req.Proto = "HTTP/2.0"
	req.ProtoMajor = 2
	req.ProtoMinor = 0
	pr, pw := io.Pipe()
	req.Body = pr

	resp, err := h2clientConn.RoundTrip(req)
	if err != nil {
		return nil, "", err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("proxy tunnel failed: %s", resp.Status)
	}

	tunneledConn := newHTTP2Conn(conn, pw, resp.Body)

	// If next proxy is HTTPS, upgrade the tunneled connection
	if nextProxy.Scheme == SchemeHttps {
		return c.upgradeToTLS(tunneledConn, nextProxy)
	}

	return tunneledConn, "", nil
}

// connectHTTP2Final establishes HTTP/2 tunnel to final destination
func (c *proxyDialer) connectHTTP2Final(req *http.Request, conn net.Conn, h2clientConn *http2.ClientConn) (net.Conn, error) {
	req.Proto = "HTTP/2.0"
	req.ProtoMajor = 2
	req.ProtoMinor = 0
	pr, pw := io.Pipe()
	req.Body = pr

	resp, err := h2clientConn.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("proxy tunnel failed: %s", resp.Status)
	}

	return newHTTP2Conn(conn, pw, resp.Body), nil
}

// connectThroughExistingH2 reuses existing HTTP/2 connection for new requests
func (c *proxyDialer) connectThroughExistingH2(ctx context.Context, userAgent, address string, conn net.Conn, h2Conn *http2.ClientConn) (net.Conn, error) {
	req := c.buildTunnelRequest(ctx, userAgent, address)
	c.addSessionHeaders(req)
	return c.connectHTTP2Final(req, conn, h2Conn)
}

// upgradeToTLS upgrades a connection to TLS
func (c *proxyDialer) upgradeToTLS(conn net.Conn, proxyURL *url.URL) (net.Conn, string, error) {
	tlsConf := tls.Config{
		NextProtos:         []string{"h2", "http/1.1"},
		ServerName:         proxyURL.Hostname(),
		InsecureSkipVerify: true,
	}
	tlsConn := tls.UClient(conn, &tlsConf, tls.HelloCustom)

	// Apply TLS fingerprint
	var fn = c.sess.GetClientHelloSpec
	if fn == nil {
		fn = GetBrowserClientHelloFunc(c.sess.Browser)
	}
	specs := fn()

	if err := tlsConn.ApplyPreset(specs); err != nil {
		return nil, "", fmt.Errorf("failed to apply TLS preset: %w", err)
	}

	if err := tlsConn.Handshake(); err != nil {
		return nil, "", fmt.Errorf("failed TLS handshake: %w", err)
	}

	return tlsConn.Conn, tlsConn.ConnectionState().NegotiatedProtocol, nil
}

// HTTP/2 connection wrapper (unchanged from original)
func newHTTP2Conn(c net.Conn, pipedReqBody *io.PipeWriter, respBody io.ReadCloser) net.Conn {
	return &http2Conn{Conn: c, in: pipedReqBody, out: respBody}
}

type http2Conn struct {
	net.Conn
	in  *io.PipeWriter
	out io.ReadCloser
}

func (h *http2Conn) Read(p []byte) (n int, err error) {
	return h.out.Read(p)
}

func (h *http2Conn) Write(p []byte) (n int, err error) {
	return h.in.Write(p)
}

func (h *http2Conn) Close() error {
	var retErr error = nil
	if err := h.in.Close(); err != nil {
		retErr = err
	}
	if err := h.out.Close(); err != nil {
		retErr = err
	}
	return retErr
}

func (h *http2Conn) CloseConn() error {
	return h.Conn.Close()
}

func (h *http2Conn) CloseWrite() error {
	return h.in.Close()
}

func (h *http2Conn) CloseRead() error {
	return h.out.Close()
}

// ClearProxy removes the proxy from the session (updated to handle unified dialer)
func (s *Session) ClearProxy() {
	if s.ProxyDialer != nil {
		if s.ProxyDialer.conn != nil {
			_ = s.ProxyDialer.conn.Close()
		}
		if s.ProxyDialer.H2Conn != nil {
			_ = s.ProxyDialer.H2Conn.Close()
		}
		s.ProxyDialer = nil
	}

	if s.Transport != nil {
		s.Transport.Proxy = nil
		s.Transport.CloseIdleConnections()
	}

	if s.HTTP2Transport != nil {
		s.HTTP2Transport.CloseIdleConnections()
	}

	if s.HTTP3Config != nil && s.HTTP3Config.transport != nil {
		s.HTTP3Config.transport.CloseIdleConnections()
		_ = s.HTTP3Config.transport.Close()
		s.HTTP3Config.transport = nil
	}

	s.Proxy = ""
}

// ClearProxyChain removes the proxy chain from the session (alias for ClearProxy)
func (s *Session) ClearProxyChain() {
	s.ClearProxy()
}

// IsChainProxy returns true if the session is using a proxy chain
func (s *Session) IsChainProxy() bool {
	if s.ProxyDialer == nil {
		return false
	}

	return len(s.ProxyDialer.ProxyChain) > 1
}

// GetProxyChain returns the current proxy chain URLs
func (s *Session) GetProxyChain() []*url.URL {
	if s.ProxyDialer == nil {
		return nil
	}

	return s.ProxyDialer.ProxyChain
}
