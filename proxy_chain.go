package azuretls

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	http "github.com/Noooste/fhttp"
	"github.com/Noooste/fhttp/http2"
	tls "github.com/Noooste/utls"
	"golang.org/x/net/proxy"
	"io"
	"net"
	"net/url"
	"strings"
	"sync"
)

// ChainProxyDialer handles chained proxy connections
type ChainProxyDialer struct {
	ProxyChain    []*url.URL
	DefaultHeader http.Header
	Dialer        net.Dialer
	DialTLS       func(network string, address string) (net.Conn, string, error)

	h2Mu   sync.Mutex
	H2Conn *http2.ClientConn
	conn   net.Conn

	sess *Session
}

// ProxyConnection represents a connection through a proxy in the chain
type ProxyConnection struct {
	conn            net.Conn
	negotiatedProto string
	h2Conn          *http2.ClientConn
	isSecure        bool
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

		switch parsed.Scheme {
		case SchemeHttp:
			if parsed.Port() == "" {
				parsed.Host = net.JoinHostPort(parsed.Host, "80")
			}
		case SchemeHttps:
			if parsed.Port() == "" {
				parsed.Host = net.JoinHostPort(parsed.Host, "443")
			}
		case Socks5, Socks5H:
			if parsed.Port() == "" {
				parsed.Host = net.JoinHostPort(parsed.Host, "1080")
			}
		default:
			return fmt.Errorf("unsupported proxy scheme %s for proxy %d", parsed.Scheme, i)
		}

		parsedProxies = append(parsedProxies, parsed)
	}

	s.ProxyDialer = &ChainProxyDialer{
		ProxyChain:    parsedProxies,
		DefaultHeader: make(http.Header),
		sess:          s,
	}

	// Set up authentication for each proxy
	for i, parsed := range parsedProxies {
		if parsed.User != nil {
			if parsed.User.Username() != "" {
				if password, ok := parsed.User.Password(); !ok {
					return fmt.Errorf("password is empty for proxy %d", i)
				} else {
					auth := parsed.User.Username() + ":" + password
					basicAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(auth))
					s.ProxyDialer.(*ChainProxyDialer).DefaultHeader.Add("Proxy-Authorization", basicAuth)
				}
			}
		}
	}

	return nil
}

// Dial establishes a connection through the proxy chain
func (c *ChainProxyDialer) Dial(userAgent, network, address string) (net.Conn, error) {
	return c.DialContext(context.Background(), userAgent, network, address)
}

// DialContext establishes a connection through the proxy chain with context
func (c *ChainProxyDialer) DialContext(ctx context.Context, userAgent, network, address string) (net.Conn, error) {
	if len(c.ProxyChain) == 0 {
		return nil, errors.New("proxy chain is empty")
	}

	// Check if we can reuse an existing HTTP/2 connection
	if c.H2Conn != nil && c.conn != nil {
		c.h2Mu.Lock()
		if c.H2Conn.CanTakeNewRequest() {
			rc := c.conn
			cc := c.H2Conn
			c.h2Mu.Unlock()
			if proxyConn, err := c.connectThroughChainHTTP2(ctx, userAgent, address, rc, cc); err == nil {
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

// establishChainConnection establishes connection through all proxies in the chain
func (c *ChainProxyDialer) establishChainConnection(ctx context.Context, userAgent, network string) (net.Conn, string, error) {
	var conn net.Conn
	var negotiatedProtocol string
	var err error

	// Connect to the first proxy
	firstProxy := c.ProxyChain[0]
	conn, negotiatedProtocol, err = c.connectToProxy(ctx, firstProxy, network)
	if err != nil {
		return nil, "", fmt.Errorf("failed to connect to first proxy: %w", err)
	}

	// Tunnel through each subsequent proxy
	for i := 1; i < len(c.ProxyChain); i++ {
		proxy := c.ProxyChain[i]
		conn, negotiatedProtocol, err = c.tunnelThroughProxy(ctx, userAgent, conn, proxy, negotiatedProtocol)
		if err != nil {
			_ = conn.Close()
			return nil, "", fmt.Errorf("failed to tunnel through proxy %d: %w", i, err)
		}
	}

	return conn, negotiatedProtocol, nil
}

// connectToProxy establishes initial connection to a proxy
func (c *ChainProxyDialer) connectToProxy(ctx context.Context, proxyURL *url.URL, network string) (net.Conn, string, error) {
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

	case Socks5, Socks5H:
		dial, err := proxy.FromURL(proxyURL, proxy.Direct)
		if err != nil {
			return nil, "", err
		}
		conn, err := dial.(proxy.ContextDialer).DialContext(ctx, network, proxyURL.Host)
		return conn, "", err

	default:
		return nil, "", fmt.Errorf("unsupported proxy scheme: %s", proxyURL.Scheme)
	}
}

// tunnelThroughProxy tunnels through an intermediate proxy to reach the next proxy
func (c *ChainProxyDialer) tunnelThroughProxy(ctx context.Context, userAgent string, conn net.Conn, nextProxy *url.URL, currentProtocol string) (net.Conn, string, error) {
	// Skip SOCKS proxies for tunneling (they handle this internally)
	if strings.HasPrefix(nextProxy.Scheme, "socks") {
		return c.connectToProxy(ctx, nextProxy, "tcp")
	}

	req := (&http.Request{
		Method: http.MethodConnect,
		URL: &url.URL{
			Host: nextProxy.Host,
		},
		Header: make(http.Header),
		Host:   nextProxy.Host,
	}).WithContext(ctx)

	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Connection", "keep-alive")

	// Add authentication if needed
	if nextProxy.User != nil {
		username := nextProxy.User.Username()
		password, _ := nextProxy.User.Password()
		auth := username + ":" + password
		basicAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(auth))
		req.Header.Set("Proxy-Authorization", basicAuth)
	}

	// Copy default headers
	for k, v := range c.DefaultHeader {
		req.Header[k] = v
	}

	// Copy session proxy headers
	for k, v := range c.sess.ProxyHeader {
		if k == http.HeaderOrderKey {
			for _, vv := range v {
				req.Header[http.HeaderOrderKey] = append(req.Header[http.HeaderOrderKey], strings.ToLower(vv))
			}
		} else {
			req.Header[k] = v
		}
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
		tlsConf := tls.Config{
			NextProtos:         []string{"h2", "http/1.1"},
			ServerName:         nextProxy.Hostname(),
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

	return conn, "", nil
}

// tunnelToDestination establishes final tunnel to the destination
func (c *ChainProxyDialer) tunnelToDestination(ctx context.Context, userAgent, address string, conn net.Conn, negotiatedProtocol string) (net.Conn, error) {
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

	// Copy headers
	for k, v := range c.DefaultHeader {
		req.Header[k] = v
	}

	for k, v := range c.sess.ProxyHeader {
		if k == http.HeaderOrderKey {
			for _, vv := range v {
				req.Header[http.HeaderOrderKey] = append(req.Header[http.HeaderOrderKey], strings.ToLower(vv))
			}
		} else {
			req.Header[k] = v
		}
	}

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

// connectHTTP1Tunnel establishes HTTP/1.1 tunnel
func (c *ChainProxyDialer) connectHTTP1Tunnel(req *http.Request, conn net.Conn) error {
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
func (c *ChainProxyDialer) connectHTTP2Tunnel(req *http.Request, conn net.Conn, h2clientConn *http2.ClientConn, nextProxy *url.URL) (net.Conn, string, error) {
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
		tlsConf := tls.Config{
			NextProtos:         []string{"h2", "http/1.1"},
			ServerName:         nextProxy.Hostname(),
			InsecureSkipVerify: true,
		}
		tlsConn := tls.UClient(tunneledConn, &tlsConf, tls.HelloCustom)

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

	return tunneledConn, "", nil
}

// connectHTTP2Final establishes HTTP/2 tunnel to final destination
func (c *ChainProxyDialer) connectHTTP2Final(req *http.Request, conn net.Conn, h2clientConn *http2.ClientConn) (net.Conn, error) {
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

// connectThroughChainHTTP2 reuses existing HTTP/2 connection for new requests
func (c *ChainProxyDialer) connectThroughChainHTTP2(ctx context.Context, userAgent, address string, conn net.Conn, h2Conn *http2.ClientConn) (net.Conn, error) {
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

	for k, v := range c.DefaultHeader {
		req.Header[k] = v
	}

	for k, v := range c.sess.ProxyHeader {
		if k == http.HeaderOrderKey {
			for _, vv := range v {
				req.Header[http.HeaderOrderKey] = append(req.Header[http.HeaderOrderKey], strings.ToLower(vv))
			}
		} else {
			req.Header[k] = v
		}
	}

	return c.connectHTTP2Final(req, conn, h2Conn)
}

// ClearProxyChain removes the proxy chain from the session
func (s *Session) ClearProxyChain() {
	if chainDialer, ok := s.ProxyDialer.(*ChainProxyDialer); ok {
		if chainDialer.conn != nil {
			_ = chainDialer.conn.Close()
		}
		if chainDialer.H2Conn != nil {
			_ = chainDialer.H2Conn.Close()
		}
	}

	s.ProxyDialer = nil

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

// IsChainProxy returns true if the session is using a proxy chain
func (s *Session) IsChainProxy() bool {
	_, ok := s.ProxyDialer.(*ChainProxyDialer)
	return ok
}

// GetProxyChain returns the current proxy chain URLs
func (s *Session) GetProxyChain() []*url.URL {
	if chainDialer, ok := s.ProxyDialer.(*ChainProxyDialer); ok {
		return chainDialer.ProxyChain
	}
	return nil
}
