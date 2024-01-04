package azuretls

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	http "github.com/Noooste/fhttp"
	"github.com/Noooste/fhttp/http2"
	"github.com/Noooste/utls"
	"golang.org/x/net/proxy"
	"io"
	"net"
	"net/url"
	"strings"
	"sync"
)

type proxyDialer struct {
	ProxyURL      *url.URL
	DefaultHeader http.Header

	Dialer net.Dialer

	DialTLS func(network string, address string) (net.Conn, string, error)

	h2Mu   sync.Mutex
	H2Conn *http2.ClientConn
	conn   net.Conn

	tr         *http2.Transport
	ForceHTTP2 bool
}

const (
	invalidProxy = "invalid proxy `%s`, %s"
)

func (s *Session) assignProxy(proxy string) error {
	parsed, err := url.Parse(proxy)

	if err != nil {
		return err
	}

	if parsed.Host == "" {
		return fmt.Errorf(invalidProxy, proxy, "make sure to specify full url like http(s)://username:password@ip:port")
	}

	switch parsed.Scheme {
	case "":
		return fmt.Errorf(invalidProxy, proxy, "empty scheme")

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
		return fmt.Errorf(invalidProxy, proxy, "scheme "+parsed.Scheme+" is not supported")
	}

	s.ProxyDialer = &proxyDialer{
		ProxyURL:      parsed,
		DefaultHeader: make(http.Header),
	}

	if parsed.User != nil {
		if parsed.User.Username() != "" {
			if password, ok := parsed.User.Password(); !ok {
				return fmt.Errorf(invalidProxy, proxy, "password is empty")
			} else {
				auth := parsed.User.Username() + ":" + password
				basicAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(auth))
				s.ProxyDialer.DefaultHeader.Add("Proxy-Authorization", basicAuth)
			}
		}
	}

	return nil
}

func (c *proxyDialer) Dial(network, address string) (net.Conn, error) {
	return c.DialContext(context.Background(), network, address)
}

type ContextKeyHeader struct{}

func (c *proxyDialer) connectHTTP1(req *http.Request, conn net.Conn) error {
	req.Proto = "HTTP/1.1"
	req.ProtoMajor = 1
	req.ProtoMinor = 1

	err := req.Write(conn)
	if err != nil {
		_ = conn.Close()
		return err
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		_ = conn.Close()
		return err
	}

	if resp.StatusCode != http.StatusOK {
		_ = conn.Close()
		return fmt.Errorf("proxy error : %s", resp.Status)
	}

	return nil
}

func (c *proxyDialer) connectHTTP2(req *http.Request, conn net.Conn, h2clientConn *http2.ClientConn) (net.Conn, error) {
	req.Proto = "HTTP/2.0"
	req.ProtoMajor = 2
	req.ProtoMinor = 0
	pr, pw := io.Pipe()
	req.Body = pr

	resp, err := h2clientConn.RoundTrip(req)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		_ = conn.Close()
		return nil, fmt.Errorf("proxy error : %s", resp.Status)
	}

	return newHTTP2Conn(conn, pw, resp.Body), nil
}

func (c *proxyDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if c.ProxyURL == nil {
		return nil, errors.New("proxy is not set")
	}

	if strings.HasPrefix(c.ProxyURL.Scheme, "socks") {
		dial, err := proxy.FromURL(c.ProxyURL, proxy.Direct)
		if err != nil {
			return nil, err
		}
		return dial.(proxy.ContextDialer).DialContext(ctx, network, address)
	}

	req := (&http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Host: address},
		Header: make(http.Header),
		Host:   address,
	}).WithContext(ctx)

	for k, v := range c.DefaultHeader {
		req.Header[k] = v
	}

	if ctxHeader, ctxHasHeader := ctx.Value(ContextKeyHeader{}).(http.Header); ctxHasHeader {
		for k, v := range ctxHeader {
			req.Header[k] = v
		}
	}

	c.h2Mu.Lock()
	unlocked := false
	if c.H2Conn != nil && c.conn != nil {
		if c.H2Conn.CanTakeNewRequest() {
			rc := c.conn
			cc := c.H2Conn
			c.h2Mu.Unlock()
			unlocked = true
			proxyConn, err := c.connectHTTP2(req, rc, cc)
			if err == nil {
				return proxyConn, nil
			}
		}
	}

	if !unlocked {
		c.h2Mu.Unlock()
	}

	rawConn, negotiatedProtocol, err := c.InitProxyConn(ctx, network)

	if err != nil {
		return nil, err
	}

	proxyConn, err := c.connect(req, rawConn, negotiatedProtocol)

	if err != nil {
		return nil, err
	}

	return proxyConn, nil
}

func (c *proxyDialer) InitProxyConn(ctx context.Context, network string) (rawConn net.Conn, negotiatedProtocol string, err error) {
	switch c.ProxyURL.Scheme {
	case SchemeHttp:
		rawConn, err = c.Dialer.DialContext(ctx, network, c.ProxyURL.Host)
		if err != nil {
			return nil, "", err
		}

	case SchemeHttps:
		if c.DialTLS != nil {
			rawConn, negotiatedProtocol, err = c.DialTLS(network, c.ProxyURL.Host)
			if err != nil {
				return nil, "", err
			}
		} else {
			tlsConf := tls.Config{
				NextProtos:         []string{"h2", "http/1.1"},
				ServerName:         c.ProxyURL.Hostname(),
				InsecureSkipVerify: true,
			}
			var tlsConn *tls.Conn
			tlsConn, err = tls.Dial(network, c.ProxyURL.Host, &tlsConf)
			if err != nil {
				return nil, "", err
			}
			err = tlsConn.Handshake()
			if err != nil {
				return nil, "", err
			}
			negotiatedProtocol = tlsConn.ConnectionState().NegotiatedProtocol
			rawConn = tlsConn
		}
	default:
		return nil, "", errors.New("scheme " + c.ProxyURL.Scheme + " is not supported")
	}

	return
}

func (c *proxyDialer) connect(req *http.Request, conn net.Conn, negotiatedProtocol string) (net.Conn, error) {
	if c.ForceHTTP2 || negotiatedProtocol == http2.NextProtoTLS {
		if h2clientConn, err := c.tr.NewClientConn(conn); err == nil {
			if proxyConn, err := c.connectHTTP2(req, conn, h2clientConn); err == nil {
				c.h2Mu.Lock()
				c.H2Conn = h2clientConn
				c.conn = conn
				c.h2Mu.Unlock()
				return proxyConn, err
			}
		}
	}

	if err := c.connectHTTP1(req, conn); err != nil {
		_ = conn.Close()
		return nil, err
	}

	return conn, nil

}

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
