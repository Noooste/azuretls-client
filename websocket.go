package azuretls

import (
	"context"
	"errors"
	"net"
	url2 "net/url"

	http "github.com/Noooste/fhttp"
	"github.com/Noooste/websocket"
)

type Websocket struct {
	Url     string
	Headers http.Header

	Request  *Request
	Response *http.Response

	dialer *websocket.Dialer

	*websocket.Conn
}

// NewWebsocket returns a new websocket connection.
func (s *Session) NewWebsocket(url string, readBufferSize, writeBufferSize int, args ...any) (*Websocket, error) {
	return s.NewWebsocketWithContext(s.ctx, url, readBufferSize, writeBufferSize, args...)
}

// NewWebsocketWithContext returns a new websocket connection with a context.
func (s *Session) NewWebsocketWithContext(ctx context.Context, url string, readBufferSize, writeBufferSize int, args ...any) (*Websocket, error) {
	if url == "" {
		return nil, errors.New("url is empty")
	}

	if readBufferSize <= 0 {
		readBufferSize = 1024
	}

	if writeBufferSize <= 0 {
		writeBufferSize = 1024
	}

	req := new(Request)
	req.Url = url

	if err := s.prepareRequest(req, args...); err != nil {
		return nil, err
	}

	var (
		ws  = new(Websocket)
		h   = make(http.Header)
		err error
	)

	req.HttpRequest = &http.Request{}
	req.parsedUrl, err = url2.Parse(req.Url)

	if err != nil {
		return nil, err
	}

	if err = s.buildRequest(ctx, req); err != nil {
		return nil, err
	}

	if !req.NoCookie {
		cookies := s.CookieJar.Cookies(req.parsedUrl)
		if cookies != nil && len(cookies) > 0 {
			if c := req.HttpRequest.Header.Get("Cookie"); c != "" {
				req.HttpRequest.Header.Set("Cookie", c+"; "+CookiesToString(cookies))
			} else {
				req.HttpRequest.Header.Set("Cookie", CookiesToString(cookies))
			}
		}
	}

	req.ForceHTTP1 = true

	ws.dialer = &websocket.Dialer{
		HandshakeTimeout: s.TimeOut,
		ReadBufferSize:   readBufferSize,
		WriteBufferSize:  writeBufferSize,
		Jar:              s.CookieJar,
		NetDialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			ctx = context.WithValue(ctx, forceHTTP1Key, true)
			return s.dialTLS(ctx, network, addr)
		},
		NetDialContext: s.dial,
	}

	c, resp, err := ws.dialer.DialContext(ctx, req.Url, req.HttpRequest.Header, req.HttpRequest.Header[http.HeaderOrderKey])

	if err != nil {
		return nil, err
	}

	return &Websocket{
		Url:      req.Url,
		Headers:  h,
		Conn:     c,
		Request:  req,
		Response: resp,
	}, nil
}
