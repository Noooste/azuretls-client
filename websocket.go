package azuretls

import (
	"context"
	"errors"
	http "github.com/Noooste/fhttp"
	"github.com/Noooste/websocket"
	"net"
	"net/url"
)

var (
	ErrNilRequest = errors.New("request is nil")
)

type Websocket struct {
	Url     string
	Headers http.Header

	Request  *Request
	Response *http.Response

	dialer *websocket.Dialer

	*websocket.Conn
}

func (s *Session) NewWebsocket(req *Request, args ...any) (*Websocket, error) {
	return s.NewWebsocketWithContext(context.Background(), req, args...)
}

func (s *Session) NewWebsocketWithContext(ctx context.Context, req *Request, args ...any) (*Websocket, error) {
	if req == nil {
		return nil, ErrNilRequest
	}

	if err := s.prepareRequest(req, args...); err != nil {
		return nil, err
	}

	var (
		ws = new(Websocket)
		h  = make(http.Header)

		conn *Conn
		err  error
	)

	req.HttpRequest = &http.Request{}
	req.parsedUrl, err = url.Parse(req.Url)

	if err != nil {
		return nil, err
	}

	req.formatHeader()

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

	ws.dialer = &websocket.Dialer{}
	ws.dialer.Jar = s.CookieJar

	if conn, err = s.initConn(req); err != nil {
		return nil, err
	}

	ws.dialer.NetDialContext = func(c context.Context, network, addr string) (net.Conn, error) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
			return conn.Conn, nil
		}
	}

	ws.dialer.NetDialTLSContext = func(c context.Context, network, addr string) (net.Conn, error) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
			return conn.TLS.Conn, nil
		}
	}

	c, resp, err := ws.dialer.DialContext(ctx, req.parsedUrl.String(), h, h[http.HeaderOrderKey])

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
