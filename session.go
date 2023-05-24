package azuretls

import (
	"context"
	"fmt"
	http "github.com/Noooste/fhttp"
	"github.com/Noooste/fhttp/cookiejar"
	"github.com/Noooste/fhttp/http2"
	"github.com/Noooste/go-utils"
	"github.com/Noooste/utls"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	http2errClientConnClosed    = "http2: client conn is closed"
	http2errClientConnUnusable  = "http2: client conn not usable"
	http2errClientConnGotGoAway = "http2: Transport received Server's graceful shutdown GOAWAY"
)

type sessionConn struct {
	tlsConn *tls.UConn
	conn    *http2.ClientConn

	pins []string
}

/*
NewSession creates a new session
It is recommended to use this function to create a new session instead of creating a new Session struct
This function will set the default values for the session
*/
func NewSession() *Session {
	return NewSessionWithContext(context.Background())
}

func NewSessionWithContext(ctx context.Context) *Session {
	cookieJar, _ := cookiejar.New(nil)

	s := &Session{
		Headers:        http.Header{},
		HeadersOrder:   []string{},
		OrderedHeaders: OrderedHeaders{},

		CookieJar: cookieJar,
		Browser:   Chrome,

		conns:              []*sessionConn{},
		GetClientHelloSpec: GetLastChromeVersion,

		mu: &sync.Mutex{},

		TimeOut: 30 * time.Second,
		ctx:     ctx,
	}

	return s
}

func (s *Session) SetTimeout(timeout time.Duration) {
	s.TimeOut = timeout
}

var proxyCheckReg = regexp.MustCompile(`^(https?://)(?:(\w+)(:(\w*))@)?(\w[\w\-_]{0,61}\w?\.(\w{1,6}|[\w-]{1,30}\.\w{2,3})|((\d{1,3})(?:\.\d{1,3}){3}))(:(\d{1,5}))$`)

func (s *Session) SetProxy(proxy string) {
	if proxyCheckReg.MatchString(proxy) {
		s.Proxy = proxy
		s.CloseConns()
	} else {
		if strings.HasPrefix(proxy, "http://") || strings.HasPrefix(proxy, "https://") {
			s.Proxy = proxy
			s.CloseConns()
		} else {
			s.Proxy = formatProxy(proxy)
			s.CloseConns()
		}
	}
}

func (s *Session) Ip() (ip string, err error) {
	proxy, _ := url.Parse(s.Proxy)
	tr := &http.Transport{
		Proxy: http.ProxyURL(proxy),
	}
	request, _ := http.NewRequest(http.MethodGet, "http://ipinfo.io/ip", nil)

	httpResponse, err := tr.RoundTrip(request)
	if err != nil {
		return
	}
	response := s.buildResponse(&Response{}, httpResponse)
	return string(response.Body), nil
}

func (s *Session) send(request *Request) (*Response, error) {
	if request.retries > 5 {
		return nil, fmt.Errorf("retries exceeded")
	}
	var err error

	httpRequest, err := s.buildRequest(request.ctx, request)
	if err != nil {
		return nil, err
	}

	request.HttpRequest = httpRequest
	request.parsedUrl = httpRequest.URL

	if err = s.initTransport(request.Browser); err != nil {
		utils.SafeGoRoutine(func() {
			s.saveVerbose(request, nil, err)
		})
		return nil, err
	}

	var sConn *sessionConn
	if sConn, err = s.initConn(request); err != nil {
		utils.SafeGoRoutine(func() {
			s.saveVerbose(request, nil, err)
		})
		return nil, err
	}

	var httpResponse *http.Response

	var roundTripper http.RoundTripper

	if sConn.conn != nil {
		roundTripper = sConn.conn
	} else {
		roundTripper = s.tr
	}

	for i := 0; i < 5; i++ {
		httpResponse, err = roundTripper.RoundTrip(httpRequest)
		if err != nil {
			switch err.Error() {
			case http2errClientConnClosed, http2errClientConnUnusable, http2errClientConnGotGoAway:
				if sConn.conn != nil {
					_ = sConn.conn.Close()
					sConn.conn = nil
				}
				if sConn.tlsConn != nil {
					_ = sConn.tlsConn.Close()
					sConn.tlsConn = nil
				}
				request.retries++
				utils.SafeGoRoutine(func() {
					s.saveVerbose(request, nil, err)
				})
				return s.send(request)
			}
		} else {
			break
		}
	}

	if httpResponse == nil {
		err = request.ctx.Err()
		switch err {
		case context.Canceled, context.DeadlineExceeded:
			return nil, fmt.Errorf("timeout")
		}
		return nil, fmt.Errorf("unknown error")
	}

	response := s.buildResponse(&Response{
		IgnoreBody: request.IgnoreBody,
		Request:    request,
	}, httpResponse)

	utils.SafeGoRoutine(func() {
		s.saveVerbose(request, response, err)
	})

	utils.SafeGoRoutine(func() {
		if s.Callback != nil {
			s.Callback(request, response, err)
		}
	})

	return response, nil
}

func (s *Session) Do(request *Request, args ...any) (*Response, error) {
	return s.do(request, args...)
}

func (s *Session) do(req *Request, args ...any) (resp *Response, err error) {
	s.prepareRequest(req, args...)

	var cancel context.CancelFunc
	if req.ctx == nil {
		req.ctx, cancel = context.WithTimeout(s.ctx, req.TimeOut)
	}

	var reqs []*Request

	var (
		redirectMethod string
		includeBody    bool
	)

	for {
		// For all but the first request, create the next
		// request hop and replace req.
		if len(reqs) > 0 {
			loc := resp.Header.Get("Location")
			if loc == "" {
				resp.CloseBody()
				cancel()
				return nil, fmt.Errorf("%d response missing Location header", resp.StatusCode)
			}
			u, err := req.parsedUrl.Parse(loc)
			if err != nil {
				resp.CloseBody()
				cancel()
				return nil, fmt.Errorf("failed to parse Location header %q: %v", loc, err)
			}

			oldReq := req

			req = &Request{
				Method:           redirectMethod,
				Url:              u.String(),
				parsedUrl:        u,
				Proxy:            oldReq.Proxy,
				IgnoreBody:       oldReq.IgnoreBody,
				Browser:          oldReq.Browser,
				TimeOut:          oldReq.TimeOut,
				Verify:           oldReq.Verify,
				listenServerPush: oldReq.listenServerPush,
				PHeader:          oldReq.PHeader,
				ctx:              oldReq.ctx,
			}

			s.prepareRequest(req, args...)

			if oldReq.OrderedHeaders != nil {
				req.OrderedHeaders = oldReq.OrderedHeaders.Clone()
			} else if oldReq.Header != nil {
				req.Header = oldReq.Header.Clone()
				req.HeaderOrder = oldReq.HeaderOrder
			}

			ireq := reqs[0]

			if includeBody && ireq.Body != nil {
				req.Body = ireq.Body
				req.contentLength = ireq.contentLength
			} else {
				req.contentLength = 0
			}

			if req.contentLength != 0 {
				req.OrderedHeaders = req.OrderedHeaders.Del("content-length")
			}

			// Add the Referer header from the most recent
			// request URL to the new one, if it's not https->http:
			if ref := refererForURL(reqs[len(reqs)-1].parsedUrl, req.parsedUrl); ref != "" {
				req.OrderedHeaders.Set("referer", ref)
			}
		}

		reqs = append(reqs, req)

		if resp, err = s.send(req); err != nil {
			if cancel != nil {
				cancel()
			}
			return nil, err
		}

		if req.DisableRedirects {
			if cancel != nil {
				cancel()
			}
			return resp, nil
		}

		var shouldRedirect bool
		redirectMethod, shouldRedirect, includeBody = redirectBehavior(req.Method, resp, reqs[0])
		if !shouldRedirect {
			if cancel != nil {
				cancel()
			}
			return resp, nil
		}
		if redirectMethod == http.MethodGet {
			req.Body = nil
			req.contentLength = 0
		}

		req.CloseBody()
	}
}

func (s *Session) Get(url string, args ...any) (*Response, error) {
	request := &Request{
		Method: http.MethodGet,
		Url:    url,
	}

	return s.do(request, args...)
}
func (s *Session) Post(url string, data []byte, args ...any) (*Response, error) {
	request := &Request{
		Method: http.MethodPost,
		Url:    url,
		Body:   data,
	}

	return s.do(request, args...)
}

func (s *Session) Put(url string, data []byte, args ...any) (*Response, error) {
	request := &Request{
		Method: http.MethodPut,
		Url:    url,
		Body:   data,
	}

	return s.do(request, args...)
}

func (s *Session) Close() {
	s.CloseConns()
	s.conns = nil
}

func (s *Session) CloseConns() {
	for _, c := range s.conns {
		if c == nil {
			continue
		}
		if c.tlsConn != nil {
			_ = c.tlsConn.Close()
			c.tlsConn = nil
		}
		if c.conn != nil {
			_ = c.conn.Close()
			c.conn = nil
		}
		if c.pins != nil {
			c.pins = nil
		}
	}
	s.conns = []*sessionConn{}
}
