package azuretls

import (
	"context"
	"errors"
	"fmt"
	http "github.com/Noooste/fhttp"
	"github.com/Noooste/fhttp/cookiejar"
	"github.com/Noooste/go-utils"
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

		Connections:        NewRequestConnPool(ctx),
		GetClientHelloSpec: GetLastChromeVersion,

		ServerPush: make(chan *Response, 10),

		mu: &sync.Mutex{},

		TimeOut: 30 * time.Second,
		ctx:     ctx,
	}

	return s
}

func (s *Session) SetTimeout(timeout time.Duration) {
	s.TimeOut = timeout
}

func (s *Session) SetContext(ctx context.Context) {
	s.ctx = ctx
	s.Connections.SetContext(ctx)
}

var proxyCheckReg = regexp.MustCompile(`^(https?://)(?:(\w+)(:(\w*))@)?(\w[\w\-_]{0,61}\w?\.(\w{1,6}|[\w-]{1,30}\.\w{2,3})|((\d{1,3})(?:\.\d{1,3}){3}))(:(\d{1,5}))$`)

func (s *Session) SetProxy(proxy string) {
	defer s.Close()

	switch {
	case proxyCheckReg.MatchString(proxy), strings.HasPrefix(proxy, "http://"), strings.HasPrefix(proxy, "https://"):
		s.Proxy = proxy
	default:
		s.Proxy = formatProxy(proxy)
	}
}

func (s *Session) Ip() (ip string, err error) {
	r, err := s.Get("https://api.ipify.org")
	if err != nil {
		return
	}
	return string(r.Body), nil
}

func (s *Session) send(request *Request) (response *Response, err error) {
	if request.retries > 5 {
		return nil, fmt.Errorf("retries exceeded")
	}

	var (
		httpResponse *http.Response

		roundTripper http.RoundTripper
		rConn        *Conn
	)

	httpRequest, err := s.buildRequest(request.ctx, request)
	if err != nil {
		return nil, err
	}

	request.HttpRequest = httpRequest
	request.parsedUrl = httpRequest.URL

	if err = s.initTransport(request.Browser); err != nil {
		utils.SafeGoRoutine(func() { s.saveVerbose(request, nil, err) })
		return nil, err
	}

	if rConn, err = s.initConn(request); err != nil {
		utils.SafeGoRoutine(func() { s.saveVerbose(request, nil, err) })
		return nil, err
	}

	request.conn = rConn

	if rConn.HTTP2 != nil {
		roundTripper = rConn.HTTP2
	} else {
		roundTripper = s.tr
	}

	httpResponse, err = roundTripper.RoundTrip(httpRequest)

	defer func() {
		if s.Callback != nil {
			s.Callback(request, response, err)
		}
	}()

	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, fmt.Errorf("timeout")
		}
		return
	}

	response = &Response{
		IgnoreBody: request.IgnoreBody,
		Request:    request,
	}

	s.buildResponse(response, httpResponse)

	utils.SafeGoRoutine(func() {
		s.saveVerbose(request, response, err)
	})

	return response, nil
}

/*
Do sends a request and returns a response
*/
func (s *Session) Do(request *Request, args ...any) (*Response, error) {
	return s.do(request, args...)
}

func (s *Session) do(req *Request, args ...any) (resp *Response, err error) {
	err = s.prepareRequest(req, args...)

	if err != nil {
		return
	}

	if req.ctx == nil {
		req.ctx = s.ctx
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
				return nil, fmt.Errorf("%d response missing Location header", resp.StatusCode)
			}

			var u *url.URL
			u, err = req.parsedUrl.Parse(loc)
			if err != nil {
				resp.CloseBody()
				return nil, fmt.Errorf("failed to parse Location header %q: %v", loc, err)
			}

			oldReq := req

			req = &Request{
				Method:             redirectMethod,
				Url:                u.String(),
				parsedUrl:          u,
				Proxy:              oldReq.Proxy,
				IgnoreBody:         oldReq.IgnoreBody,
				Browser:            oldReq.Browser,
				TimeOut:            oldReq.TimeOut,
				InsecureSkipVerify: oldReq.InsecureSkipVerify,
				listenServerPush:   oldReq.listenServerPush,
				PHeader:            oldReq.PHeader,
				ctx:                oldReq.ctx,
			}

			err = s.prepareRequest(req, args...)
			if err != nil {
				return
			}

			if oldReq.OrderedHeaders != nil {
				req.OrderedHeaders = oldReq.OrderedHeaders.Clone()
			} else if oldReq.Header != nil {
				req.Header = oldReq.Header.Clone()
				req.HeaderOrder = oldReq.HeaderOrder
			}

			oldRequest := reqs[0]

			if includeBody && oldRequest.Body != nil {
				req.Body = oldRequest.Body
				req.contentLength = oldRequest.contentLength
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
			return nil, err
		}

		if req.DisableRedirects {
			req.CloseBody()
			return resp, nil
		}

		var shouldRedirect bool
		redirectMethod, shouldRedirect, includeBody = redirectBehavior(req.Method, resp, reqs[0])
		if !shouldRedirect {
			req.CloseBody()
			return resp, nil
		}

		if redirectMethod == http.MethodGet {
			req.Body = nil
			req.contentLength = 0
		}

		req.CloseBody()
	}
}

/*
Get provides shortcut for sending GET request
*/
func (s *Session) Get(url string, args ...any) (*Response, error) {
	request := &Request{
		Method: http.MethodGet,
		Url:    url,
	}

	return s.do(request, args...)
}

/*
Post provides shortcut for sending POST request
*/
func (s *Session) Post(url string, data []byte, args ...any) (*Response, error) {
	request := &Request{
		Method: http.MethodPost,
		Url:    url,
		Body:   data,
	}

	return s.do(request, args...)
}

/*
Put provides shortcut for sending PUT request
*/
func (s *Session) Put(url string, data []byte, args ...any) (*Response, error) {
	request := &Request{
		Method: http.MethodPut,
		Url:    url,
		Body:   data,
	}

	return s.do(request, args...)
}

/*
Patch provides shortcut for sending PATCH request²
*/
func (s *Session) Patch(url string, data any, args ...any) (*Response, error) {
	request := &Request{
		Method: http.MethodPatch,
		Url:    url,
		Body:   data,
	}

	return s.do(request, args...)
}

/*
Delete provides shortcut for sending DELETE request
*/
func (s *Session) Delete(url string, args ...any) (*Response, error) {
	request := &Request{
		Method: http.MethodDelete,
		Url:    url,
	}

	return s.do(request, args...)
}

/*
Head provides shortcut for sending HEAD request
*/
func (s *Session) Head(url string, args ...any) (*Response, error) {
	request := &Request{
		Method: http.MethodHead,
		Url:    url,
	}

	return s.do(request, args...)
}

/*
Options provides shortcut for sending OPTIONS request
*/
func (s *Session) Options(url string, args ...any) (*Response, error) {
	request := &Request{
		Method: http.MethodOptions,
		Url:    url,
	}

	return s.do(request, args...)
}

func (s *Session) Close() {
	s.Connections.Close()
	s.Connections = NewRequestConnPool(s.ctx)
}
