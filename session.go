package azuretls

import (
	"context"
	"errors"
	"fmt"
	http "github.com/Noooste/fhttp"
	"github.com/Noooste/fhttp/cookiejar"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	http2errClientConnClosed    = "http2: client conn is closed"
	http2errClientConnUnusable  = "http2: client conn not usable"
	http2errClientConnGotGoAway = "http2: Transport received Server's graceful shutdown GOAWAY"
)

// NewSession creates a new session
// It is a shortcut for NewSessionWithContext(context.Background())
func NewSession() *Session {
	return NewSessionWithContext(context.Background())
}

// NewSessionWithContext creates a new session with context
// It is recommended to use this function to create a new session instead of creating a new Session struct
func NewSessionWithContext(ctx context.Context) *Session {
	cookieJar, _ := cookiejar.New(nil)

	s := &Session{
		OrderedHeaders: make(OrderedHeaders, 0),

		CookieJar: cookieJar,
		Browser:   Chrome,

		Connections:        NewRequestConnPool(ctx),
		GetClientHelloSpec: GetLastChromeVersion,

		UserAgent: defaultUserAgent,

		MaxRedirects: 10,

		mu: new(sync.Mutex),

		TimeOut: 30 * time.Second,
		ctx:     ctx,
	}

	return s
}

// SetTimeout sets timeout for the session
func (s *Session) SetTimeout(timeout time.Duration) {
	s.TimeOut = timeout
	if s.Transport != nil {
		s.Transport.TLSHandshakeTimeout = timeout
		s.Transport.ResponseHeaderTimeout = timeout
	}
}

// SetContext sets the given context for the session
func (s *Session) SetContext(ctx context.Context) {
	s.ctx = ctx
	s.Connections.SetContext(ctx)
}

// Ip returns the public IP address of the session
func (s *Session) Ip() (ip string, err error) {
	r, err := s.Get("https://api.ipify.org")
	if err != nil {
		return
	}
	return string(r.Body), nil
}

// SetProxy sets the proxy for the session
func (s *Session) SetProxy(proxy string) error {
	defer s.Close()

	if proxy == "" {
		return fmt.Errorf("proxy is empty")
	}

	switch {
	case strings.HasPrefix(proxy, "socks5h://"), strings.HasPrefix(proxy, "socks5://"),
		strings.HasPrefix(proxy, "http://"), strings.HasPrefix(proxy, "https://"):
		s.Proxy = proxy

	default:
		s.Proxy = formatProxy(proxy)
	}

	if err := s.assignProxy(s.Proxy); err != nil {
		return err
	}

	return nil
}

// ClearProxy removes the proxy from the session
func (s *Session) ClearProxy() {
	s.Proxy = ""
	s.ProxyDialer = nil
	s.Connections.Close()
}

func (s *Session) send(request *Request) (response *Response, err error) {
	var (
		httpResponse *http.Response
		roundTripper http.RoundTripper
		rConn        *Conn
	)

	if err = s.buildRequest(request.ctx, request); err != nil {
		return nil, err
	}

	request.parsedUrl = request.HttpRequest.URL

	if err = s.initTransport(s.Browser); err != nil {
		s.dumpRequest(request, nil, err)
		return nil, err
	}

	if rConn, err = s.initConn(request); err != nil {
		s.dumpRequest(request, nil, err)
		return nil, err
	}

	request.conn = rConn
	request.Proto = rConn.Proto

	if rConn.HTTP2 != nil {
		roundTripper = rConn.HTTP2
	} else {
		roundTripper = s.Transport
	}

	s.logRequest(request)

	httpResponse, err = roundTripper.RoundTrip(request.HttpRequest)

	response = &Response{
		IgnoreBody: request.IgnoreBody,
		Request:    request,
	}

	defer func() {
		if s.Callback != nil {
			s.Callback(request, response, err)
		}
	}()

	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			rConn.Close()
			s.logResponse(response, err)
			return nil, fmt.Errorf("timeout")
		}
		s.logResponse(response, err)
		return
	}

	err = s.buildResponse(response, httpResponse)

	s.dumpRequest(request, response, err)
	s.logResponse(response, err)

	return response, err
}

// Do sends a request and returns a response
func (s *Session) Do(request *Request, args ...any) (*Response, error) {
	return s.do(request, args...)
}

func (s *Session) do(req *Request, args ...any) (resp *Response, err error) {
	if err = s.prepareRequest(req, args...); err != nil {
		return
	}

	if req.ctx == nil {
		req.ctx = s.ctx
	}

	var reqs = make([]*Request, 0, req.MaxRedirects+1)

	var (
		redirectMethod string
		includeBody    bool
		copyHeaders    = s.makeHeadersCopier(req)
	)

	var i uint
	for i = 0; i < req.MaxRedirects; i++ {
		// For all but the first request, create the next
		// request hop and replace req.
		if len(reqs) > 0 {
			loc := resp.Header.Get("Location")
			if loc == "" {
				_ = resp.CloseBody()
				return nil, fmt.Errorf("%d response missing Location header", resp.StatusCode)
			}

			var u *url.URL
			u, err = req.parsedUrl.Parse(loc)
			if err != nil {
				_ = resp.CloseBody()
				return nil, fmt.Errorf("failed to parse Location header %q: %v", loc, err)
			}

			oldReq := req

			req = &Request{
				Method:             redirectMethod,
				Url:                u.String(),
				parsedUrl:          u,
				Response:           resp,
				IgnoreBody:         oldReq.IgnoreBody,
				TimeOut:            oldReq.TimeOut,
				InsecureSkipVerify: oldReq.InsecureSkipVerify,
				PHeader:            oldReq.PHeader,
				ctx:                oldReq.ctx,
			}

			copyHeaders(req)

			err = s.prepareRequest(req, args...)
			if err != nil {
				return
			}

			oldRequest := reqs[0]

			if includeBody && oldRequest.Body != nil {
				req.Body = oldRequest.Body
				req.ContentLength = oldRequest.ContentLength
			}

			// Add the Referer header from the most recent
			// request URL to the new one, if it's not https->http:
			if ref := RefererForURL(reqs[len(reqs)-1].parsedUrl, req.parsedUrl); ref != "" {
				req.OrderedHeaders.Set("referer", ref)
			}
		}

		reqs = append(reqs, req)

		req.startTime = time.Now()
		if resp, err = s.send(req); err != nil {
			return nil, err
		}

		if req.DisableRedirects {
			req.CloseBody()
			return resp, nil
		}

		var shouldRedirect bool

		redirectMethod, shouldRedirect, includeBody = RedirectBehavior(req.Method, resp, reqs[0])
		if !shouldRedirect {
			req.CloseBody()
			return resp, nil
		}

		req.CloseBody()
	}

	return nil, errors.New("too many Redirects")
}

// Get provides shortcut for sending GET request
func (s *Session) Get(url string, args ...any) (*Response, error) {
	request := &Request{
		Method: http.MethodGet,
		Url:    url,
	}

	return s.do(request, args...)
}

// Head provides shortcut for sending HEAD request
func (s *Session) Head(url string, args ...any) (*Response, error) {
	request := &Request{
		Method:     http.MethodHead,
		IgnoreBody: true,
		Url:        url,
	}

	return s.do(request, args...)
}

// Post provides shortcut for sending POST request
func (s *Session) Post(url string, data any, args ...any) (*Response, error) {
	request := &Request{
		Method: http.MethodPost,
		Url:    url,
		Body:   data,
	}

	return s.do(request, args...)
}

// Put provides shortcut for sending PUT request
func (s *Session) Put(url string, data any, args ...any) (*Response, error) {
	request := &Request{
		Method: http.MethodPut,
		Url:    url,
		Body:   data,
	}

	return s.do(request, args...)
}

// Delete provides shortcut for sending DELETE request
func (s *Session) Delete(url string, args ...any) (*Response, error) {
	request := &Request{
		Method: http.MethodDelete,
		Url:    url,
	}

	return s.do(request, args...)
}

// Options provides shortcut for sending OPTIONS request
func (s *Session) Options(url string, args ...any) (*Response, error) {
	request := &Request{
		Method: http.MethodOptions,
		Url:    url,
	}

	return s.do(request, args...)
}

// Patch provides shortcut for sending PATCH request
func (s *Session) Patch(url string, data any, args ...any) (*Response, error) {
	request := &Request{
		Method: http.MethodPatch,
		Url:    url,
		Body:   data,
	}

	return s.do(request, args...)
}

// Connect initiates a connection to the specified URL
func (s *Session) Connect(u string) error {
	var request = &Request{}
	var err error

	request.parsedUrl, err = url.Parse(u)
	request.Method = http.MethodConnect
	request.startTime = time.Now()

	if err != nil {
		return err
	}

	s.logRequest(request)

	if err = s.initTransport(s.Browser); err != nil {
		return err
	}

	if _, err = s.initConn(request); err != nil {
		return err
	}

	s.logResponse(&Response{
		Request: request,
	}, err)

	return nil
}

// Close closes the session and all its connections
func (s *Session) Close() {
	s.Connections.Close()
	s.Connections = NewRequestConnPool(s.ctx)
}
