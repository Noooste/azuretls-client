package azuretls

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"runtime"
	"strconv"
	"sync"
	"time"

	http "github.com/Noooste/fhttp"
	"github.com/Noooste/fhttp/cookiejar"
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

		UserAgent: defaultUserAgent,

		MaxRedirects: 10,

		PinManager: DefaultPinManager,

		mu: new(sync.Mutex),

		TimeOut: 30 * time.Second,
		ctx:     ctx,
	}

	s.setupFinalizer()

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
}

func (s *Session) Context() context.Context {
	return s.ctx
}

// Ip returns the public IP address of the session
func (s *Session) Ip() (ip string, err error) {
	r, err := s.Get("https://api.ipify.org")
	if err != nil {
		return
	}
	return string(r.Body), nil
}

func (s *Session) send(request *Request) (response *Response, err error) {
	var (
		httpResponse *http.Response
		roundTripper http.RoundTripper
	)

	if err = s.buildRequest(request.ctx, request); err != nil {
		return nil, err
	}

	request.parsedUrl = request.HttpRequest.URL

	response = &Response{
		IgnoreBody: request.IgnoreBody,
		Request:    request,
	}

	defer func() {
		if s.Callback != nil {
			s.Callback(request, response, err)
		}

		if s.CallbackWithContext != nil {
			c := &Context{
				Session:          s,
				Request:          request,
				Response:         response,
				Err:              err,
				ctx:              s.ctx,
				RequestStartTime: request.startTime,
			}

			s.CallbackWithContext(c)

			err = c.Err
			response = c.Response
		}
	}()

	if err = s.initTransport(s.Browser); err != nil {
		s.dumpRequest(request, nil, err)
		return nil, err
	}

	roundTripper, response.isHTTP3, err = s.selectTransport(request)
	if err != nil {
		s.dumpRequest(request, nil, err)
		return nil, err
	}

	s.logRequest(request)

	request.ctx = context.WithValue(request.ctx, "request", request)

	if request.ForceHTTP1 {
		request.ctx = context.WithValue(request.ctx, forceHTTP1Key, true)
	}

	request.HttpRequest = request.HttpRequest.WithContext(request.ctx)

	httpResponse, err = roundTripper.RoundTrip(request.HttpRequest)

	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			err = fmt.Errorf("timeout")
		}

		s.dumpRequest(request, response, err)
		s.logResponse(response, err)

		return nil, err
	}

	if err = s.buildResponse(response, httpResponse); err != nil {
		_ = httpResponse.Body.Close()

		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			err = fmt.Errorf("read body: timeout")
		}

		return nil, err
	}

	s.dumpRequest(request, response, err)
	s.logResponse(response, err)

	if err != nil {
		return nil, err
	}

	// Process Alt-SVC header to enable HTTP/3 for future requests, if possible.
	s.handleAltSvc(response)

	return response, err
}

// Do sends a request and returns a response
func (s *Session) Do(request *Request, args ...any) (*Response, error) {
	return s.do(request, args...)
}

func (s *Session) do(req *Request, args ...any) (resp *Response, err error) {
	if s.closed {
		return nil, errors.New("session is closed")
	}

	if err = s.prepareRequest(req, args...); err != nil {
		return
	}

	if req.ctx == nil {
		req.ctx = s.ctx
	}

	if req.deadline.IsZero() {
		req.deadline = time.Now().Add(req.TimeOut)
	}

	var cancel context.CancelFunc

	if !req.IgnoreBody {
		req.ctx, cancel = context.WithDeadline(req.ctx, req.deadline)
	}

	defer func() {
		if cancel != nil {
			cancel()
		}
	}()

	if req.DisableRedirects {
		req.startTime = time.Now()
		resp, err = s.send(req)
		if err != nil {
			return
		}
		req.CloseBody()
		req.Response = resp
		return
	}

	var reqs = make([]*Request, 0, req.MaxRedirects+1)

	var (
		redirectMethod string
		includeBody    bool
		copyHeaders    = s.makeHeadersCopier(req)
	)

	var ireq = req

	for {
		// For all but the first request, create the next
		// request hop and replace req.
		if len(reqs) > 0 {
			if resp == nil {
				return nil, errors.New("internal error: nil response")
			}

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
				deadline:           oldReq.deadline,
				MaxRedirects:       oldReq.MaxRedirects,
			}

			copyHeaders(req)

			// Add the Referer header from the first
			// request URL to the new one, if it's not https->http:
			if ref := RefererForURL(ireq.parsedUrl, req.parsedUrl); ref != "" {
				if req.OrderedHeaders != nil {
					if req.OrderedHeaders.Get("Referer") == "" || req.OrderedHeaders.Get("referer") == "" {
						req.OrderedHeaders.Set("Referer", ref)
					}
				} else {
					if req.Header == nil {
						req.Header = make(http.Header)
						if req.Header.Get("Referer") == "" || req.Header.Get("referer") == "" {
							req.Header.Set("Referer", ref)
						}
					}
				}
			}

			err = s.checkRedirect(req, reqs)
			if errors.Is(err, ErrUseLastResponse) || errors.Is(err, http.ErrUseLastResponse) {
				return resp, nil
			}

			const maxBodySlurpSize = 2 << 10
			if resp.ContentLength == -1 || resp.ContentLength <= maxBodySlurpSize {
				_, _ = io.CopyN(io.Discard, resp.RawBody, maxBodySlurpSize)
			}

			_ = resp.RawBody.Close()

			if err != nil {
				return nil, err
			}

			if includeBody && ireq.Body != nil {
				req.Body = ireq.Body
				req.ContentLength = ireq.ContentLength
				req.OrderedHeaders.Set("Content-Length", strconv.Itoa(int(req.ContentLength)))
			} else {
				req.ContentLength = 0
				req.OrderedHeaders.Del("Content-Length")
				req.OrderedHeaders.Del("Content-Type")
			}

			if s.PreHookWithContext != nil {
				if err = s.PreHookWithContext(&Context{
					Session: s,
					Request: req,
				}); err != nil {
					return nil, err
				}
			}

			if s.PreHook != nil {
				if err = s.PreHook(req); err != nil {
					return nil, err
				}
			}

			s.fillEmptyValues(req)
		}

		reqs = append(reqs, req)

		req.startTime = time.Now()

		if resp, err = s.send(req); err != nil {
			return nil, err
		}

		req.Response = resp

		var shouldRedirect bool

		redirectMethod, shouldRedirect, includeBody = RedirectBehavior(req.Method, resp, reqs[0])
		if !shouldRedirect {
			return resp, nil
		}

		if redirectMethod == http.MethodGet {
			req.Body = nil
			req.ContentLength = 0
			req.OrderedHeaders.Del("Content-Length")
			req.OrderedHeaders.Del("Content-Type")
			req.Header.Del("Content-Length")
			req.Header.Del("Content-Type")
		}

		req.CloseBody()
	}
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
	req := &Request{
		Method: http.MethodConnect,
		Url:    u,
	}

	_, err := s.do(req)
	return err
}

func (c *Context) Context() context.Context {
	return c.ctx
}

// Close closes the session and all its connections.
// It is recommended to call this function when the session is no longer needed.
//
// After calling this function, the session is no longer usable.
func (s *Session) Close() {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()

	s.ClearProxy()

	// Close HTTP/3 transport properly
	if s.HTTP3Config != nil && s.HTTP3Config.transport != nil {
		// First close idle connections
		s.HTTP3Config.transport.CloseIdleConnections()

		// Then close the transport completely
		_ = s.HTTP3Config.transport.Close()

		// Clear the transport reference
		s.HTTP3Config.transport = nil
		s.HTTP3Config = nil
	}

	// Close HTTP/2 transport
	if s.HTTP2Transport != nil {
		s.HTTP2Transport.CloseIdleConnections()
		s.HTTP2Transport = nil
	}

	// Close HTTP/1 transport
	if s.Transport != nil {
		s.Transport.CloseIdleConnections()
		s.Transport = nil
	}

	s.dumpIgnore = nil
	s.loggingIgnore = nil
	s.CookieJar = nil
	s.ctx = nil

	// Don't set s.mu = nil as it may cause race conditions
}

func (s *Session) setupFinalizer() {
	runtime.SetFinalizer(s, (*Session).finalize)
}

func (s *Session) finalize() {
	if !s.closed {
		s.Close()
	}
}
