package azuretls

import (
	"bytes"
	"context"
	"fmt"
	http "github.com/Noooste/fhttp"
	"io"
	"strings"
	"time"
)

func (r *Request) CloseBody() {
	if r.HttpRequest.Body != nil {
		_ = r.HttpRequest.Body.Close()
	}
}

func (s *Session) prepareRequest(request *Request, args ...any) error {
	for _, arg := range args {
		switch i := arg.(type) {
		case OrderedHeaders:
			request.OrderedHeaders = i.Clone()
		case PHeader:
			request.PHeader = i
		case http.Header:
			request.Header = i
		case HeaderOrder:
			request.HeaderOrder = i
		case time.Duration:
			request.TimeOut = i
		case context.Context:
			request.ctx = i
		default:
			if request.Body != nil {
				return fmt.Errorf("ambiguous argument, multiple body detected, what do you mean by this: %T", arg)
			}
			request.Body = arg
		}
	}

	s.fillEmptyValues(request)

	if s.PreHookWithContext != nil {
		return s.PreHookWithContext(&Context{
			Session: s,
			Request: request,
		})
	}

	if s.PreHook != nil {
		return s.PreHook(request)
	}

	return nil
}

func (s *Session) fillHeaders(request *Request) {
	if request.OrderedHeaders == nil {
		if s.OrderedHeaders != nil && len(s.OrderedHeaders) > 0 {
			request.OrderedHeaders = s.OrderedHeaders.Clone()
			return
		}

		if request.Header == nil {
			if s.Header != nil {
				request.Header = s.Header.Clone()
			} else {
				request.Header = make(http.Header)
			}
		}

		if request.HeaderOrder == nil {
			if s.HeaderOrder != nil && len(s.HeaderOrder) > 0 {
				request.HeaderOrder = make(HeaderOrder, len(s.HeaderOrder))
				copy(request.HeaderOrder, s.HeaderOrder)
			} else {
				request.HeaderOrder = make(HeaderOrder, 0)
			}
		}
	}
}

func (s *Session) fillEmptyValues(request *Request) {
	s.fillHeaders(request)

	if request.TimeOut == 0 {
		request.TimeOut = s.TimeOut
	}

	if request.Method == "" {
		request.Method = http.MethodGet
	}

	if request.MaxRedirects == 0 {
		if s.MaxRedirects == 0 {
			s.MaxRedirects = 10
		}
		request.MaxRedirects = s.MaxRedirects
	}

	if !request.InsecureSkipVerify {
		request.InsecureSkipVerify = s.InsecureSkipVerify
	}
}

func (s *Session) buildRequest(ctx context.Context, req *Request) (err error) {
	req.HttpRequest, err = newRequest(ctx, s.Verbose || s.VerboseFunc != nil, req)

	req.browser = s.Browser
	req.ua = s.UserAgent

	if err != nil {
		return
	}

	if req.PHeader == nil {
		req.PHeader = s.PHeader
	}

	req.formatHeader()

	if !req.NoCookie {
		cookies := s.CookieJar.Cookies(req.HttpRequest.URL)
		if cookies != nil && len(cookies) > 0 {
			if c := req.HttpRequest.Header.Get("Cookie"); c != "" {
				req.HttpRequest.Header.Set("Cookie", c+"; "+CookiesToString(cookies))
			} else {
				req.HttpRequest.Header.Set("Cookie", CookiesToString(cookies))
			}
		}
	}
	return
}

func newRequest(ctx context.Context, verbose bool, req *Request) (newReq *http.Request, err error) {
	if req.Body != nil {
		if verbose {
			req.body = ToBytes(req.Body)
			newReq, err = http.NewRequestWithContext(ctx, strings.ToUpper(req.Method), req.Url, bytes.NewReader(req.body))
		} else {
			var reader io.Reader

			if reader, err = ToReader(req.Body); err != nil {
				return nil, err
			}

			newReq, err = http.NewRequestWithContext(ctx, strings.ToUpper(req.Method), req.Url, reader)
		}
	} else {
		newReq, err = http.NewRequestWithContext(ctx, strings.ToUpper(req.Method), req.Url, nil)
	}

	return
}

// SetContext sets the context for the request.
func (r *Request) SetContext(ctx context.Context) {
	r.ctx = ctx
}

// Context returns the context for the request.
func (r *Request) Context() context.Context {
	return r.ctx
}
