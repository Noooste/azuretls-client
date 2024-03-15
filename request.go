package azuretls

import (
	"bytes"
	"context"
	"errors"
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
		switch arg.(type) {
		case OrderedHeaders:
			oh := arg.(OrderedHeaders)
			request.OrderedHeaders = oh.Clone()
		case PHeader:
			request.PHeader = arg.(PHeader)
		case http.Header:
			request.Header = arg.(http.Header)
		case HeaderOrder:
			request.HeaderOrder = arg.(HeaderOrder)
		case time.Duration:
			request.TimeOut = arg.(time.Duration)
		default:
			if request.Body != nil {
				return errors.New("ambiguous argument, multiple body detected")
			}

			request.Body = arg
		}
	}

	s.fillEmptyValues(request)

	if s.PreHook != nil {
		return s.PreHook(request)
	}

	if s.PreHookWithContext != nil {
		return s.PreHookWithContext(&Context{
			Session: s,
			Request: request,
		})
	}

	return nil
}

func (s *Session) fillEmptyValues(request *Request) {
	if request.OrderedHeaders == nil {
		if s.OrderedHeaders != nil && len(s.OrderedHeaders) > 0 {
			request.OrderedHeaders = s.OrderedHeaders.Clone()
		} else if s.Header != nil && len(s.Header) > 0 {
			request.Header = s.Header.Clone()
			request.HeaderOrder = s.HeaderOrder
		} else {
			request.OrderedHeaders = make(OrderedHeaders, 0)
		}
	}

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

	request.InsecureSkipVerify = s.InsecureSkipVerify
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

			if reader, err = toReader(req.Body); err != nil {
				return nil, err
			}

			newReq, err = http.NewRequestWithContext(ctx, strings.ToUpper(req.Method), req.Url, reader)
		}
	} else {
		newReq, err = http.NewRequestWithContext(ctx, strings.ToUpper(req.Method), req.Url, nil)
	}

	return
}

func (r *Request) SetContext(ctx context.Context) {
	r.ctx = ctx
}
