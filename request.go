package azuretls

import (
	"context"
	http "github.com/Noooste/fhttp"
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

		case http.Header:
			request.Header = arg.(http.Header).Clone()

		case PHeader:
			request.PHeader = arg.(PHeader)

		case HeaderOrder:
			request.HeaderOrder = arg.(HeaderOrder)

		case time.Duration:
			request.TimeOut = arg.(time.Duration)
		}
	}

	if request.Browser == "" {
		request.Browser = s.Browser
	}

	if request.Header == nil {
		if s.Headers != nil {
			request.Header = s.Headers.Clone()
		} else {
			request.Header = http.Header{}
		}
	}

	if request.HeaderOrder == nil {
		request.HeaderOrder = s.HeadersOrder
	}

	if request.OrderedHeaders == nil {
		if s.OrderedHeaders != nil && len(s.OrderedHeaders) > 0 {
			request.OrderedHeaders = s.OrderedHeaders.Clone()
		}
	}

	if request.Proxy == "" {
		request.Proxy = s.Proxy
	}

	if request.Browser == "" {
		request.Browser = s.Browser
	}

	if request.TimeOut == 0 {
		request.TimeOut = s.TimeOut
	}

	if request.TimeOut == 0 {
		request.TimeOut = 30 * time.Second
	}

	if s.PreHook != nil {
		return s.PreHook(request)
	}

	return nil
}

func (r *Request) SetContext(ctx context.Context) {
	r.ctx = ctx
}
