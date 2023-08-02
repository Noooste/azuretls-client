package azuretls

import (
	"bytes"
	"context"
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

	request.InsecureSkipVerify = s.InsecureSkipVerify

	if s.PreHook != nil {
		return s.PreHook(request)
	}

	return nil
}

func (s *Session) buildRequest(ctx context.Context, req *Request) (*http.Request, error) {
	var newReq *http.Request
	var err error

	if req.Body != nil {
		if s.Verbose {
			req.body = toBytes(req.Body)
			newReq, err = http.NewRequestWithContext(ctx, strings.ToUpper(req.Method), req.Url, bytes.NewReader(req.body))
		} else {
			//prepare new request
			var reader io.Reader
			if req.Body != nil {
				switch req.Body.(type) {
				case string:
					reader = strings.NewReader(req.Body.(string))
				case []byte:
					reader = bytes.NewReader(req.Body.([]byte))
				case io.Reader:
					reader = req.Body.(io.Reader)
				}
			}

			newReq, err = http.NewRequestWithContext(ctx, strings.ToUpper(req.Method), req.Url, reader)
		}
	} else {
		newReq, err = http.NewRequestWithContext(ctx, strings.ToUpper(req.Method), req.Url, nil)
	}

	if err != nil {
		return nil, err
	}

	if req.OrderedHeaders != nil && len(req.OrderedHeaders) > 0 {
		newReq.Header = make(http.Header)
		length := 0
		for i := range req.OrderedHeaders {
			if len(req.OrderedHeaders[i]) > 0 {
				length++
			}
		}
		newReq.Header[http.HeaderOrderKey] = make([]string, length)
		iter := 0
		for _, key := range req.OrderedHeaders {
			l := len(key)
			if l > 0 {
				newReq.Header[http.HeaderOrderKey][iter] = strings.ToLower(key[0])
				if l > 1 {
					newReq.Header[strings.ToLower(key[0])] = key[1:]
					iter++
				}
			}
		}
	} else {
		if req.Header != nil {
			newReq.Header = req.Header
			newReq.Header[http.HeaderOrderKey] = req.HeaderOrder
		}
	}

	if !req.NoCookie {
		cookies := s.CookieJar.Cookies(newReq.URL)
		if cookies != nil && len(cookies) > 0 && newReq.Header.Get("Cookie") == "" {
			newReq.Header.Set("Cookie", cookiesToString(cookies))
		}
	} else {
		newReq.Header.Del("Cookie")
	}

	if req.PHeader[0] != "" {
		for _, el := range req.PHeader {
			if el[0] != ':' {
				el = ":" + el
			}
		}
		newReq.Header[http.PHeaderOrderKey] = req.PHeader[:]
	} else if s.PHeader[0] != "" {
		newReq.Header[http.PHeaderOrderKey] = s.PHeader[:]
	} else {
		switch req.Browser {
		case Firefox:
			newReq.Header[http.PHeaderOrderKey] = []string{Method, Path, Authority, Scheme}
		case Ios:
			newReq.Header[http.PHeaderOrderKey] = []string{Method, Scheme, Path, Authority}
		default: //chrome sub products
			newReq.Header[http.PHeaderOrderKey] = []string{Method, Authority, Scheme, Path}
		}
	}

	if newReq.Method == http.MethodGet {
		newReq.Header.Del("Content-Length")
		newReq.Header.Del("Content-Type")
	}

	return newReq, nil
}

func (r *Request) SetContext(ctx context.Context) {
	r.ctx = ctx
}
