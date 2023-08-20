package azuretls

import (
	"bytes"
	"context"
	"encoding/json"
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
		case time.Duration:
			request.TimeOut = arg.(time.Duration)
		}
	}

	s.fillEmptyValues(request)

	if s.PreHook != nil {
		return s.PreHook(request)
	}

	return nil
}

func (s *Session) fillEmptyValues(request *Request) {
	if request.Browser == "" {
		request.Browser = s.Browser
	}

	if request.OrderedHeaders == nil {
		if s.OrderedHeaders != nil && len(s.OrderedHeaders) > 0 {
			request.OrderedHeaders = s.OrderedHeaders.Clone()
		}
	}

	if request.Proxy == "" {
		request.Proxy = s.Proxy
	}

	if request.TimeOut == 0 {
		request.TimeOut = s.TimeOut
	}

	request.InsecureSkipVerify = s.InsecureSkipVerify
}

func (s *Session) buildRequest(ctx context.Context, req *Request) (newReq *http.Request, err error) {
	newReq, err = newRequest(ctx, s.Verbose || s.VerboseFunc != nil, req)

	if !req.NoCookie {
		cookies := s.CookieJar.Cookies(newReq.URL)
		if cookies != nil && len(cookies) > 0 && newReq.Header.Get("Cookie") == "" {
			newReq.Header.Set("Cookie", cookiesToString(cookies))
		}
	} else {
		newReq.Header.Del("Cookie")
	}

	if req.PHeader[0] == "" {
		req.PHeader = s.PHeader
	}

	s.formatHeader(req, newReq)

	return newReq, nil
}

func newRequest(ctx context.Context, verbose bool, req *Request) (newReq *http.Request, err error) {
	if req.Body != nil {
		if verbose {
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
				default:
					var dumped []byte
					dumped, err = json.Marshal(req.Body)
					if err != nil {
						return nil, err
					}
					reader = bytes.NewReader(dumped)
				}
			}

			newReq, err = http.NewRequestWithContext(ctx, strings.ToUpper(req.Method), req.Url, reader)
		}
	} else {
		newReq, err = http.NewRequestWithContext(ctx, strings.ToUpper(req.Method), req.Url, nil)
	}

	return
}

func (s *Session) formatHeader(req *Request, httpReq *http.Request) {
	httpReq.Header = make(http.Header, len(req.OrderedHeaders)+2)
	httpReq.Header[http.HeaderOrderKey] = make([]string, 0, len(req.OrderedHeaders))

	var setUserAgent = true
	for _, el := range req.OrderedHeaders {
		var startIndex = 1
		if _, ok := httpReq.Header[el[0]]; !ok {
			if setUserAgent && strings.ToLower(el[0]) == "user-agent" {
				setUserAgent = false
			}
			httpReq.Header.Set(el[0], el[1])
			httpReq.Header[http.HeaderOrderKey] = append(httpReq.Header[http.HeaderOrderKey], el[0])
			startIndex = 2
		}
		for _, v := range el[startIndex:] {
			httpReq.Header.Add(el[0], v)
		}
	}

	if setUserAgent && s.UserAgent != "" {
		httpReq.Header.Set("User-Agent", s.UserAgent)
		httpReq.Header[http.HeaderOrderKey] = append(httpReq.Header[http.HeaderOrderKey], "User-Agent")
	}

	if req.PHeader[0] != "" {
		for i, el := range req.PHeader {
			if el[0] != ':' {
				req.PHeader[i] = ":" + el
			}
		}
		httpReq.Header[http.PHeaderOrderKey] = req.PHeader[:]
	} else {
		switch req.Browser {
		case Firefox:
			httpReq.Header[http.PHeaderOrderKey] = []string{Method, Path, Authority, Scheme}
		case Ios:
			httpReq.Header[http.PHeaderOrderKey] = []string{Method, Scheme, Path, Authority}
		default: //chrome sub products
			httpReq.Header[http.PHeaderOrderKey] = []string{Method, Authority, Scheme, Path}
		}
	}

	if httpReq.Method == http.MethodGet {
		httpReq.Header.Del("Content-Length")
		httpReq.Header.Del("Content-Type")
	}
}

func (r *Request) SetContext(ctx context.Context) {
	r.ctx = ctx
}
