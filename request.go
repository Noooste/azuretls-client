package azuretls

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	http "github.com/Noooste/fhttp"
	"io"
	"reflect"
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
		}
	}

	s.fillEmptyValues(request)

	if s.PreHook != nil {
		return s.PreHook(request)
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

	request.InsecureSkipVerify = s.InsecureSkipVerify
}

func (s *Session) buildRequest(ctx context.Context, req *Request) (err error) {
	req.HttpRequest, err = newRequest(ctx, s.Verbose || s.VerboseFunc != nil, req)

	req.browser = s.Browser
	req.ua = s.UserAgent

	if err != nil {
		return
	}

	if req.PHeader[0] == "" {
		req.PHeader = s.PHeader
	}

	req.formatHeader()

	if !req.NoCookie {
		cookies := s.CookieJar.Cookies(req.HttpRequest.URL)
		if cookies != nil && len(cookies) > 0 {
			if c := req.HttpRequest.Header.Get("Cookie"); c != "" {
				req.HttpRequest.Header.Set("Cookie", c+"; "+cookiesToString(cookies))
			} else {
				req.HttpRequest.Header.Set("Cookie", cookiesToString(cookies))
			}
		}
	}
	return
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
					value := reflect.ValueOf(req.Body)

					if value.Kind() == reflect.Ptr {
						value = value.Elem()
					}

					switch value.Kind() {
					case reflect.Struct, reflect.Map, reflect.Slice, reflect.Array:
						var dumped []byte
						dumped, err = json.Marshal(req.Body)
						if err != nil {
							return nil, err
						}
						reader = bytes.NewReader(dumped)
					default:
						return nil, errors.New("unsupported body type : " + value.Kind().String())
					}
				}
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
