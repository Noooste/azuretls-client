package azuretls

import (
	"bytes"
	"context"
	"encoding/json"
	http "github.com/Noooste/fhttp"
	"math/rand"
	"strings"
	"time"
)

func (s *Session) buildRequest(ctx context.Context, req *Request) (*http.Request, error) {
	var newReq *http.Request
	var err error

	//prepare new request
	switch req.Body {
	case nil:
		newReq, err = http.NewRequestWithContext(ctx, strings.ToUpper(req.Method), req.Url, nil)
	default:
		newReq, err = http.NewRequestWithContext(ctx, strings.ToUpper(req.Method), req.Url, bytes.NewBuffer(req.Body))
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

	if s.PHeader[0] != "" {
		newReq.Header[http.PHeaderOrderKey] = s.PHeader[:]
	} else {
		var order []string

		if req.PHeader[0] != "" {
			order = make([]string, 4)
			for i, el := range req.PHeader {
				if el[0] != ':' {
					el = ":" + el
				}
				order[i] = el
			}

		} else {
			switch req.Browser {
			case Firefox:
				order = []string{Method, Path, Authority, Scheme}
			case Ios:
				order = []string{Method, Scheme, Path, Authority}
			default: //chrome sub products
				order = []string{Method, Authority, Scheme, Path}
			}
		}

		newReq.Header[http.PHeaderOrderKey] = order
	}

	if newReq.Method == http.MethodGet {
		newReq.Header.Del("Content-Length")
		newReq.Header.Del("Content-Type")
	}

	return newReq, nil
}

func (r *Response) toString() string {
	returnElement, _ := json.Marshal(r)
	return string(returnElement)
}

func getRandomId() uint64 {
	rand.Seed(time.Now().UnixNano())
	return rand.Uint64()
}

func formatProxy(proxy string) string {
	var split = strings.Split(strings.Trim(proxy, "\n\r"), ":")
	if len(split) == 4 {
		return "http://" + split[2] + ":" + split[3] + "@" + split[0] + ":" + split[1]
	} else if len(split) == 2 {
		return "http://" + split[0] + ":" + split[1]
	}
	return proxy
}
