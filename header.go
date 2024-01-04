package azuretls

import (
	http "github.com/Noooste/fhttp"
	"net/url"
	"sort"
	"strings"
)

// OrderedHeaders is a slice of headers.
type OrderedHeaders [][]string

type PHeader [4]string

type HeaderOrder []string

func (ph PHeader) GetDefault() {
	ph[0] = Method
	ph[1] = Authority
	ph[2] = Scheme
	ph[3] = Path
}

// Clone returns a copy of the header.
func (oh *OrderedHeaders) Clone() OrderedHeaders {
	var clone = make(OrderedHeaders, 0, len(*oh))

	for _, header := range *oh {
		var fieldClone = make([]string, 0, len(header))
		for _, field := range header {
			fieldClone = append(fieldClone, field)
		}
		clone = append(clone, fieldClone)
	}

	return clone
}

// Add adds the value to the field.
// It appends to any existing values associated with the field.
func (oh *OrderedHeaders) Add(field string, value ...string) {
	for i, c := range *oh {
		if c[0] == field {
			(*oh)[i] = append((*oh)[i], value...)
		}
	}
}

// Set sets the field to the given value.
// It replaces any existing values associated with the field.
func (oh *OrderedHeaders) Set(field string, value ...string) {
	newList := append([]string{field}, value...)
	for i, c := range *oh {
		if c[0] == field {
			(*oh)[i] = newList
			return
		}
	}
	*oh = append(*oh, newList)
}

// Get returns the first value associated with the given field.
// If the field is not present, it returns an empty string.
func (oh *OrderedHeaders) Get(field string) string {
	for _, c := range *oh {
		if c[0] == field {
			return strings.Join(c[1:], "; ")
		}
	}

	return ""
}

// Remove removes the first instance of the field from the header.
// If the field is not present, it does nothing.
// Deprecated: Use Del instead.
func (oh *OrderedHeaders) Remove(field string) OrderedHeaders {
	return oh.Del(field)
}

// Del removes the first instance of the field from the header.
// If the field is not present, it does nothing.
func (oh *OrderedHeaders) Del(field string) OrderedHeaders {
	var index = -1
	for i := 0; i < len(*oh); i++ {
		if (*oh)[i][0] == field {
			index = i
		}
	}

	if index != -1 {
		return append((*oh)[:index], (*oh)[index+1:]...)
	}

	return *oh
}

func (r *Request) formatHeader() {
	var setUserAgent = true

	if r.OrderedHeaders != nil && len(r.OrderedHeaders) > 0 {
		r.HttpRequest.Header = make(http.Header, len(r.OrderedHeaders)+2) // +2 for http.HeaderOrderKey and http.PHeaderOrderKey
		r.HttpRequest.Header[http.HeaderOrderKey] = make([]string, 0, len(r.OrderedHeaders))

		for _, el := range r.OrderedHeaders {
			if len(el) == 0 {
				continue
			}

			r.HttpRequest.Header[http.HeaderOrderKey] = append(r.HttpRequest.Header[http.HeaderOrderKey], el[0])
			if len(el) == 1 {
				// skip empty header value, the key indicates the order
				continue
			}

			if _, ok := r.HttpRequest.Header[el[0]]; !ok {
				if setUserAgent && strings.ToLower(el[0]) == "user-agent" {
					setUserAgent = false
				}

				r.HttpRequest.Header.Set(el[0], el[1])
			}

			for _, v := range el[2:] {
				r.HttpRequest.Header.Add(el[0], v)
			}
		}

	} else if r.Header != nil && len(r.Header) > 0 {
		r.HttpRequest.Header = r.Header
		if r.HeaderOrder != nil && len(r.HeaderOrder) > 0 {
			if v, ok := r.Header[http.HeaderOrderKey]; ok {
				r.Header[http.HeaderOrderKey] = append(v, r.HeaderOrder...)
			} else {
				r.Header[http.HeaderOrderKey] = r.HeaderOrder
			}
		}

		for k := range r.Header {
			if strings.ToLower(k) == "user-agent" {
				setUserAgent = false
				break
			}
		}
	}

	if setUserAgent {
		if r.ua == "" {
			r.ua = defaultUserAgent
		}

		r.HttpRequest.Header.Set("User-Agent", r.ua)
	}

	if r.PHeader[0] != "" {
		for i, el := range r.PHeader {
			if el[0] != ':' {
				r.PHeader[i] = ":" + el
			}
		}
		r.HttpRequest.Header[http.PHeaderOrderKey] = r.PHeader[:]
	} else {
		switch r.browser {
		case Firefox:
			r.HttpRequest.Header[http.PHeaderOrderKey] = []string{Method, Path, Authority, Scheme}
		case Ios:
			r.HttpRequest.Header[http.PHeaderOrderKey] = []string{Method, Scheme, Path, Authority}
		default: //chrome sub products
			r.HttpRequest.Header[http.PHeaderOrderKey] = []string{Method, Authority, Scheme, Path}
		}
	}

	if r.Body == nil && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
		r.HttpRequest.Header.Del("Content-Length")
		r.HttpRequest.Header.Del("Content-Type")
		delete(r.HttpRequest.Header, "content-length")
		delete(r.HttpRequest.Header, "content-type")
	}
}

// makeHeadersCopier makes a function that copies headers from the
// initial Request, ireq. For every redirect, this function must be called
// so that it can copy headers into the upcoming Request.
func (s *Session) makeHeadersCopier(ireq *Request) func(*Request) {
	// The headers to copy are from the very initial request.
	// We use a closured callback to keep a reference to these original headers.
	var (
		ireqhdr  = ireq.Header.Clone()
		icookies map[string][]*http.Cookie
	)

	if s.CookieJar != nil && ireq.Header.Get("Cookie") != "" {
		icookies = make(map[string][]*http.Cookie)
		for _, c := range ireq.HttpRequest.Cookies() {
			icookies[c.Name] = append(icookies[c.Name], c)
		}
	}

	preq := ireq // The previous request
	return func(req *Request) {
		// If Jar is present and there was some initial cookies provided
		// via the request header, then we may need to alter the initial
		// cookies as we follow redirects since each redirect may end up
		// modifying a pre-existing cookie.
		//
		// Since cookies already set in the request header do not contain
		// information about the original domain and path, the logic below
		// assumes any new set cookies override the original cookie
		// regardless of domain or path.
		//
		// See https://golang.org/issue/17494
		if s.CookieJar != nil && icookies != nil {
			var changed bool
			for k := range req.Response.Cookies {
				if _, ok := icookies[k]; ok {
					delete(icookies, k)
					changed = true
				}
			}
			if changed {
				ireqhdr.Del("Cookie")
				var ss []string
				for _, cs := range icookies {
					for _, c := range cs {
						ss = append(ss, c.Name+"="+c.Value)
					}
				}
				sort.Strings(ss) // Ensure deterministic headers
				ireqhdr.Set("Cookie", strings.Join(ss, "; "))
			}
		}

		// Copy the initial request's Header Values
		// (at least the safe ones).
		for k, vv := range ireqhdr {
			if shouldCopyHeaderOnRedirect(k, preq.parsedUrl, req.parsedUrl) {
				req.Header[k] = vv
			}
		}

		preq = req // Update previous Request with the current request
	}
}

func shouldCopyHeaderOnRedirect(headerKey string, initial, dest *url.URL) bool {
	switch http.CanonicalHeaderKey(headerKey) {
	case "Authorization", "Www-Authenticate", "Cookie", "Cookie2":
		// Permit sending auth/cookie headers from "foo.com"
		// to "sub.foo.com".

		// Note that we don't send all cookies to subdomains
		// automatically. This function is only used for
		// Cookies set explicitly on the initial outgoing
		// client request. Cookies automatically added via the
		// CookieJar mechanism continue to follow each
		// cookie's scope as set by Set-Cookie. But for
		// outgoing requests with the Cookie header set
		// directly, we don't know their scope, so we assume
		// it's for *.domain.com.

		ihost := getHost(initial)
		dhost := getHost(dest)
		return isDomainOrSubdomain(dhost, ihost)
	}
	// All other headers are copied:
	return true
}
