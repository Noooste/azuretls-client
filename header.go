package azuretls

import (
	http "github.com/Noooste/fhttp"
	"net/url"
	"sort"
	"strings"
)

// OrderedHeaders is a slice of headers.
type OrderedHeaders [][]string

// PHeader is a slice of pseudo headers.
type PHeader []string

// HeaderOrder is a slice of header names.
type HeaderOrder []string

const SensitiveHeaders = "Sensitive-Headers:"

var defaultSensitiveHeaders = []string{
	"Authorization",
	"Cookie", "Cookie2", "Set-Cookie", "Set-Cookie2",
}

// GetDefaultPseudoHeaders returns the default pseudo headers.
func GetDefaultPseudoHeaders() PHeader {
	return []string{Method, Authority, Scheme, Path}
}

// Clone returns a copy of the header.
func (oh *OrderedHeaders) Clone() OrderedHeaders {
	if oh == nil {
		return nil
	}

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
	field = http.CanonicalHeaderKey(field)
	for i, c := range *oh {
		if http.CanonicalHeaderKey(c[0]) == field {
			(*oh)[i] = append((*oh)[i], value...)
		}
	}
}

// Set sets the field to the given value.
// It replaces any existing values associated with the field.
func (oh *OrderedHeaders) Set(field string, value ...string) {
	field = http.CanonicalHeaderKey(field)
	newList := append([]string{field}, value...)
	for i, c := range *oh {
		if http.CanonicalHeaderKey(c[0]) == field {
			(*oh)[i] = newList
			return
		}
	}
	*oh = append(*oh, newList)
}

// Get returns the first value associated with the given field.
// If the field is not present, it returns an empty string.
func (oh *OrderedHeaders) Get(field string) string {
	field = http.CanonicalHeaderKey(field)
	for _, c := range *oh {
		if http.CanonicalHeaderKey(c[0]) == field {
			return strings.Join(c[1:], "; ")
		}
	}

	return ""
}

// Remove removes the first instance of the field from the header.
// If the field is not present, it does nothing.
// Deprecated: Use Del instead.
func (oh *OrderedHeaders) Remove(field string) OrderedHeaders {
	return oh.Del(http.CanonicalHeaderKey(field))
}

// Del removes the first instance of the field from the header.
// If the field is not present, it does nothing.
func (oh *OrderedHeaders) Del(field string) OrderedHeaders {
	var index = -1
	field = http.CanonicalHeaderKey(field)
	for i := 0; i < len(*oh); i++ {
		if http.CanonicalHeaderKey((*oh)[i][0]) == field {
			index = i
		}
	}

	if index != -1 {
		return append((*oh)[:index], (*oh)[index+1:]...)
	}

	return *oh
}

func (oh *OrderedHeaders) ToHeader() http.Header {
	var result = make(http.Header, len(*oh))
	var order = make([]string, 0, len(*oh))

	for _, header := range *oh {
		if len(header) == 0 {
			continue
		}

		var key = http.CanonicalHeaderKey(header[0])

		if result.Get(key) != "" {
			for _, v := range header[1:] {
				result.Add(key, v)
			}
		} else {
			order = append(order, key)
			if len(header) == 1 {
				continue
			}
			result.Set(key, header[1])
			for _, v := range header[2:] {
				result.Add(key, v)
			}
		}
	}

	return result
}

//gocyclo:ignore
func (r *Request) formatHeader() {
	var (
		setUserAgent        = true
		setSensitiveHeaders = true
	)

	if r.OrderedHeaders != nil && len(r.OrderedHeaders) > 0 {
		r.HttpRequest.Header = make(http.Header, len(r.OrderedHeaders)+2) // +2 for http.HeaderOrderKey and http.PHeaderOrderKey
		r.HttpRequest.Header[http.HeaderOrderKey] = make([]string, 0, len(r.OrderedHeaders))

		for _, el := range r.OrderedHeaders {
			if len(el) == 0 {
				continue
			}
			r.HttpRequest.Header[http.HeaderOrderKey] = append(r.HttpRequest.Header[http.HeaderOrderKey], strings.ToLower(el[0]))
		}

		for _, el := range r.OrderedHeaders {
			if len(el) == 0 || !shouldCopyHeaderOnRedirect(el[0], r.HttpRequest.URL, r.HttpRequest.URL) {
				continue
			}

			var key = el[0]

			if key == SensitiveHeaders {
				if len(el) > 1 {
					r.HttpRequest.SensitiveHeaders = el[1:]
					setSensitiveHeaders = false
				}
				continue
			}

			if strings.ToLower(key) == "content-length" {
				continue
			}

			if len(el) == 1 {
				// skip empty header value, the key indicates the order
				continue
			}

			if v := r.HttpRequest.Header.Get(key); v == "" {
				if setUserAgent && strings.ToLower(key) == "user-agent" {
					setUserAgent = false
				}
			}

			r.HttpRequest.Header.Add(key, el[1])

			for _, v := range el[2:] {
				r.HttpRequest.Header.Add(key, v)
			}
		}

	} else if r.Header != nil && len(r.Header) > 0 {
		r.HttpRequest.Header = r.Header.Clone()
		if r.HeaderOrder != nil && len(r.HeaderOrder) > 0 {
			if v, ok := r.Header[http.HeaderOrderKey]; ok {
				r.HttpRequest.Header[http.HeaderOrderKey] = append(v, r.HeaderOrder...)
			} else {
				r.HttpRequest.Header[http.HeaderOrderKey] = r.HeaderOrder
			}
		}

		for k := range r.Header {
			if http.CanonicalHeaderKey(k) == "User-Agent" {
				setUserAgent = false
				break
			}
		}

		if v := r.HttpRequest.Header[SensitiveHeaders]; v != nil {
			r.HttpRequest.SensitiveHeaders = v
			delete(r.HttpRequest.Header, SensitiveHeaders)
			setSensitiveHeaders = false
		}
	} else {
		r.HttpRequest.Header = make(http.Header, 4)
	}

	if setUserAgent {
		if r.ua == "" {
			r.ua = defaultUserAgent
		}

		r.HttpRequest.Header.Set("User-Agent", r.ua)
	}

	if setSensitiveHeaders {
		r.HttpRequest.SensitiveHeaders = defaultSensitiveHeaders
	}

	if r.ForceHTTP1 {
		return
	}

	if r.PHeader != nil {
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
			r.HttpRequest.Header[http.PHeaderOrderKey] = []string{Method, Scheme, Authority, Path}
		case Safari:
			r.HttpRequest.Header[http.PHeaderOrderKey] = []string{Method, Scheme, Authority, Path}
		default: //chrome sub products
			r.HttpRequest.Header[http.PHeaderOrderKey] = GetDefaultPseudoHeaders()
		}
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

// makeHeadersCopier makes a function that copies headers from the
// initial Request, ireq. For every redirect, this function must be called
// so that it can copy headers into the upcoming Request.
func (s *Session) makeHeadersCopier(ireq *Request) func(*Request) {
	// The headers to copy are from the very initial request.
	// We use a closured callback to keep a reference to these original headers.
	var (
		ireqhdr  = ireq.Header
		icookies map[string][]*http.Cookie
	)

	var header = ireq.Header

	if ireq.OrderedHeaders != nil {
		header = ireq.OrderedHeaders.ToHeader()
	}

	if s.CookieJar != nil && header.Get("Cookie") != "" {
		icookies = make(map[string][]*http.Cookie)
		for _, c := range http.ReadCookies(ireq.Header, "") {
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
			resp := req.Response // The response that caused the upcoming redirect
			for k := range resp.Cookies {
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
				if req.OrderedHeaders != nil {
					req.OrderedHeaders.Add(k, vv...)
				} else {
					if req.Header == nil {
						req.Header = make(http.Header)
					}

					req.Header[k] = vv
				}
			}
		}

		preq = req // Update previous Request with the current request
	}
}
