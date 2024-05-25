package azuretls

import (
	http "github.com/Noooste/fhttp"
	"net/url"
	"strings"
)

// OrderedHeaders is a slice of headers.
type OrderedHeaders [][]string

// PHeader is a slice of pseudo headers.
type PHeader []string

// HeaderOrder is a slice of header names.
type HeaderOrder []string

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

//gocyclo:ignore
func (r *Request) formatHeader() {
	var setUserAgent = true

	if r.OrderedHeaders != nil && len(r.OrderedHeaders) > 0 {
		r.HttpRequest.Header = make(http.Header, len(r.OrderedHeaders)+2) // +2 for http.HeaderOrderKey and http.PHeaderOrderKey
		r.HttpRequest.Header[http.HeaderOrderKey] = make([]string, 0, len(r.OrderedHeaders))

		for _, el := range r.OrderedHeaders {
			if len(el) == 0 || !shouldCopyHeaderOnRedirect(el[0], r.HttpRequest.URL, r.HttpRequest.URL) {
				continue
			}

			var key = strings.ToLower(el[0])

			r.HttpRequest.Header[http.HeaderOrderKey] = append(r.HttpRequest.Header[http.HeaderOrderKey], key)

			if len(el) == 1 {
				// skip empty header value, the key indicates the order
				continue
			}

			if _, ok := r.HttpRequest.Header[key]; !ok {
				if setUserAgent && http.CanonicalHeaderKey(key) == "User-Agent" {
					setUserAgent = false
				}

				r.HttpRequest.Header.Set(key, el[1])
			}

			for _, v := range el[2:] {
				r.HttpRequest.Header.Add(key, v)
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
			if http.CanonicalHeaderKey(k) == "User-Agent" {
				setUserAgent = false
				break
			}
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
			r.HttpRequest.Header[http.PHeaderOrderKey] = []string{Method, Scheme, Path, Authority}
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
