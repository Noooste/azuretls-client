package azuretls

import (
	"errors"
	http "github.com/Noooste/fhttp"
	"net/url"
	"strings"
)

var ErrTooManyRedirects = errors.New("too many redirects")

// RefererForURL returns a referer without any authentication info or
// an empty string if lastReq scheme is https and newReq scheme is http.
func RefererForURL(ireq, newReq *url.URL) string {
	// https://tools.ietf.org/html/rfc7231#section-5.5.2
	//   "Clients SHOULD NOT include a Referer header field in a
	//    (non-secure) HTTP request if the referring page was
	//    transferred with a secure protocol."
	if ireq.Scheme == "https" && newReq.Scheme == "http" {
		return ""
	}
	referer := ireq.String()
	if ireq.User != nil {
		// This is not very efficient, but is the best we can
		// do without:
		// - introducing a new method on URL
		// - creating a race condition
		// - copying the URL struct manually, which would cause
		//   maintenance problems down the line
		auth := ireq.User.String() + "@"
		referer = strings.Replace(referer, auth, "", 1)
	}
	return referer
}

// RedirectBehavior describes what should happen when the
// client encounters a 3xx status code from the server
func RedirectBehavior(reqMethod string, resp *Response, ireq *Request) (redirectMethod string, shouldRedirect, includeBody bool) {
	switch resp.StatusCode {
	case 301, 302, 303:
		redirectMethod = reqMethod
		shouldRedirect = true
		includeBody = false

		// RFC 2616 allowed automatic redirection only with GET and
		// HEAD requests. RFC 7231 lifts this restriction, but we still
		// restrict other methods to GET to maintain compatibility.
		if reqMethod != http.MethodGet && reqMethod != http.MethodHead {
			redirectMethod = http.MethodGet
		}

	case 307, 308:
		redirectMethod = reqMethod
		shouldRedirect = true
		includeBody = true

		// Treat 307 and 308 specially, since they're new in
		// Go 1.8, and they also require re-sending the request body.
		if resp.Header.Get("Location") == "" {
			// 308s have been observed in the wild being served
			// without Location headers. Since Go 1.7 and earlier
			// didn't follow these codes, just stop here instead
			// of returning an error.
			shouldRedirect = false
			break
		}

		if ireq.Body == nil && ireq.ContentLength != 0 {
			shouldRedirect = false
		}
	}

	return redirectMethod, shouldRedirect, includeBody
}

func defaultCheckRedirect(req *Request, via []*Request) error {
	if uint(len(via)) >= req.MaxRedirects {
		return ErrTooManyRedirects
	}
	return nil
}

func (s *Session) checkRedirect(req *Request, via []*Request) error {
	fn := s.CheckRedirect
	if fn == nil {
		fn = defaultCheckRedirect
	}
	return fn(req, via)
}
