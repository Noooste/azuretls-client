package azuretls

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"sync"

	http "github.com/Noooste/fhttp"
)

func (s *Session) buildResponse(response *Response, httpResponse *http.Response) (err error) {
	response.RawBody = httpResponse.Body
	response.HttpResponse = httpResponse
	response.Session = s

	var (
		headers = make(http.Header, len(httpResponse.Header))
		body    []byte
	)

	for key, value := range httpResponse.Header {
		headers[key] = value
	}

	response.StatusCode = httpResponse.StatusCode
	response.Status = httpResponse.Status
	response.Header = headers

	encoding := httpResponse.Header.Get("Content-Encoding")

	if !response.IgnoreBody {
		contentLength := httpResponse.ContentLength

		// Use goroutine for large bodies or unknown size to overlap I/O with other processing
		if contentLength < 0 || contentLength > 65536 { // 64KB threshold
			var wg sync.WaitGroup
			var readErr error

			wg.Add(1)
			go func() {
				defer wg.Done()
				body, readErr = response.ReadBody(httpResponse.Body, encoding)
			}()

			// Process other response data while body reads
			var u *url.URL
			if response.Url == "" {
				response.Url = httpResponse.Request.URL.String()
				u = httpResponse.Request.URL
			} else {
				u, _ = url.Parse(response.Url)
			}

			if !response.Request.NoCookie {
				cookies := httpResponse.Cookies()
				s.CookieJar.SetCookies(u, cookies)
				response.Cookies = GetCookiesMap(cookies)
			}

			response.ContentLength = httpResponse.ContentLength

			wg.Wait()

			if readErr != nil {
				return readErr
			}
		} else {
			// Small body - read synchronously to avoid goroutine overhead
			body, err = response.ReadBody(httpResponse.Body, encoding)
			if err != nil {
				return err
			}

			var u *url.URL
			if response.Url == "" {
				response.Url = httpResponse.Request.URL.String()
				u = httpResponse.Request.URL
			} else {
				u, _ = url.Parse(response.Url)
			}

			if !response.Request.NoCookie {
				cookies := httpResponse.Cookies()
				s.CookieJar.SetCookies(u, cookies)
				response.Cookies = GetCookiesMap(cookies)
			}

			response.ContentLength = httpResponse.ContentLength
		}
	} else {
		// Handle case when body is ignored
		var u *url.URL
		if response.Url == "" {
			response.Url = httpResponse.Request.URL.String()
			u = httpResponse.Request.URL
		} else {
			u, _ = url.Parse(response.Url)
		}

		if !response.Request.NoCookie {
			cookies := httpResponse.Cookies()
			s.CookieJar.SetCookies(u, cookies)
			response.Cookies = GetCookiesMap(cookies)
		}

		response.ContentLength = httpResponse.ContentLength
	}

	response.Body = body
	return nil
}

func (r *Response) ReadBody(in io.ReadCloser, encoding string) (out []byte, err error) {
	defer func() {
		_ = in.Close()
	}()

	if r.Session.DisableAutoDecompression {
		return io.ReadAll(in)
	}

	return DecodeResponseBody(in, encoding)
}

func (r *Response) CloseBody() error {
	if r.RawBody != nil {
		return r.RawBody.Close()
	}

	return nil
}

func (r *Response) JSON(v any) error {
	if r.Body == nil {
		return fmt.Errorf("response body is nil")
	}

	return json.Unmarshal(r.Body, v)
}

func (r *Response) MustJSON(v any) {
	if err := r.JSON(v); err != nil {
		panic(err)
	}
}

func (r *Response) String() string {
	return string(r.Body)
}
