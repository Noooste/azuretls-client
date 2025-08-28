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
		wg      sync.WaitGroup
		headers = make(http.Header, len(httpResponse.Header))
		body    []byte
	)

	if !response.IgnoreBody {
		wg.Add(1)

		go func() {
			defer wg.Done()

			var readErr error
			body, readErr = response.ReadBody(httpResponse.Body)

			if readErr != nil {
				err = readErr
				return
			}
		}()
	}

	for key, value := range httpResponse.Header {
		headers[key] = value
	}

	response.StatusCode = httpResponse.StatusCode
	response.Status = httpResponse.Status

	response.Header = headers

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

	if err != nil {
		return err
	}

	response.Body = body

	return
}

func (r *Response) ReadBody(in io.ReadCloser) (out []byte, err error) {
	defer func() {
		_ = in.Close()
	}()

	if r.Session.DisableAutoDecompression {
		return io.ReadAll(in)
	}

	ce := r.Header.Get("Content-Encoding")

	return DecodeResponseBody(in, ce)
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
