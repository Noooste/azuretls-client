package azuretls

import (
	"encoding/json"
	"fmt"
	http "github.com/Noooste/fhttp"
	"io"
	"net/url"
	"sync"
)

func (s *Session) buildResponse(response *Response, httpResponse *http.Response) (err error) {
	response.RawBody = httpResponse.Body
	response.HttpResponse = httpResponse
	response.Session = s

	var (
		wg      sync.WaitGroup
		headers = make(http.Header, len(httpResponse.Header))
	)

	if !response.IgnoreBody {
		wg.Add(1)

		go func() {
			defer wg.Done()

			if readBody, readErr := response.ReadBody(); readErr == nil {
				response.Body = readBody
			} else {
				err = readErr
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

	cookies := ReadSetCookies(httpResponse.Header)
	s.CookieJar.SetCookies(u, cookies)
	response.Cookies = GetCookiesMap(cookies)
	response.ContentLength = httpResponse.ContentLength

	wg.Wait()

	return
}

func (r *Response) ReadBody() (body []byte, err error) {
	defer func() {
		_ = r.HttpResponse.Body.Close()
	}()
	return io.ReadAll(r.HttpResponse.Body)
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
