package azuretls

import (
	"encoding/json"
	"fmt"
	http "github.com/Noooste/fhttp"
	"io"
	"net/url"
	"sync"
	"time"
)

func (s *Session) buildResponse(response *Response, httpResponse *http.Response) (err error) {
	response.RawBody = httpResponse.Body
	response.HttpResponse = httpResponse

	var (
		wg      = sync.WaitGroup{}
		headers = make(http.Header, len(httpResponse.Header))
	)

	wg.Add(1)

	if !response.IgnoreBody {
		go func() {
			done := make(chan bool, 1)

			defer func() {
				recover()
				wg.Done()
				close(done)
			}()

			timer := time.NewTimer(response.Request.TimeOut)
			defer timer.Stop()

			go func() {
				defer func() {
					recover()
				}()

				response.Body, err = response.ReadBody()
				done <- true
			}()

			for {
				select {
				case <-timer.C:
					response.Body = nil
					err = fmt.Errorf("read body: timeout")
					return

				case <-done:
					return
				}
			}
		}()
	}

	for key, value := range httpResponse.Header {
		headers[key] = value
	}

	response.StatusCode = httpResponse.StatusCode
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

func (r *Response) ReadBody() ([]byte, error) {
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(r.HttpResponse.Body)

	encoding := r.HttpResponse.Header.Get("content-encoding")

	bodyBytes, err := io.ReadAll(r.HttpResponse.Body)

	if err != nil {
		return nil, err
	}

	result := DecompressBody(bodyBytes, encoding)
	if err != nil {
		return nil, err
	}

	return result, nil
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
