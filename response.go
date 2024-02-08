package azuretls

import (
	"encoding/json"
	"fmt"
	http "github.com/Noooste/fhttp"
	"io"
	"net/url"
	"time"
)

func (s *Session) buildResponse(response *Response, httpResponse *http.Response) (err error) {
	response.RawBody = httpResponse.Body
	response.HttpResponse = httpResponse

	var (
		done    = make(chan bool, 1)
		headers = make(http.Header, len(httpResponse.Header))
	)

	defer close(done)

	if !response.IgnoreBody {
		go func() {
			defer func() {
				recover()
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
					done <- true
					err = fmt.Errorf("read body: timeout")
					break

				case <-done:
					break
				}
			}
		}()
	} else {
		done <- true
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

	cookies := http.ReadSetCookies(httpResponse.Header)
	s.CookieJar.SetCookies(u, cookies)
	response.Cookies = GetCookiesMap(cookies)
	response.ContentLength = httpResponse.ContentLength
	response.TLS = httpResponse.TLS

	<-done

	return
}

func (r *Response) ReadBody() ([]byte, error) {
	defer r.HttpResponse.Body.Close()

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
