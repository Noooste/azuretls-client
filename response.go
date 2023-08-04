package azuretls

import (
	"encoding/json"
	http "github.com/Noooste/fhttp"
	"github.com/Noooste/go-utils"
	"io"
	"net/url"
)

func (s *Session) buildResponse(response *Response, httpResponse *http.Response) {
	response.RawBody = httpResponse.Body
	response.HttpResponse = httpResponse

	var (
		done    chan bool
		headers = make(http.Header, len(httpResponse.Header))
	)

	if !response.IgnoreBody {
		done = make(chan bool, 1)
		defer close(done)
		utils.SafeGoRoutine(func() {
			response.Body, _ = response.ReadBody()
			done <- true
		})
	}

	for key, value := range httpResponse.Header {
		headers[key] = value
	}

	response.Id = getRandomId()
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
	response.Cookies = getCookiesMap(cookies)
	response.ContentLength = httpResponse.ContentLength
	response.TLS = httpResponse.TLS

	<-done
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

func (r *Response) CloseBody() {
	if r.RawBody != nil {
		_ = r.RawBody.Close()
	}
}

func (r *Response) Load(v any) error {
	if r.Body == nil {
		return nil
	}

	return json.Unmarshal(r.Body, v)
}

func (r *Response) MustLoad(v any) {
	if err := r.Load(v); err != nil {
		panic(err)
	}
}
