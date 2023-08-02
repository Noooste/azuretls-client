package azuretls

import (
	"encoding/base64"
	"encoding/json"
	http "github.com/Noooste/fhttp"
	"github.com/Noooste/fhttp/cookiejar"
	"io"
	"strings"
)

func (s *Session) buildResponse(response *Response, httpResponse *http.Response) *Response {
	response.RawBody = httpResponse.Body
	response.HttpResponse = httpResponse

	if !response.IgnoreBody {
		response.Body, _ = response.ReadBody()
	}

	var Header = http.Header{}

	for key, value := range httpResponse.Header {
		Header[key] = value
	}

	response.Id = getRandomId()
	response.StatusCode = httpResponse.StatusCode
	response.Header = Header
	response.Url = httpResponse.Request.URL.String()

	if s.CookieJar == nil {
		s.CookieJar, _ = cookiejar.New(nil)
	}

	cookies := http.ReadSetCookies(httpResponse.Header)
	s.CookieJar.SetCookies(httpResponse.Request.URL, cookies)
	response.Cookies = getCookiesMap(cookies)

	response.ContentLength = httpResponse.ContentLength
	response.TLS = httpResponse.TLS

	return response
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

func buildServerPushResponse(response *http.Response) *ServerPush {
	defer response.Body.Close()

	var body string

	encoding := response.Header.Get("content-encoding")

	bodyBytes, err := io.ReadAll(response.Body)

	if err != nil {
		body = "error"
	} else if encoding != "" {
		result := DecompressBody(bodyBytes, encoding)
		if strings.Contains(response.Header.Get("content-type"), "octet-stream") {
			body = base64.StdEncoding.EncodeToString(result)
		} else {
			body = string(result)
		}

	} else {
		body = string(bodyBytes)
	}

	var Header = map[string]string{}

	for key, value := range response.Header {
		Header[key] = value[0]
	}

	return &ServerPush{
		StatusCode: response.StatusCode,
		Body:       body,
		Headers:    Header,
		Cookies:    getCookiesMap(http.ReadSetCookies(response.Header)),
		Url:        response.Request.URL.String(),
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
