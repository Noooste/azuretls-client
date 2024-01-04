package azuretls_tests

import (
	"context"
	"github.com/Noooste/azuretls-client"
	http "github.com/Noooste/fhttp"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestRequest_SetContext(t *testing.T) {
	session := azuretls.NewSession()

	req := &azuretls.Request{
		Method: http.MethodGet,
		Url:    "https://httpbin.org/delay/5",
	}

	ctx := context.Background()

	var cancel context.CancelFunc
	ctx, cancel = context.WithTimeout(ctx, 1*time.Second)
	defer cancel()

	req.SetContext(ctx)

	_, err := session.Do(req)

	if err == nil || err.Error() != "timeout" {
		t.Fatal("TestSession_SetTimeout failed, expected: timeout, got: ", err)
		return
	}

}

func TestRequest_NoCookies(t *testing.T) {
	session := azuretls.NewSession()

	session.CookieJar.SetCookies(&url.URL{
		Scheme: "https",
		Host:   "httpbin.org",
	}, []*http.Cookie{
		{
			Name:  "test",
			Value: "test",
		},
	})

	req := &azuretls.Request{
		Method:   http.MethodGet,
		Url:      "https://httpbin.org/cookies",
		NoCookie: true,
	}

	resp, err := session.Do(req)

	if err != nil {
		t.Fatal("TestRequest_NoCookies failed, expected: nil, got: ", err)
		return
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatal("TestRequest_NoCookies failed, expected: 200, got: ", resp.StatusCode)
		return
	}

	if strings.Contains(string(resp.Body), "test") {
		t.Fatal("TestRequest_NoCookies failed, expected: false, got: true")
		return
	}
}

func TestRequest_TooManyRedirections(t *testing.T) {
	session := azuretls.NewSession()

	req := &azuretls.Request{
		Method:          http.MethodGet,
		Url:             "https://httpbin.org/redirect/5",
		MaxRedirections: 1,
	}

	resp, err := session.Do(req)

	if err == nil || !strings.Contains(err.Error(), "too many redirections") {
		t.Fatal("TestSession_TooManyRedirections failed, expected: too many redirections, got: ", err)
		return
	}

	if resp != nil {
		t.Fatal("TestSession_TooManyRedirections failed, expected: nil, got: ", resp)
		return
	}
}
