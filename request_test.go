package azuretls

import (
	"context"
	http "github.com/Noooste/fhttp"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestRequest_SetContext(t *testing.T) {
	session := NewSession()

	req := &Request{
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
	session := NewSession()

	session.CookieJar.SetCookies(&url.URL{
		Scheme: "https",
		Host:   "httpbin.org",
	}, []*http.Cookie{
		{
			Name:  "test",
			Value: "test",
		},
	})

	req := &Request{
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
