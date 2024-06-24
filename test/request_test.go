package azuretls_test

import (
	"bytes"
	"context"
	"fmt"
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

func TestRequest_TooManyRedirects(t *testing.T) {
	session := azuretls.NewSession()

	req := &azuretls.Request{
		Method:       http.MethodGet,
		Url:          "https://httpbin.org/redirect/5",
		MaxRedirects: 1,
	}

	resp, err := session.Do(req)

	if err == nil || !strings.Contains(err.Error(), "too many Redirects") {
		t.Fatal("TestSession_TooManyRedirects failed, expected: too many Redirects, got: ", err)
		return
	}

	if resp != nil {
		t.Fatal("TestSession_TooManyRedirects failed, expected: nil, got: ", resp)
		return
	}
}

func TestRequestBody(t *testing.T) {
	m := []any{
		"test",
		[]byte("test"),
		strings.NewReader("test"),
		bytes.NewBufferString("test"),
		map[string]string{
			"test": "test",
		},
		&map[string]string{
			"test": "test",
		},
		[]string{"test", "test"},
		&[]string{"test", "test"},
	}

	for _, v := range m {
		req := &azuretls.Request{
			Method: http.MethodPost,
			Url:    "https://httpbin.org/post",
			Body:   v,
		}

		resp, err := azuretls.NewSession().Do(req)

		if err != nil {
			t.Fatal("TestRequestBody failed, expected: nil, got: ", err)
			return
		}

		if resp.StatusCode != http.StatusOK {
			t.Fatal("TestRequestBody failed, expected: 200, got: ", resp.StatusCode)
			return
		}

		if !strings.Contains(string(resp.Body), "test") {
			t.Fatal("TestRequestBody failed, expected: true, got: false")
			return
		}
	}
}

func TestRequest_BadBody(t *testing.T) {
	req := &azuretls.Request{
		Method: http.MethodPost,
		Url:    "https://httpbin.org/post",
		Body:   make(chan int),
	}

	resp, err := azuretls.NewSession().Do(req)

	if err == nil || err.Error() != "unsupported body type : chan" {
		t.Fatal("TestRequest_BadBody failed, expected: invalid body, got:", err)
		return
	}

	if resp != nil {
		t.Fatal("TestRequest_BadBody failed, expected: nil, got: ", resp)
		return
	}
}

func TestRequest_NoCookies2(t *testing.T) {
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
		t.Fatal("TestRequest_NoCookies2 failed, expected: nil, got: ", err)
		return
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatal("TestRequest_NoCookies2 failed, expected: 200, got: ", resp.StatusCode)
		return
	}

	if strings.Contains(string(resp.Body), "test") {
		t.Fatal("TestRequest_NoCookies2 failed, expected: false, got: true")
		return
	}
}

func TestRequest_InsecureSkipVerify(t *testing.T) {
	session := azuretls.NewSession()

	// commenting out this line will make the code work
	session.InsecureSkipVerify = true

	response, err := session.Get("https://www.google.com")
	if err != nil {
		panic(err)
	}
	fmt.Println(response.StatusCode)
	response, err = session.Get("https://www.google.com")
	if err != nil {
		panic(err)
	}
	fmt.Println(response.StatusCode)
}
