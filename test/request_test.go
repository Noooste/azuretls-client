package azuretls_test

import (
	"bytes"
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Noooste/azuretls-client"
	http "github.com/Noooste/fhttp"
)

func TestRequest_SetContext(t *testing.T) {
	session := azuretls.NewSession()

	req := &azuretls.Request{
		Method: http.MethodGet,
		Url:    "https://httpbingo.org/delay/5",
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
		Host:   "httpbingo.org",
	}, []*http.Cookie{
		{
			Name:  "test",
			Value: "test",
		},
	})

	req := &azuretls.Request{
		Method:   http.MethodGet,
		Url:      "https://httpbingo.org/cookies",
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
		Url:          "https://httpbingo.org/redirect/5",
		MaxRedirects: 1,
	}

	resp, err := session.Do(req)

	if err == nil || !errors.Is(err, azuretls.ErrTooManyRedirects) {
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
			Url:    "https://httpbingo.org/post",
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

		if !bytes.Contains(resp.Body, testB64) {
			t.Fatal("TestRequestBody failed, expected: true, got: false")
			return
		}
	}
}

func TestRequest_BadBody(t *testing.T) {
	req := &azuretls.Request{
		Method: http.MethodPost,
		Url:    "https://httpbingo.org/post",
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
		Host:   "httpbingo.org",
	}, []*http.Cookie{
		{
			Name:  "test",
			Value: "test",
		},
	})

	req := &azuretls.Request{
		Method:   http.MethodGet,
		Url:      "https://httpbingo.org/cookies",
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

	_, err := session.Get("https://www.google.com")
	if err != nil {
		panic(err)
	}
	response, err = session.Get("https://www.google.com")
	if err != nil {
		panic(err)
	}
}

func TestHTTP1Request(t *testing.T) {
	session := azuretls.NewSession()

	req := &azuretls.Request{
		Method:     http.MethodGet,
		Url:        "https://tls.peet.ws/api/all",
		ForceHTTP1: true,
	}

	resp, err := session.Do(req)

	if err != nil {
		t.Fatal("TestHTTP1Request failed, expected: nil, got: ", err)
		return
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatal("TestHTTP1Request failed, expected: 200, got: ", resp.StatusCode)
		return
	}
}

func TestRequestNoDuplicateContentLength(t *testing.T) {
	session := azuretls.NewSession()

	req := &azuretls.Request{
		Method: http.MethodPost,
		Url:    "https://httpbingo.org/post",
		Body:   "test",
		OrderedHeaders: azuretls.OrderedHeaders{
			{"content-length", "4"},
		},
	}

	resp, err := session.Do(req)

	if err != nil {
		t.Fatal("TestRequestNoDuplicateContentLength failed, expected: nil, got: ", err)
		return
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatal("TestRequestNoDuplicateContentLength failed, expected: 200, got: ", resp.StatusCode)
		return
	}

	if !bytes.Contains(resp.Body, testB64) {
		t.Fatal("TestRequestNoDuplicateContentLength failed, expected: true, got: false")
		return
	}
}

func TestRequestDuplicateHeaders(t *testing.T) {
	s := azuretls.NewSession()
	defer s.Close()

	s.Browser = azuretls.Chrome
	header := map[string][]string{
		"User-Agent": {"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36"},
	}
	for range 5 {
		time.Sleep(1 * time.Second)
		_, err := s.Do(&azuretls.Request{
			Method:  http.MethodPost,
			Url:     "https://www.twayair.com",
			Header:  header,
			Body:    "hello",
			TimeOut: 3 * time.Second,
		})
		if err != nil {
			panic(err)
		}
	}
}
