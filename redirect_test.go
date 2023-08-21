package azuretls

import (
	http "github.com/Noooste/fhttp"
	"net/url"
	"strings"
	"testing"
)

func TestRedirect(t *testing.T) {
	session := NewSession()

	response, err := session.Get("https://httpbin.org/redirect/1")

	if err != nil {
		t.Fatal(err)
	}

	if response.StatusCode != 200 {
		t.Fatal("TestRedirect failed, expected: 200, got: ", response.StatusCode)
	}

	if response.Url != "https://httpbin.org/get" {
		t.Fatal("TestRedirect failed, expected: https://httpbin.org/get, got: ", response.Url)
	}
}

func TestRedirect2_307(t *testing.T) {
	session := NewSession()

	response, err := session.Get("https://httpbin.org/status/307")

	if err != nil {
		t.Fatal(err)
	}

	if response.StatusCode != 200 {
		t.Fatal("TestRedirect2_307 failed, expected: 200, got: ", response.StatusCode)
	}

	if response.Url != "https://httpbin.org/get" {
		t.Fatal("TestRedirect2_307 failed, expected: https://httpbin.org/get, got: ", response.Url)
	}
}

func TestRedirect2(t *testing.T) {
	resp := &Response{
		StatusCode: http.StatusPermanentRedirect,
		Header:     make(http.Header),
	}

	_, shouldRedirect, _ := redirectBehavior(http.MethodGet, resp, &Request{})

	if shouldRedirect {
		t.Fatal("TestRedirect2 failed, expected no redirection")
	}

	resp.Header.Set("Location", "something")
	_, shouldRedirect, _ = redirectBehavior(http.MethodGet, resp, &Request{
		contentLength: 1,
	})

	if shouldRedirect {
		t.Fatal("TestRedirect2 failed, expected no redirection")
	}

	resp.StatusCode = http.StatusFound
	m, _, _ := redirectBehavior(http.MethodPost, resp, &Request{})

	if m != http.MethodGet {
		t.Fatal("TestRedirect2 failed, expected no redirection")
	}

	if v := refererForURL(&url.URL{Host: "example.com", Scheme: SchemeHttps}, &url.URL{Host: "example.com", Scheme: SchemeHttp}); v != "" {
		t.Fatal("TestRedirect2 failed, expected no referer, got", v)
	}

	if v := refererForURL(&url.URL{User: &url.Userinfo{}, Host: "example.com", Scheme: SchemeHttps}, &url.URL{Host: "example.com", Scheme: SchemeHttp}); strings.Contains(v, "@") {
		t.Fatal("TestRedirect2 failed, expected referer without @, got", v)
	}
}
