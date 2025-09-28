package azuretls_test

import (
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/Noooste/azuretls-client"
	http "github.com/Noooste/fhttp"
)

func TestRedirect(t *testing.T) {
	session := azuretls.NewSession()

	response, err := session.Get(httpbinBaseURL + "/redirect/1")

	if err != nil {
		t.Fatal(err)
	}

	if response.StatusCode != 200 {
		t.Fatal("TestRedirect failed, expected: 200, got: ", response.StatusCode)
	}

	if response.Url != httpbinBaseURL+"/get" {
		t.Fatal("TestRedirect failed, expected: https://httpbingo.org/get, got: ", response.Url)
	}
}

func TestRedirect2_307(t *testing.T) {
	session := azuretls.NewSession()

	response, err := session.Get(httpbinBaseURL + "/status/307")

	if err != nil {
		t.Fatal(err)
	}

	if response.StatusCode != 200 {
		t.Fatal("TestRedirect2_307 failed, expected: 200, got: ", response.StatusCode)
	}

	if response.Url != httpbinBaseURL+"/get" {
		t.Fatal("TestRedirect2_307 failed, expected: https://httpbingo.org/get, got: ", response.Url)
	}
}

func TestRedirect2(t *testing.T) {
	resp := &azuretls.Response{
		StatusCode: http.StatusPermanentRedirect,
		Header:     make(http.Header),
	}

	_, shouldRedirect, _ := azuretls.RedirectBehavior(http.MethodGet, resp, &azuretls.Request{})

	if shouldRedirect {
		t.Fatal("TestRedirect2 failed, expected no redirection")
	}

	resp.Header.Set("Location", "something")
	_, shouldRedirect, _ = azuretls.RedirectBehavior(http.MethodGet, resp, &azuretls.Request{
		ContentLength: 1,
	})

	if shouldRedirect {
		t.Fatal("TestRedirect2 failed, expected no redirection")
	}

	resp.StatusCode = http.StatusFound
	m, _, _ := azuretls.RedirectBehavior(http.MethodPost, resp, &azuretls.Request{})

	if m != http.MethodGet {
		t.Fatal("TestRedirect2 failed, expected no redirection")
	}

	if v := azuretls.RefererForURL(&url.URL{Host: "example.com", Scheme: azuretls.SchemeHttps}, &url.URL{Host: "example.com", Scheme: azuretls.SchemeHttp}); v != "" {
		t.Fatal("TestRedirect2 failed, expected no referer, got", v)
	}

	if v := azuretls.RefererForURL(&url.URL{User: &url.Userinfo{}, Host: "example.com", Scheme: azuretls.SchemeHttps}, &url.URL{Host: "example.com", Scheme: azuretls.SchemeHttp}); strings.Contains(v, "@") {
		t.Fatal("TestRedirect2 failed, expected referer without @, got", v)
	}
}

func TestRedirectWithCheckRedirect(t *testing.T) {
	session := azuretls.NewSession()
	defer session.Close()

	var called bool

	session.CheckRedirect = func(req *azuretls.Request, via []*azuretls.Request) error {
		if req.Response == nil {
			t.Error("expected non-nil Request.Response")
		}

		called = true
		return azuretls.ErrUseLastResponse
	}

	response, err := session.Get(httpbinBaseURL + "/redirect/1")

	if err != nil {
		t.Fatal(err)
	}

	if response.StatusCode != 302 {
		t.Fatal("TestRedirectWithCheckRedirect failed, expected: 200, got: ", response.StatusCode)
	}

	if !called {
		t.Fatal("TestRedirectWithCheckRedirect failed, CheckRedirect was not called")
	}
}

func TestRedirectWithDump(t *testing.T) {
	session := azuretls.NewSession()
	defer session.Close()

	session.Dump("./testdata/")

	response, err := session.Get(httpbinBaseURL + "/redirect/1")

	if err != nil {
		t.Fatal(err)
	}

	if response.StatusCode != 200 {
		t.Fatal("TestRedirectWithDump failed, expected: 200, got: ", response.StatusCode)
	}

	if _, err = os.Stat("./testdata/"); os.IsExist(err) {
		t.Fatal("TestRedirectWithDump failed, expected dump file to exist, got error: ", err)
	}
}
