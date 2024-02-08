package azuretls_test

import (
	"github.com/Noooste/azuretls-client"
	http "github.com/Noooste/fhttp"
	"os"
	"strings"
	"testing"
	"time"
)

func TestSession_EnableVerbose(t *testing.T) {
	defer os.RemoveAll("./tmp")

	session := azuretls.NewSession()

	session.EnableVerbose("./tmp", []string{"*.httpbin.org"})

	if !session.Verbose {
		t.Fatal("Verbose not enabled")
	}

	if session.VerbosePath != "./tmp" {
		t.Fatal("VerbosePath not set")
	}

	if len(session.VerboseIgnoreHost) != 1 {
		t.Fatal("VerboseIgnoreHost not set")
	}

	if session.VerboseIgnoreHost[0] != "*.httpbin.org" {
		t.Fatal("VerboseIgnoreHost not set")
	}

	if !session.IsVerboseIgnored("test.httpbin.org") {
		t.Fatal("test.httpbin.org is not ignored")
	}

	if !session.IsVerboseIgnored("httpbin.org") {
		t.Fatal("test.httpbin.org is not ignored")
	}

	if err := session.EnableVerbose("", nil); err == nil {
		t.Fatal(err)
	}

	_, err := session.Post("https://httpbin.org/post", "ahhhhhh")

	if err != nil {
		t.Error(err)
		return
	}

	if err = session.EnableVerbose("./tmp", nil); err != nil {
		t.Fatal(err)
	}

	_, err = session.Get("https://httpbin.org/get?t=v")

	if err != nil {
		t.Error(err)
		return
	}

	time.Sleep(50 * time.Millisecond)
	f, err := os.ReadDir("./tmp")

	if err != nil {
		t.Error(err)
		return
	}

	if len(f) == 0 {
		t.Error("No files created")
		return
	}
}

func TestSession_EnableVerbose2(t *testing.T) {
	req := (&azuretls.Request{
		HttpRequest: &http.Request{
			Header: http.Header{
				"cookie":     {"c1=v1; c2=v2"},
				"set-cookie": {"c1=v1", "c2=v2"},
			},
		},
		Proxy: "test",
		Body:  "aa",
	}).String()

	if !strings.Contains(req, "Proxy : test") {
		t.Fatal("no proxy in req.String()")
	} else if !strings.Contains(req, "\naa") {
		t.Fatal("no body in req.String()")
	} else if !strings.Contains(req, "cookie: c1=v1\ncookie: c2=v2") {
		t.Fatal("no cookies in req.String()")
	} else if !strings.Contains(req, "set-cookie: c1=v1\nset-cookie: c2=v2") {
		t.Fatal("no set-cookie in req.String()")
	}

	defer os.RemoveAll("./tmp")

	session := azuretls.NewSession()

	session.EnableVerbose("./tmp", []string{"*.httpbin.org"})

	if !session.Verbose {
		t.Fatal("Verbose not enabled")
	}

	if session.VerbosePath != "./tmp" {
		t.Fatal("VerbosePath not set")
	}

	if len(session.VerboseIgnoreHost) != 1 {
		t.Fatal("VerboseIgnoreHost not set")
	}

	if session.VerboseIgnoreHost[0] != "*.httpbin.org" {
		t.Fatal("VerboseIgnoreHost not set")
	}

	_, err := session.Get("https://httpbin.org/get")

	if err != nil {
		t.Error(err)
		return
	}

	session.EnableVerbose("./tmp", nil)

	var headers = azuretls.OrderedHeaders{
		{"sec-ch-ua-mobile", "?0"},
		{"user-agent", session.UserAgent},
		{"content-type", "application/json; charset=UTF-8"},
		{"accept", "application/json"},
		{"sec-ch-ua-platform", "\"Windows\""},
		{"origin", "https://www.nike.com"},
		{"sec-fetch-site", "same-site"},
		{"sec-fetch-mode", "cors"},
		{"sec-fetch-dest", "empty"},
		{"referer", "https://www.nike.com/"},
		{"accept-encoding", "gzip, deflate, br"},
		{"accept-language", "en-US,en;q=0.9"},
	}

	_, err = session.Get("https://httpbin.org/anything/test/test2%2ftest/", headers)

	if err != nil {
		t.Error(err)
		return
	}

	time.Sleep(50 * time.Millisecond)
	f, err := os.ReadDir("./tmp")

	if err != nil {
		t.Error(err)
		return
	}

	if len(f) == 0 {
		t.Error("No files created")
		return
	}

}
