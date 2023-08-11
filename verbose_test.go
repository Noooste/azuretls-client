package azuretls

import (
	"os"
	"testing"
	"time"
)

func TestSession_EnableVerbose(t *testing.T) {
	defer os.RemoveAll("./tmp")

	session := NewSession()

	session.EnableVerbose("./tmp", []string{"*.httpbin.org"})

	if !session.Verbose {
		t.Fatal("Verbose not enabled")
	}

	if session.VerbosePath != "./tmp" {
		t.Fatal("VerbosePath not set")
	}

	if len(session.VerboseIgnoreHost) != 2 {
		t.Fatal("VerboseIgnoreHost not set")
	}

	if session.VerboseIgnoreHost[0] != "*.httpbin.org" {
		t.Fatal("VerboseIgnoreHost not set")
	}

	if session.VerboseIgnoreHost[1] != "ipinfo.org" {
		t.Fatal("VerboseIgnoreHost not set")
	}

	_, err := session.Get("https://httpbin.org/get")

	if err != nil {
		t.Error(err)
		return
	}

	session.EnableVerbose("./tmp", nil)

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
	defer os.RemoveAll("./tmp")

	session := NewSession()

	session.EnableVerbose("./tmp", []string{"*.httpbin.org"})

	if !session.Verbose {
		t.Fatal("Verbose not enabled")
	}

	if session.VerbosePath != "./tmp" {
		t.Fatal("VerbosePath not set")
	}

	if len(session.VerboseIgnoreHost) != 2 {
		t.Fatal("VerboseIgnoreHost not set")
	}

	if session.VerboseIgnoreHost[0] != "*.httpbin.org" {
		t.Fatal("VerboseIgnoreHost not set")
	}

	if session.VerboseIgnoreHost[1] != "ipinfo.org" {
		t.Fatal("VerboseIgnoreHost not set")
	}

	_, err := session.Get("https://httpbin.org/get")

	if err != nil {
		t.Error(err)
		return
	}

	session.EnableVerbose("./tmp", nil)

	var headers = OrderedHeaders{
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

	_, err = session.Get("http://httpbin.org/anything/test/test2%2ftest/", headers)

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
