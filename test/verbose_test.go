package azuretls_test

import (
	"github.com/Noooste/azuretls-client"
	"os"
	"testing"
	"time"
)

func TestSession_EnableVerbose(t *testing.T) {
	defer func() {
		_ = os.RemoveAll("./tmp")
	}()

	session := azuretls.NewSession()

	_, err := session.Post("https://httpbin.org/post", "ahhhhhh")

	if err != nil {
		t.Error(err)
		return
	}

	if err = session.Dump("./tmp"); err != nil {
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
	defer func() {
		_ = os.RemoveAll("./tmp")
	}()

	session := azuretls.NewSession()

	if err := session.Dump("./tmp", "/get"); err != nil {
		t.Fatal(err)
	}

	_, err := session.Get("https://httpbin.org/get")

	time.Sleep(50 * time.Millisecond)
	f, err := os.ReadDir("./tmp")

	if err != nil {
		t.Error(err)
		return
	}

	if len(f) != 0 {
		t.Error("files created")
		return
	}

	if err != nil {
		t.Error(err)
		return
	}

	if err := session.Dump("./tmp"); err != nil {
		t.Fatal(err)
	}

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
	f, err = os.ReadDir("./tmp")

	if err != nil {
		t.Error(err)
		return
	}

	if len(f) == 0 {
		t.Error("No files created")
		return
	}

}
