package azuretls_test

import (
	"fmt"
	"github.com/Noooste/azuretls-client"
	http "github.com/Noooste/fhttp"
	url2 "net/url"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
)

func TestSessionConn(t *testing.T) {
	runtime.GOMAXPROCS(runtime.NumCPU())

	session := azuretls.NewSession()

	response, err := session.Get("https://example.com/")

	if err != nil {
		t.Fatal(err)
	}

	if response.StatusCode != 200 {
		t.Fatal("TestHeader failed, expected: 200, got: ", response.StatusCode)
	}

	u := &url2.URL{
		Scheme: "https",
		Host:   "example.com",
	}

	firstConn := session.Connections.Get(u)

	if !firstConn.HTTP2.CanTakeNewRequest() {
		t.Fatal("TestSessionConn failed, Conn is not reusable")
	}

	if err = firstConn.TLS.VerifyHostname("example.com"); err != nil {
		t.Fatal("TestSessionConn failed, VerifyHostname failed : ", err)
	}

	response, err = session.Get("https://example.com/")

	if err != nil {
		t.Fatal(err)
	}

	if response.StatusCode != 200 {
		t.Fatal("TestHeader failed, expected: 200, got: ", response.StatusCode)
	}

	if session.Connections.Get(u) != firstConn {
		t.Fatal("TestSessionConn failed, Conn is not reused")
	}
}

func TestHTTP1Conn(t *testing.T) {
	session := azuretls.NewSession()

	_, err := session.Get("https://api.ipify.org/")

	if err != nil {
		t.Fatal(err)
	}
}

func TestCloudflareRequest(t *testing.T) {
	session := azuretls.NewSession()
	defer session.Close()

	response, err := session.Get("https://www.cloudflare.com/cdn-cgi/trace")

	if err != nil {
		t.Fatal(err)
	}

	if response.StatusCode != 200 {
		t.Fatal("TestHeader failed, expected: 200, got: ", response.StatusCode)
	}
}

func concurrency(session *azuretls.Session, wg *sync.WaitGroup, ok *int64) bool {
	defer wg.Done()

	for i := 0; i < 10; i++ {
		_, err2 := session.Get("https://example.com/")

		if err2 != nil {
			fmt.Println(err2)
			return false
		}
	}

	atomic.AddInt64(ok, 1)

	return true
}

func TestHighConcurrency(t *testing.T) {
	session := azuretls.NewSession()
	defer session.Close()

	wait := &sync.WaitGroup{}

	var count int64 = 100

	wait.Add(int(count))

	var err error
	var ok = new(int64)

	var i int64

	for i = 0; i < count; i++ {
		go concurrency(session, wait, ok)
	}

	wait.Wait()

	if err != nil {
		t.Error("TestHighConcurrency failed, expected: ", count, ", got: ", ok)
		t.Fatal(err)
	}

	if atomic.LoadInt64(ok) < count-1 { //~1 request can fail
		t.Fatal("TestHighConcurrency failed, expected: ", count, ", got: ", ok)
	}
}

func downloadImage(client *azuretls.Session, url string) ([]byte, error) {
	resp, err := client.Do(&azuretls.Request{
		Method: http.MethodGet,
		Url:    url,
		OrderedHeaders: azuretls.OrderedHeaders{
			{"Host", "dd.prod.captcha-delivery.com"},
			{"Connection", "keep-alive"},
			{"sec-ch-ua", `"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"`},
			{"Origin", "https://geo.captcha-delivery.com"},
			{"sec-ch-ua-mobile", "?0"},
			{"User-Agent", `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36`},
			{"sec-ch-ua-platform", `"macOS"`},
			{"Accept", "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8"},
			{"Sec-Fetch-Site", "same-site"},
			{"Sec-Fetch-Mode", "cors"},
			{"Sec-Fetch-Dest", "image"},
			{"Referer", "https://geo.captcha-delivery.com/"},
			{"Accept-Encoding", "gzip, deflate, br, zstd"},
			{"Accept-Language", "en-GB,en-US;q=0.9,en;q=0.8"},
		},
		ForceHTTP1: true,
	})
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status code: %d", resp.StatusCode)
	}
	return resp.Body, nil
}
