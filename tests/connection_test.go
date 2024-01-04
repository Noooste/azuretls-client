package azuretls_tests

import (
	"github.com/Noooste/azuretls-client"
	url2 "net/url"
	"runtime"
	"sync"
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

	response, err := session.Get("https://www.cloudflare.com/cdn-cgi/trace")

	if err != nil {
		t.Fatal(err)
	}

	if response.StatusCode != 200 {
		t.Fatal("TestHeader failed, expected: 200, got: ", response.StatusCode)
	}
}

func TestHighConcurrency(t *testing.T) {
	session := azuretls.NewSession()

	wait := &sync.WaitGroup{}

	count := 50

	wait.Add(count)

	var err error
	var ok int

	for i := 0; i < count; i++ {
		go func() {
			defer wait.Done()
			_, err2 := session.Get("https://example.com")

			if err2 != nil {
				err = err2
				t.Error(err2)
				return
			}

			ok++
		}()
	}

	wait.Wait()

	if err != nil {
		t.Error("TestHighConcurrency failed, expected: ", count, ", got: ", ok)
		t.Fatal(err)
	}

	if ok < count-1 { //~1 request can fail
		t.Fatal("TestHighConcurrency failed, expected: ", count, ", got: ", ok)
	}
}
