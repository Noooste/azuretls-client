package azuretls_test

import (
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Noooste/azuretls-client"
)

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
		_, err2 := session.Do(&azuretls.Request{
			Method: "GET",
			Url:    "http://example.com/",
		})

		if err2 != nil {
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

	var ok = new(int64)

	var i int64

	for i = 0; i < count; i++ {
		go concurrency(session, wait, ok)
	}

	wait.Wait()

	if atomic.LoadInt64(ok) < count-1 { //~1 request can fail
		t.Fatal("TestHighConcurrency failed, expected: ", count, ", got: ", ok)
	}
}

func TestPeetClosingConn(t *testing.T) {
	session := azuretls.NewSession()
	defer session.Close()

	_, err := session.Get("https://tls.peet.ws/api/all")

	if err != nil {
		t.Fatal(err)
	}

	_, err = session.Get("https://tls.peet.ws/api/all")

	if err != nil {
		t.Fatal(err)
	}
}

func TestForceHTTP1Request(t *testing.T) {
	session := azuretls.NewSession()
	defer session.Close()

	response, err := session.Do(&azuretls.Request{
		Method:     "GET",
		Url:        "https://tls.peet.ws/api/all",
		ForceHTTP1: true,
	})

	if err != nil {
		t.Fatal(err)
	}

	if response.StatusCode != 200 {
		t.Fatal("TestHeader failed, expected: 200, got: ", response.StatusCode)
	}

	var result map[string]any

	if err = response.JSON(&result); err != nil {
		t.Fatal(err)
	}

	if result["http_version"] != "HTTP/1.1" {
		t.Fatal("TestHeader failed, expected: HTTP/1.1, got: ", result["protocol"])
	}

	response, err = session.Do(&azuretls.Request{
		Method: "GET",
		Url:    "https://tls.peet.ws/api/all",
	})

	if err != nil {
		t.Fatal(err)
	}

	if response.StatusCode != 200 {
		t.Fatal("TestHeader failed, expected: 200, got: ", response.StatusCode)
	}

	if err = response.JSON(&result); err != nil {
		t.Fatal(err)
	}

	if result["http_version"] != "h2" {
		t.Fatal("TestHeader failed, expected: HTTP/1.1, got: ", result["protocol"])
	}
}
func TestModifyDialer(t *testing.T) {
	session := azuretls.NewSession()
	defer session.Close()

	session.ModifyDialer = func(dialer *net.Dialer) error {
		dialer.Timeout = 10 * time.Second
		return nil
	}

	response, err := session.Get("https://tls.peet.ws/api/all")

	if err != nil {
		t.Fatal(err)
	}

	if response.StatusCode != 200 {
		t.Fatal("TestHeader failed, expected: 200, got: ", response.StatusCode)
	}
}

func TestInsecureSkipVerifySession(t *testing.T) {
	session := azuretls.NewSession()
	defer session.Close()

	session.InsecureSkipVerify = true

	response, err := session.Get("https://expired.badssl.com/")

	if err != nil {
		t.Fatal("InsecureSkipVerify should allow expired certificates, got error:", err)
	}

	if response.StatusCode != 200 {
		t.Fatal("TestInsecureSkipVerifySession failed, expected: 200, got: ", response.StatusCode)
	}
}

func TestInsecureSkipVerifyRequest(t *testing.T) {
	session := azuretls.NewSession()
	defer session.Close()

	response, err := session.Do(&azuretls.Request{
		Method:             "GET",
		Url:                "https://wrong.host.badssl.com/",
		InsecureSkipVerify: true,
	})

	if err != nil {
		t.Fatal("InsecureSkipVerify should allow wrong host certificates, got error:", err)
	}

	if response.StatusCode != 200 {
		t.Fatal("TestInsecureSkipVerifyRequest failed, expected: 200, got: ", response.StatusCode)
	}
}

func TestInsecureSkipVerifyMultipleHosts(t *testing.T) {
	session := azuretls.NewSession()
	defer session.Close()

	session.InsecureSkipVerify = true

	// Test expired certificate
	response1, err1 := session.Get("https://expired.badssl.com/")
	if err1 != nil {
		t.Fatal("InsecureSkipVerify should allow expired certificates, got error:", err1)
	}
	if response1.StatusCode != 200 {
		t.Fatal("TestInsecureSkipVerifyMultipleHosts (expired) failed, expected: 200, got: ", response1.StatusCode)
	}

	// Test self-signed certificate
	response2, err2 := session.Get("https://self-signed.badssl.com/")
	if err2 != nil {
		t.Fatal("InsecureSkipVerify should allow self-signed certificates, got error:", err2)
	}
	if response2.StatusCode != 200 {
		t.Fatal("TestInsecureSkipVerifyMultipleHosts (self-signed) failed, expected: 200, got: ", response2.StatusCode)
	}

	// Test wrong host
	response3, err3 := session.Get("https://wrong.host.badssl.com/")
	if err3 != nil {
		t.Fatal("InsecureSkipVerify should allow wrong host certificates, got error:", err3)
	}
	if response3.StatusCode != 200 {
		t.Fatal("TestInsecureSkipVerifyMultipleHosts (wrong host) failed, expected: 200, got: ", response3.StatusCode)
	}
}
