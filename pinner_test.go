package azuretls

import (
	"net/url"
	"testing"
)

func TestPins(t *testing.T) {
	session := NewSession()

	session.VerifyPins = true

	response, err := session.Get("https://httpbin.org/get")

	if err != nil {
		t.Fatal(err)
	}

	if response.StatusCode != 200 {
		t.Fatal("TestPins failed, expected: 200, got: ", response.StatusCode)
	}

	if len(session.conns.hosts) == 0 {
		t.Fatal("TestPins failed, Conn is empty")
	}

	if len(session.conns.hosts["httpbin.org:443"].pins) == 0 {
		t.Fatal("TestPins failed, Pins is empty")
	}

	session.SetProxy("http://localhost:8888")

	response, err = session.Get("https://httpbin.org/get")

	if err != nil && err.Error() != "pin verification failed" {
		t.Fatal("TestPins failed, expected: pin verification failed, got: ", err)
	} else if err == nil {
		t.Fatal("TestPins failed, expected: pin verification failed, got: ", err)
	}
}

func TestSession_AddPins(t *testing.T) {
	session := NewSession()

	session.AddPins(&url.URL{
		Scheme: "https",
		Host:   "httpbin.org",
	}, []string{
		"j5bzD/UjYVE+0feXsngcrVs3i1vSaoOOtPgpLBb9Db8=",
		"18tkPyr2nckv4fgo0dhAkaUtJ2hu2831xlO2SKhq8dg=",
		"++MBgDH5WGvL9Bcn5Be30cRcL0f5O+NyoXuWtQdX1aI=",
		"KwccWaCgrnaw6tsrrSO61FgLacNgG2MMLq8GE6+oP5I=",
	})

	_, err := session.Get("https://httpbin.org/get")

	if err != nil {
		t.Fatal("TestPins failed, expected: nothing wrong, got: ", err)
	}
}

func TestSession_AddPins2(t *testing.T) {
	session := NewSession()

	session.AddPins(&url.URL{
		Scheme: "https",
		Host:   "httpbin.org",
	}, []string{
		"not a good pin here",
	})

	_, err := session.Get("https://httpbin.org/get")

	if err != nil && err.Error() != "pin verification failed" {
		t.Fatal("TestPins failed, expected: pin verification failed, got: ", err)
	} else if err == nil {
		t.Fatal("TestPins failed, expected: pin verification failed, got: ", err)
	}
}
