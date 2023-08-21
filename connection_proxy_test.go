package azuretls

import (
	"context"
	"os"
	"testing"
)

var skipProxy bool

func TestProxyDialer_Dial(t *testing.T) {
	session := NewSession()

	if err := session.SetProxy("http://localhost:8888"); err != nil {
		t.Fatal(err)
	}

	_, _, err := session.proxyDialer.initProxyConn(context.Background(), "tcp")

	if err != nil {
		skipProxy = true
	}
}

func testAssignProxyFormat(t *testing.T, proxy string) {

	s := &Session{}

	err := s.assignProxy(proxy)

	if err == nil {
		t.Fatal("TestProxyDialer_WrongFormat failed with ", proxy, ", expected: error, got: nil")
	}
}

func TestProxyDialer_WrongFormat(t *testing.T) {
	testAssignProxyFormat(t, "notgoodurl")
	testAssignProxyFormat(t, "http://username@aaaaa")
	testAssignProxyFormat(t, "http://username@aaaaa:9999")
	testAssignProxyFormat(t, "@")
	testAssignProxyFormat(t, "://aaaa")
	testAssignProxyFormat(t, "socks5://aaaaa")
	testAssignProxyFormat(t, "/qqqqq")
}

func testAssignProxy(t *testing.T, proxy string) {
	s := &Session{}

	err := s.assignProxy(proxy)

	if err != nil {
		t.Fatal("TestProxyDialer failed with ", proxy, ", expected: ", nil, ", got: ", err)
		return
	}
}

func TestProxyDialer(t *testing.T) {
	testAssignProxy(t, "http://username:password@aaaaa:9999")
	testAssignProxy(t, "http://username:password@aaaaa")
	testAssignProxy(t, "http://aaaaa:9999")
	testAssignProxy(t, "http://aaaaa")
	testAssignProxy(t, "https://aaaaa")
}

func TestProxy(t *testing.T) {
	if skipProxy {
		t.Skip("TestProxy skipped")
	}

	session := NewSession()

	if err := session.SetProxy("socks5://test.com"); err == nil {
		t.Fatal("testProxy failed, expected error, got nil")
	} else if err = session.SetProxy(""); err == nil {
		t.Fatal("testProxy failed, expected error, got nil")
	}

	response, err := session.Get("https://api.ipify.org/")

	if err != nil {
		t.Fatal(err)
	}

	oldIP := string(response.Body)

	session.InsecureSkipVerify = true

	if os.Getenv("HTTP_PROXY") == "" {
		t.Fatal("TestProxy failed, HTTP_PROXY is not set")
	}

	session.SetProxy(os.Getenv("HTTP_PROXY"))

	response, err = session.Get("https://api.ipify.org/")

	if err != nil {
		t.Fatal(err)
	}

	newIP := string(response.Body)

	if oldIP == newIP {
		t.Fatal("TestProxy failed, IP is not changed")
	}
}

func TestProxy2(t *testing.T) {
	if skipProxy {
		t.Skip("TestProxy skipped")
	}

	session := NewSession()

	session.H2Proxy = true
	if err := session.SetProxy(os.Getenv("HTTP_PROXY")); err != nil {
		t.Fatal(err)
	}

	_, err := session.Get("https://tls.peet.ws/api/all")

	if err != nil {
		t.Fatal(err)
	}
}

func TestProxy3(t *testing.T) {
	if skipProxy {
		t.Skip("TestProxy skipped")
	}

	session := NewSession()
	session.H2Proxy = true

	if err := session.SetProxy(os.Getenv("HTTPS_PROXY")); err != nil {
		t.Fatal(err)
	}

	_, err := session.Get("https://www.nike.com/fr/")

	if err != nil {
		t.Fatal(err)
	}

	oldConn := session.proxyDialer.h2Conn

	_, err = session.proxyDialer.Dial("tcp", "www.nike.com:443")

	if err != nil {
		t.Fatal(err)
	}

	if session.proxyDialer.h2Conn != oldConn {
		t.Fatal("TestProxy failed, Conn is not reused")
	}

	_, err = session.Get("https://www.nike.com/fr/")

	if err != nil {
		t.Fatal(err)
	}
}
