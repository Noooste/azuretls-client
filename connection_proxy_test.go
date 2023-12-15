package azuretls

import (
	"context"
	"os"
	"testing"
)

var skipProxy bool

func TestProxyDialer_Dial(t *testing.T) {
	session := NewSession()

	if err := session.SetProxy(os.Getenv("NON_SECURE_PROXY")); err != nil {
		skipProxy = true
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
	session := NewSession()

	if err := session.SetProxy(""); err == nil {
		t.Fatal("testProxy failed, expected error, got nil")
	}

	var loaded map[string]any

	response, err := session.Get("https://tls.peet.ws/api/all")

	if err != nil {
		t.Fatal(err)
	}

	if err = response.JSON(&loaded); err != nil {
		t.Fatal(err)
	}

	oldIP := loaded["ip"].(string)

	session.InsecureSkipVerify = true

	if os.Getenv("NON_SECURE_PROXY") == "" {
		t.Fatal("TestProxy failed, NON_SECURE_PROXY is not set")
	}

	session.SetProxy(os.Getenv("NON_SECURE_PROXY"))

	response, err = session.Get("https://tls.peet.ws/api/all")

	if err != nil {
		t.Fatal(err)
	}

	if err = response.JSON(&loaded); err != nil {
		t.Fatal(err)
	}

	newIP := loaded["ip"].(string)

	if oldIP == newIP {
		t.Fatal("TestProxy failed, IP is not changed")
	}
}

func TestProxy2(t *testing.T) {
	t.SkipNow()

	session := NewSession()

	session.H2Proxy = true
	if err := session.SetProxy(os.Getenv("NON_SECURE_PROXY")); err != nil {
		t.Fatal(err)
	}

	_, err := session.Get("https://tls.peet.ws/api/all")

	if err != nil {
		t.Fatal(err)
	}
}

func TestProxy3(t *testing.T) {
	t.SkipNow()

	session := NewSession()
	session.H2Proxy = true

	if err := session.SetProxy(os.Getenv("SECURE_PROXY")); err != nil {
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

func TestProxy4(t *testing.T) {
	t.SkipNow()

	session := NewSession()

	if err := session.SetProxy("socks5://test.com"); err != nil {
		t.Fatal("testProxy failed, expected nil, got ", err)
	} else if err = session.SetProxy(""); err == nil {
		t.Fatal("testProxy failed, expected error, got nil")
	}

	var loaded map[string]any

	session.ClearProxy()
	response, err := session.Get("https://tls.peet.ws/api/all")

	if err != nil {
		t.Fatal(err)
	}

	if err = response.JSON(&loaded); err != nil {
		t.Fatal(err)
	}

	oldIP := loaded["ip"].(string)

	session.InsecureSkipVerify = true

	if os.Getenv("SOCKS5_PROXY") == "" {
		t.Fatal("TestProxy failed, SOCKS5_PROXY is not set")
	}

	session.SetProxy(os.Getenv("SOCKS5_PROXY"))

	response, err = session.Get("https://tls.peet.ws/api/all")

	if err != nil {
		t.Fatal(err)
	}

	if err = response.JSON(&loaded); err != nil {
		t.Fatal(err)
	}

	newIP := loaded["ip"].(string)

	if oldIP == newIP {
		t.Fatal("TestProxy failed, IP is not changed")
	}
}
