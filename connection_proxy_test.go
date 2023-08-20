package azuretls

import (
	"context"
	"net/url"
	"testing"
)

var skipProxy bool

func TestProxyDialer_Dial(t *testing.T) {
	parsed, _ := url.Parse("https://example.com")

	connPool := NewRequestConnPool(context.Background())

	var (
		c   *Conn
		err error
	)

	if c, err = connPool.Get(parsed); err != nil {
		t.Fatal(err)
	}

	if err = c.assignProxy("http://localhost:8888"); err != nil {
		t.Fatal(err)
	}

	_, _, err = c.proxyDialer.initProxyConn(context.Background(), "tcp")

	if err != nil {
		skipProxy = true
	}
}

func TestProxy(t *testing.T) {
	if skipProxy {
		t.Skip("TestProxy skipped")
	}

	session := NewSession()

	response, err := session.Get("https://api.ipify.org/")

	if err != nil {
		t.Fatal(err)
	}

	oldIP := string(response.Body)

	session.InsecureSkipVerify = true

	session.SetProxy("http://localhost:8888")

	response, err = session.Get("https://api.ipify.org/")

	if err != nil {
		t.Fatal(err)
	}

	newIP := string(response.Body)

	if oldIP == newIP {
		t.Fatal("TestProxy failed, IP is not changed")
	}
}
