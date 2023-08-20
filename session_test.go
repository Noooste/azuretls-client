package azuretls

import (
	"bytes"
	"context"
	"errors"
	http "github.com/Noooste/fhttp"
	"strings"
	"testing"
	"time"
)

func TestNewSession(t *testing.T) {
	session := NewSession()
	if session == nil {
		t.Fatal("session is nil")
	}
}

func testProxy(t *testing.T, session *Session, proxy string, expected ...string) {
	session.SetProxy(proxy)
	if len(expected) > 0 {
		if session.Proxy != expected[0] {
			t.Fatal("TestSession_SetProxy failed, expected: ", expected[0], ", got: ", session.Proxy)
			return
		}
	} else {
		if session.Proxy != proxy {
			t.Fatal("TestSession_SetProxy failed, expected: ", proxy, ", got: ", session.Proxy)
			return
		}
	}
}

func TestSession_SetProxy(t *testing.T) {
	s := NewSession()
	testProxy(t, s, "http://username:password@ip:9999")
	testProxy(t, s, "http://ip:9999")
	testProxy(t, s, "http://username:password@ip")
	testProxy(t, s, "ip:9999:username:password", "http://username:password@ip:9999")
	testProxy(t, s, "username:password:ip:9999", "http://username:password@ip:9999")
	testProxy(t, s, "username:password@ip:9999", "http://username:password@ip:9999")
	testProxy(t, s, "qqqqqq", "")
	testProxy(t, s, "ip:9999", "http://ip:9999")
}

func TestSession_Ip(t *testing.T) {
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

	ip, err := session.Ip()

	if err != nil {
		t.Fatal(err)
	}

	if oldIP == ip {
		t.Fatal("TestProxy failed, IP is not changed")
	}
}

func TestSession_SetTimeout(t *testing.T) {
	session := NewSession()
	session.SetTimeout(10 * time.Second)
	if session.TimeOut != 10*time.Second {
		t.Fatal("TestSession_SetTimeout failed, expected: ", 10*time.Second, ", got: ", session.TimeOut)
		return
	}

	session.SetTimeout(0)
	if session.TimeOut != 0 {
		t.Fatal("TestSession_SetTimeout failed, expected: ", 0, ", got: ", session.TimeOut)
		return
	}

	session.SetTimeout(500 * time.Millisecond)

	_, err := session.Get("https://httpbin.org/delay/5")

	if err == nil || (err.Error() != "timeout" && !strings.Contains(err.Error(), "timeout")) {
		t.Fatal("TestSession_SetTimeout failed, expected: timeout, got: ", err)
		return
	}
}

func TestNewSessionWithContext(t *testing.T) {
	req := &Request{
		Method: http.MethodGet,
		Url:    "https://httpbin.org/delay/5",
	}

	ctx := context.Background()

	var cancel context.CancelFunc

	ctx, cancel = context.WithTimeout(ctx, 500*time.Millisecond)
	session := NewSessionWithContext(ctx)
	defer cancel()

	_, err := session.Do(req)

	if err == nil || !(strings.Contains(err.Error(), "timeout") || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) {
		t.Fatal("TestSession_SetTimeout failed, expected: timeout, got: ", err)
		return
	}

}

func TestNewSessionWithContext2(t *testing.T) {
	req := &Request{
		Method: http.MethodGet,
		Url:    "https://httpbin.org/delay/5",
	}

	ctx := context.Background()

	var cancel context.CancelFunc

	ctx, cancel = context.WithCancel(ctx)

	time.AfterFunc(1*time.Second, func() {
		cancel()
	})

	session := NewSessionWithContext(ctx)

	_, err := session.Do(req)

	if err == nil || err.Error() != "timeout" {
		t.Fatal("TestSession_SetTimeout failed, expected: timeout, got: ", err)
		return
	}
}

func TestSession_Post(t *testing.T) {
	session := NewSession()
	req := &Request{
		Method: http.MethodPost,
		Url:    "https://httpbin.org/post",
		Body:   "test",
	}

	resp, err := session.Do(req)
	if err != nil {
		t.Fatal("TestSession_Post failed, expected: nil, got: ", err)
		return
	}

	if resp.StatusCode != 200 {
		t.Fatal("TestSession_Post failed, expected: 200, got: ", resp.StatusCode)
		return
	}

	if resp.Body == nil {
		t.Fatal("TestSession_Post failed, expected: not nil, got: ", resp.Body)
		return
	}

	if !bytes.Contains(resp.Body, []byte("test")) {
		t.Fatal("TestSession_Post failed, expected: not contains, got: ", resp.Body)
		return
	}
}
