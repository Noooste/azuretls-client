package azuretls

import (
	"context"
	http "github.com/Noooste/fhttp"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestNewSession(t *testing.T) {
	runtime.GOMAXPROCS(runtime.NumCPU())
	t.Parallel()

	session := NewSession()
	if session == nil {
		t.Error("session is nil")
		t.SkipNow()
	}
}

func testProxy(t *testing.T, session *Session, proxy string, expected ...string) {
	session.SetProxy(proxy)
	if len(expected) > 0 {
		if session.Proxy != expected[0] {
			t.Error("TestSession_SetProxy failed, expected: ", expected[0], ", got: ", session.Proxy)
		}
	} else {
		if session.Proxy != proxy {
			t.Error("TestSession_SetProxy failed, expected: ", proxy, ", got: ", session.Proxy)
		}
	}
}

func TestSession_SetProxy(t *testing.T) {
	t.Parallel()

	session := NewSession()
	testProxy(t, session, "http://username:password@ip:9999")
	testProxy(t, session, "http://ip:9999")
	testProxy(t, session, "http://username:password@ip")
	testProxy(t, session, "ip:9999:username:password", "http://username:password@ip:9999")
	testProxy(t, session, "ip:9999", "http://ip:9999")
}

func TestSession_SetTimeout(t *testing.T) {
	t.Parallel()

	session := NewSession()
	session.SetTimeout(10 * time.Second)
	if session.TimeOut != 10*time.Second {
		t.Error("TestSession_SetTimeout failed, expected: ", 10*time.Second, ", got: ", session.TimeOut)
	}

	session.SetTimeout(0)
	if session.TimeOut != 0 {
		t.Error("TestSession_SetTimeout failed, expected: ", 0, ", got: ", session.TimeOut)
	}

	session.SetTimeout(500 * time.Millisecond)

	_, err := session.Get("https://httpbin.org/delay/5")

	if err == nil || (err.Error() != "timeout" && !strings.Contains(err.Error(), "timeout")) {
		t.Error("TestSession_SetTimeout failed, expected: timeout, got: ", err)
	}
}

func TestNewSessionWithContext(t *testing.T) {
	t.Parallel()

	req := &Request{
		Method: http.MethodGet,
		Url:    "https://httpbin.org/delay/5",
	}

	ctx := context.Background()

	var cancel context.CancelFunc

	ctx, cancel = context.WithTimeout(ctx, 500*time.Millisecond)
	session := NewSessionWithContext(ctx)

	_, err := session.Do(req)

	if err == nil || err.Error() != "timeout" {
		t.Error("TestSession_SetTimeout failed, expected: timeout, got: ", err)
	}

	cancel()
}

func TestNewSessionWithContext2(t *testing.T) {
	t.Parallel()

	req := &Request{
		Method: http.MethodGet,
		Url:    "https://httpbin.org/delay/5",
	}

	ctx := context.Background()

	var cancel context.CancelFunc

	ctx, cancel = context.WithCancel(ctx)

	go func() {
		time.Sleep(1 * time.Second)
		cancel()
	}()

	session := NewSessionWithContext(ctx)

	_, err := session.Do(req)

	if err == nil || err.Error() != "timeout" {
		t.Error("TestSession_SetTimeout failed, expected: timeout, got: ", err)
	}
}
