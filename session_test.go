package azuretls

import (
	"bytes"
	"context"
	"errors"
	http "github.com/Noooste/fhttp"
	"net/url"
	"os"
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

	if err = session.SetProxy(os.Getenv("NON_SECURE_PROXY")); err != nil {
		t.Fatal(err)
	}

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

	session.SetTimeout(30 * time.Second)
	if session.tr.TLSHandshakeTimeout != 30*time.Second || session.tr.ResponseHeaderTimeout != 30*time.Second {
		t.Fatal("TestSession_SetTimeout failed, expected: timeout, got: 30*time.Second", session.tr.TLSHandshakeTimeout, "and", session.tr.ResponseHeaderTimeout)
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

	session := NewSession()

	session.SetContext(ctx)

	_, err := session.Do(req)

	if err == nil || !(err.Error() == "timeout" || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) {
		t.Fatal("TestSession_SetTimeout failed, expected: timeout, got: ", err)
		return
	}
}

func TestSession_Post(t *testing.T) {
	session := NewSession()
	session.Browser = Firefox

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

func TestSessionPreHook(t *testing.T) {
	session := NewSession()
	session.Browser = Firefox

	req := &Request{
		Method: http.MethodPost,
		Url:    "https://httpbin.org/post",
		Body:   "test",
	}

	session.PreHook = func(req *Request) error {
		req.OrderedHeaders = append(req.OrderedHeaders, []string{"X-Test", "test"})
		return nil
	}

	resp, err := session.Do(req)
	if err != nil {
		t.Fatal("TestSessionPreHook failed, expected: nil, got: ", err)
		return
	}

	if resp.StatusCode != 200 {
		t.Fatal("TestSessionPreHook failed, expected: 200, got: ", resp.StatusCode)
		return
	}

	if resp.Body == nil {
		t.Fatal("TestSessionPreHook failed, expected: not nil, got: ", resp.Body)
		return
	}

	if !bytes.Contains(resp.Body, []byte("test")) {
		t.Fatal("TestSessionPreHook failed, expected: not contains, got: ", resp.Body)
		return
	}

	if !bytes.Contains(resp.Body, []byte("X-Test")) {
		t.Fatal("TestSessionPreHook failed, expected: not contains, got: ", resp.Body)
		return
	}
}

func TestSessionPrehookError(t *testing.T) {
	session := NewSession()
	session.Browser = Firefox

	req := &Request{
		Method: http.MethodPost,
		Url:    "https://httpbin.org/post",
		Body:   "test",
	}

	session.PreHook = func(req *Request) error {
		return errors.New("test")
	}

	_, err := session.Do(req)
	if err == nil {
		t.Fatal("TestSessionPrehookError failed, expected: error, got: nil")
		return
	}
}

func TestSessionCallback(t *testing.T) {
	session := NewSession()
	session.Browser = Firefox

	req := &Request{
		Method: http.MethodPost,
		Url:    "https://www.google.com",
		Body:   "test",
	}

	var called bool

	session.Callback = func(req *Request, resp *Response, err error) {
		called = true
	}

	_, err := session.Do(req)
	if err != nil {
		t.Fatal("TestSessionCallback failed, expected: nil, got: ", err)
		return
	}

	if !called {
		t.Fatal("TestSessionCallback failed, expected: called, got: ", called)
		return
	}
}

func TestSession_Put(t *testing.T) {
	session := NewSession()
	session.Browser = Firefox

	resp, err := session.Put("https://httpbin.org/put", "test")
	if err != nil {
		t.Fatal("TestSession_Put failed, expected: nil, got: ", err)
		return
	}

	if resp.StatusCode != 200 {
		t.Fatal("TestSession_Put failed, expected: 200, got: ", resp.StatusCode)
		return
	}

	if resp.Body == nil {
		t.Fatal("TestSession_Put failed, expected: not nil, got: ", resp.Body)
		return
	}

	if !bytes.Contains(resp.Body, []byte("test")) {
		t.Fatal("TestSession_Put failed, expected: not contains, got: ", resp.Body)
		return
	}
}

func TestSession_Delete(t *testing.T) {
	session := NewSession()
	session.Browser = Firefox

	resp, err := session.Delete("https://httpbin.org/delete", "test")
	if err != nil {
		t.Fatal("TestSession_Delete failed, expected: nil, got: ", err)
		return
	}

	if resp.StatusCode != 200 {
		t.Fatal("TestSession_Delete failed, expected: 200, got: ", resp.StatusCode)
		return
	}

	if resp.Body == nil {
		t.Fatal("TestSession_Delete failed, expected: not nil, got: ", resp.Body)
		return
	}

	if !bytes.Contains(resp.Body, []byte("test")) {
		t.Fatal("TestSession_Delete failed, expected: not contains, got: ", resp.Body)
		return
	}
}

func TestSession_Patch(t *testing.T) {
	session := NewSession()
	session.Browser = Firefox

	resp, err := session.Patch("https://httpbin.org/patch", "test")
	if err != nil {
		t.Fatal("TestSession_Patch failed, expected: nil, got: ", err)
		return
	}

	if resp.StatusCode != 200 {
		t.Fatal("TestSession_Patch failed, expected: 200, got: ", resp.StatusCode)
		return
	}

	if resp.Body == nil {
		t.Fatal("TestSession_Patch failed, expected: not nil, got: ", resp.Body)
		return
	}

	if !bytes.Contains(resp.Body, []byte("test")) {
		t.Fatal("TestSession_Patch failed, expected: not contains, got: ", resp.Body)
		return
	}
}

func TestSession_Head(t *testing.T) {
	session := NewSession()
	session.Browser = Firefox

	resp, err := session.Head("https://httpbin.org/get")
	if err != nil {
		t.Fatal("TestSession_Head failed, expected: nil, got: ", err)
		return
	}

	if resp.StatusCode != 200 {
		t.Fatal("TestSession_Head failed, expected: 200, got: ", resp.StatusCode)
		return
	}

	if resp.Body != nil {
		t.Fatal("TestSession_Head failed, expected: nil, got: ", resp.Body)
		return
	}
}

func TestSession_Options(t *testing.T) {
	session := NewSession()
	session.Browser = Firefox

	resp, err := session.Options("https://httpbin.org/get", "test")
	if err != nil {
		t.Fatal("TestSession_Options failed, expected: nil, got: ", err)
		return
	}

	if resp.StatusCode != 200 {
		t.Fatal("TestSession_Options failed, expected: 200, got: ", resp.StatusCode)
		return
	}

	if resp.Body == nil {
		t.Fatal("TestSession_Options failed, expected: not nil, got: ", resp.Body)
		return
	}
}

func TestSession_Connect(t *testing.T) {
	session := NewSession()
	session.Browser = Firefox

	err := session.Connect("https://httpbin.org/get")

	if err != nil {
		t.Fatal("TestSession_Connect failed, expected: nil, got: ", err)
		return
	}

	conn := session.Connections.Get(&url.URL{
		Scheme: "https",
		Host:   "httpbin.org",
	})

	if conn == nil {
		t.Fatal("TestSession_Connect failed, expected: not nil, got: ", conn)
		return
	}

	resp, err := session.Get("https://httpbin.org/get")

	if resp.StatusCode != 200 {
		t.Fatal("TestSession_Options failed, expected: 200, got: ", resp.StatusCode)
		return
	}

	if resp.Body == nil {
		t.Fatal("TestSession_Options failed, expected: not nil, got: ", resp.Body)
		return
	}

	conn2 := session.Connections.Get(&url.URL{
		Scheme: "https",
		Host:   "httpbin.org",
	})

	if conn2 != conn {
		t.Fatal("TestSession_Connect failed, expected: same connection, got: ", conn2)
		return
	}

	session.Close()
}
