package azuretls_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/Noooste/azuretls-client"
	http "github.com/Noooste/fhttp"
	"log"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestNewSession(t *testing.T) {
	session := azuretls.NewSession()
	if session == nil {
		t.Fatal("session is nil")
	}
}

func testProxy(t *testing.T, session *azuretls.Session, proxy string, expected ...string) {
	err := session.SetProxy(proxy)

	if err != nil {
		t.Fatal(err)
		return
	}

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
	s := azuretls.NewSession()
	testProxy(t, s, "http://username:password@ip:9999")
	testProxy(t, s, "http://ip:9999")
	testProxy(t, s, "http://username:password@ip")
	testProxy(t, s, "ip:9999:username:password", "http://username:password@ip:9999")
	testProxy(t, s, "username:password:ip:9999", "http://username:password@ip:9999")
	testProxy(t, s, "username:password@ip:9999", "http://username:password@ip:9999")
	testProxy(t, s, "ip:9999", "http://ip:9999")
}

func TestSession_Ip(t *testing.T) {
	t.SkipNow()

	session := azuretls.NewSession()

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
	session := azuretls.NewSession()
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

	now := time.Now()
	_, err := session.Get("https://httpbin.org/delay/5")
	fmt.Println(time.Since(now))

	if err == nil || (err.Error() != "timeout" && !strings.Contains(err.Error(), "timeout")) {
		t.Fatal("TestSession_SetTimeout failed, expected: timeout, got: ", err)
		return
	}

	session.SetTimeout(30 * time.Second)
	if session.Transport.TLSHandshakeTimeout != 30*time.Second || session.Transport.ResponseHeaderTimeout != 30*time.Second {
		t.Fatal(
			"TestSession_SetTimeout failed, expected: timeout, got: 30*time.Second",
			session.Transport.TLSHandshakeTimeout, "and", session.Transport.ResponseHeaderTimeout)
	}
}

func TestNewSessionWithContext(t *testing.T) {
	req := &azuretls.Request{
		Method: http.MethodGet,
		Url:    "https://httpbin.org/delay/5",
	}

	ctx := context.Background()

	var cancel context.CancelFunc

	ctx, cancel = context.WithTimeout(ctx, 500*time.Millisecond)
	session := azuretls.NewSessionWithContext(ctx)
	defer cancel()

	_, err := session.Do(req)

	if err == nil || !(strings.Contains(err.Error(), "timeout") || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) {
		t.Fatal("TestSession_SetTimeout failed, expected: timeout, got: ", err)
		return
	}

}

func TestNewSessionWithContext2(t *testing.T) {
	req := &azuretls.Request{
		Method: http.MethodGet,
		Url:    "https://httpbin.org/delay/5",
	}

	ctx := context.Background()

	var cancel context.CancelFunc

	ctx, cancel = context.WithCancel(ctx)

	time.AfterFunc(1*time.Second, func() {
		cancel()
	})

	session := azuretls.NewSession()

	session.SetContext(ctx)

	_, err := session.Do(req)

	if err == nil || !(err.Error() == "timeout" || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) {
		t.Fatal("TestSession_SetTimeout failed, expected: timeout, got: ", err)
		return
	}
}

func TestSession_Post(t *testing.T) {
	session := azuretls.NewSession()
	session.Browser = azuretls.Firefox

	req := &azuretls.Request{
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
	session := azuretls.NewSession()
	session.Browser = azuretls.Firefox

	req := &azuretls.Request{
		Method: http.MethodPost,
		Url:    "https://httpbin.org/post",
		Body:   "test",
	}

	session.PreHook = func(req *azuretls.Request) error {
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
	session := azuretls.NewSession()
	session.Browser = azuretls.Firefox

	req := &azuretls.Request{
		Method: http.MethodPost,
		Url:    "https://httpbin.org/post",
		Body:   "test",
	}

	session.PreHook = func(req *azuretls.Request) error {
		return errors.New("test")
	}

	_, err := session.Do(req)
	if err == nil {
		t.Fatal("TestSessionPrehookError failed, expected: error, got: nil")
		return
	}

	session.PreHook = nil
	session.PreHookWithContext = func(ctx *azuretls.Context) error {
		return errors.New("test")
	}

	_, err = session.Do(req)
	if err == nil {
		t.Fatal("TestSessionPrehookError failed, expected: error, got: nil")
		return
	}
}

func TestSessionCallback(t *testing.T) {
	session := azuretls.NewSession()
	session.Browser = azuretls.Firefox

	req := &azuretls.Request{
		Method: http.MethodPost,
		Url:    "https://www.google.com",
		Body:   "test",
	}

	var called bool
	var withContextCalled bool

	session.Callback = func(req *azuretls.Request, resp *azuretls.Response, err error) {
		called = true
	}

	session.CallbackWithContext = func(ctx *azuretls.Context) {
		withContextCalled = true
		if ctx.Response.Url == "https://www.google.com" {
			response, _ := session.Get("https://httpbin.org/get")
			ctx.Response = response
		}
	}

	response, err := session.Do(req)
	if err != nil {
		t.Fatal("TestSessionCallback failed, expected: nil, got: ", err)
		return
	}

	if response.Url != "https://httpbin.org/get" {
		t.Fatal("TestSessionCallback failed, expected: https://httpbin.org/get, got: ", response.Url)
		return
	}

	if !called {
		t.Fatal("TestSessionCallback failed, expected: called, got: ", called)
		return
	}

	if !withContextCalled {
		t.Fatal("TestSessionCallback failed, expected: called, got: ", withContextCalled)
		return
	}

	session.CallbackWithContext = func(ctx *azuretls.Context) {
		ctx.Err = errors.New("test")
	}

	_, err = session.Do(req)

	if err == nil {
		t.Fatal("TestSessionCallback failed, expected: error, got: nil")
		return
	}
}

func TestSession_Put(t *testing.T) {
	session := azuretls.NewSession()
	session.Browser = azuretls.Firefox

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
	session := azuretls.NewSession()
	session.Browser = azuretls.Firefox

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
	session := azuretls.NewSession()
	session.Browser = azuretls.Firefox

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
	session := azuretls.NewSession()
	session.Browser = azuretls.Firefox

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
	session := azuretls.NewSession()
	session.Browser = azuretls.Firefox

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
	/*
		session := azuretls.NewSession()
		session.Browser = azuretls.Firefox

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

		conn2 := session.Connections.Get(&url.URL{
			Scheme: "https",
			Host:   "httpbin.org",
		})

		if conn2 != conn {
			t.Fatal("TestSession_Connect failed, expected: same connection, got: ", conn2)
			return
		}

		session.Close()
	*/
}

func TestSession_TooManyRedirects(t *testing.T) {
	session := azuretls.NewSession()

	resp, err := session.Get("https://httpbin.org/redirect/11")

	if err == nil || !errors.Is(err, azuretls.ErrTooManyRedirects) {
		t.Fatal("TestSession_TooManyRedirects failed, expected: too many Redirects, got: ", err)
		return
	}

	if resp != nil {
		t.Fatal("TestSession_TooManyRedirects failed, expected: nil, got: ", resp)
		return
	}

	session.MaxRedirects = 1

	resp, err = session.Get("https://httpbin.org/redirect/2")

	if err == nil || !errors.Is(err, azuretls.ErrTooManyRedirects) {
		t.Fatal("TestSession_TooManyRedirects failed, expected: too many Redirects, got: ", err)
		return
	}

	if resp != nil {
		t.Fatal("TestSession_TooManyRedirects failed, expected: nil, got: ", resp)
		return
	}
}

func TestSession_SetContext(t *testing.T) {
	/*
		session := azuretls.NewSession()
		session.Get("https://httpbin.org/get")

		conn := session.Connections.Get(&url.URL{
			Scheme: "https",
			Host:   "httpbin.org",
		})

		if conn == nil {
			t.Fatal("TestSession_SetContext failed, expected: not nil, got: ", conn)
			return
		}

		ctx := context.Background()

		conn.SetContext(ctx)

		if conn.GetContext() != ctx {
			t.Fatal("TestSession_SetContext failed, expected: ", ctx, ", got: ", conn.GetContext())
			return
		}

		session.Connections.Remove(&url.URL{
			Scheme: "https",
			Host:   "httpbin.org",
		})

		if session.Connections.Get(&url.URL{
			Scheme: "https",
			Host:   "httpbin.org",
		}) == conn {
			t.Fatal("TestSession_SetContext failed, expected: nil, got: not nil")
			return
		}

		session.Connections.Set(&url.URL{
			Scheme: "https",
			Host:   "httpbin.org",
		}, conn)

		if getConn := session.Connections.Get(&url.URL{
			Scheme: "https",
			Host:   "httpbin.org",
		}); getConn != conn {
			t.Fatal("TestSession_SetContext failed, expected: ", conn, ", got: ", getConn)
			return
		}

		session.Get("https://httpbin.org/get")

		if conn.GetContext() != ctx {
			t.Fatal("TestSession_SetContext failed, expected: ", ctx, ", got: ", conn.GetContext())
			return
		}
	*/
}

func TestSession_ContextError(t *testing.T) {
	exampleContext, ca := context.WithCancel(context.Background())
	defer ca()

	session := azuretls.NewSessionWithContext(exampleContext)

	session.CallbackWithContext = func(ctx *azuretls.Context) {
		exampleContextFromCtx := ctx.Context()
		if exampleContextFromCtx == exampleContext {
			fmt.Println("match")
		} else {
			fmt.Println("no match")
			session1 := azuretls.NewSessionWithContext(exampleContextFromCtx)
			_, err := session1.Get("https://httpbin.org/headers")

			if err != nil {
				log.Fatal(err)
			}
		}
	}

	_, _ = session.Get("https://httpbin.org/headers")
}

func TestSession_Timeout(t *testing.T) {
	session := azuretls.NewSession()
	defer session.Close()

	err := session.ApplyJa3("771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-16-5-34-51-43-13-45-28-65037,29-23-24-25-256-257,0", azuretls.Firefox)
	if err != nil {
		log.Fatal(err)
		return
	}

	err = session.ApplyHTTP2("1:65536,4:131072,5:16384|12517377|3:0:0:201,5:0:0:101,7:0:0:1,9:0:7:1,11:0:3:1,13:0:0:241|m,p,a,s")
	if err != nil {
		log.Fatal(err)
		return
	}

	response, err := session.Get("https://www.cloudflare.com/cdn-cgi/trace")

	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println(response.StatusCode, string(response.Body))
	}
}

func TestSession_Timeout2(t *testing.T) {
	var err error

	wg := &sync.WaitGroup{}
	wg.Add(1)

	go func() {
		defer wg.Done()
		session := azuretls.NewSession()
		session.Log()
		defer session.Close()

		session.SetTimeout(1 * time.Second)

		_, err = session.Get("https://testfile.org/files-5GB")
	}()

	wg.Wait()

	if err == nil {
		t.Fatal("TestSession_Timeout2 failed, expected: error, got: nil")
		return
	}

	if err.Error() != "timeout" {
		t.Fatal("TestSession_Timeout2 failed, expected: timeout, got:", err)
		return
	}
}
