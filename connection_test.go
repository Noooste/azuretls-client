package azuretls

import (
	"runtime"
	"sync"
	"testing"
	"time"
)

func TestSessionConn(t *testing.T) {
	runtime.GOMAXPROCS(runtime.NumCPU())

	session := NewSession()

	response, err := session.Get("https://example.com/")

	if err != nil {
		t.Fatal(err)
	}

	if response.StatusCode != 200 {
		t.Fatal("TestHeader failed, expected: 200, got: ", response.StatusCode)
	}

	if len(session.Connections.hosts) == 0 {
		t.Fatal("TestSessionConn failed, Conn is empty")
	}

	firstConn := session.Connections.hosts["example.com:443"]

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

	if len(session.Connections.hosts) != 1 {
		t.Fatal("TestSessionConn failed, Conn is not reused")
	}

	if firstConn != session.Connections.hosts["example.com:443"] {
		t.Fatal("TestSessionConn failed, Conn is not reused")
	}
}

func TestHTTP1Conn(t *testing.T) {
	session := NewSession()

	_, err := session.Get("https://api.ipify.org/")

	if err != nil {
		t.Fatal(err)
	}
}

func TestHighConcurrency(t *testing.T) {
	session := NewSession()

	wait := &sync.WaitGroup{}

	count := 100

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

func TestConnContext(t *testing.T) {
	session := NewSession()

	_, err := session.Do(&Request{
		Method:  "GET",
		Url:     "https://example.com/",
		TimeOut: 1 * time.Second,
	})

	if err != nil {
		t.Fatal(err)
	}

	if session.Connections.hosts["example.com:443"].ctx != session.ctx {
		t.Fatal("TestConnContext failed, expected: ", session.ctx, ", got: ", session.Connections.hosts["example.com:443"].ctx)
	}

	select {
	case <-time.After(2 * time.Second):
		_, err := session.Get("https://example.com/")

		if err != nil {
			t.Fatal(err)
		}

		if session.Connections.hosts["example.com:443"].ctx != session.ctx {
			t.Fatal("TestConnContext failed, expected: ", session.ctx, ", got: ", session.Connections.hosts["example.com:443"].ctx)
		}
	}
}
