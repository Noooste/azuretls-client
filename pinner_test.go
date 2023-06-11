package azuretls

import "testing"

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
