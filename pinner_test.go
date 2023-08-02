package azuretls

import (
	"net/url"
	"testing"
)

func TestPins(t *testing.T) {
	session := NewSession()

	_, err := session.Get("https://example.com")

	if err != nil {
		t.Fatal(err)
	}

	if len(session.Connections.hosts) == 0 {
		t.Fatal("TestPins failed, Conn is empty")
	}

	if len(session.Connections.hosts["example.com:443"].Pins.m) == 0 {
		t.Fatal("TestPins failed, Pins is empty")
	}
}

func TestPins2(t *testing.T) {
	session := NewSession()

	session.SetProxy("http://localhost:8888")

	_, err := session.Get("https://example.com")

	if err != nil && err.Error() != "pin verification failed" {
		t.Fatal("TestPins failed, expected: pin verification failed, got: ", err)
	} else if err == nil {
		t.Fatal("TestPins failed, expected: pin verification failed, got: ", err)
	}
}

func TestSession_AddPins(t *testing.T) {
	session := NewSession()

	if err := session.AddPins(&url.URL{
		Scheme: "https",
		Host:   "example.com",
	}, []string{
		"RQeZkB42znUfsDIIFWIRiYEcKl7nHwNFwWCrnMMJbVc=",
		"Xs+pjRp23QkmXeH31KEAjM1aWvxpHT6vYy+q2ltqtaM=",
	}); err != nil {
		t.Fatal("TestPins failed, expected: nothing wrong, got: ", err)
	}

	_, err := session.Get("https://example.com")

	if err != nil {
		t.Fatal("TestPins failed, expected: nothing wrong, got: ", err)
	}
}

func TestSession_AddPins2(t *testing.T) {
	session := NewSession()

	if err := session.AddPins(&url.URL{
		Scheme: "https",
		Host:   "example.com",
	}, []string{
		"not a good pin here",
	}); err != nil {
		t.Fatal("TestPins failed, expected: error, got: ", err)
	}

	_, err := session.Get("https://example.com")

	if err != nil && err.Error() != "pin verification failed" {
		t.Fatal("TestPins failed, expected: pin verification failed, got: ", err)
	} else if err == nil {
		t.Fatal("TestPins failed, expected: pin verification failed, got: ", err)
	}
}
