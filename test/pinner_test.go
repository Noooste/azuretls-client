package azuretls_test

import (
	"github.com/Noooste/azuretls-client"
	"net/url"
	"strings"
	"testing"
)

func TestPins(t *testing.T) {
	session := azuretls.NewSession()

	_, err := session.Get("https://example.com")

	if err != nil {
		t.Fatal(err)
	}
}

func TestSession_AddPins2(t *testing.T) {
	session := azuretls.NewSession()
	session.PinManager = azuretls.NewPinManager() // use a specific one to test pinning

	if err := session.AddPins(&url.URL{
		Scheme: "https",
		Host:   "example.com",
	}, []string{
		"not a good pin here",
	}); err != nil {
		t.Fatal("TestPins failed, expected: error, got: ", err)
	}

	_, err := session.Get("https://example.com")

	if err != nil && !strings.Contains(err.Error(), "pin verification failed") {
		t.Fatal("TestPins failed, expected: pin verification failed, got: ", err)
	} else if err == nil {
		t.Fatal("TestPins failed, expected: pin verification failed, got: ", err)
	}
}

func TestSession_ClearPins(t *testing.T) {
	session := azuretls.NewSession()

	if err := session.AddPins(&url.URL{
		Scheme: "https",
		Host:   "example.com",
	}, []string{
		"RQeZkB42znUfsDIIFWIRiYEcKl7nHwNFwWCrnMMJbVc=",
		"Xs+pjRp23QkmXeH31KEAjM1aWvxpHT6vYy+q2ltqtaM=",
	}); err != nil {
		t.Fatal("TestPins failed, expected: nothing wrong, got: ", err)
	}

	if err := session.ClearPins(&url.URL{
		Scheme: "https",
		Host:   "example.com",
	}); err != nil {
		t.Fatal("TestPins failed, expected: nothing wrong, got: ", err)
	}

	_, err := session.Get("https://example.com")

	if err != nil {
		t.Fatal("TestPins failed, expected: nothing wrong, got: ", err)
	}
}
