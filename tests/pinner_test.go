package azuretls_tests

import (
	"github.com/Noooste/azuretls-client"
	"net/url"
	"testing"
)

func TestPins(t *testing.T) {
	if skipProxy {
		t.Skip("TestProxy skipped")
	}

	session := azuretls.NewSession()

	_, err := session.Get("https://example.com")

	if err != nil {
		t.Fatal(err)
	}

	url := &url.URL{
		Scheme: "https",
		Host:   "example.com",
	}

	if len(session.Connections.Get(url).PinManager.GetPins()) == 0 {
		t.Fatal("TestPins failed, PinManager is empty")
	}
}

func TestSession_AddPins(t *testing.T) {
	if skipProxy {
		t.Skip("TestProxy skipped")
	}

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

	_, err := session.Get("https://example.com")

	if err != nil {
		t.Fatal("TestPins failed, expected: nothing wrong, got: ", err)
	}
}

func TestSession_AddPins2(t *testing.T) {
	if skipProxy {
		t.Skip("TestProxy skipped")
	}

	session := azuretls.NewSession()

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

func TestSession_ClearPins(t *testing.T) {
	if skipProxy {
		t.Skip("TestProxy skipped")
	}

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
