package azuretls

import (
	"github.com/Noooste/azuretls-client"
	"os"
	"testing"
)

func TestHTTPProxy(t *testing.T) {
	session := azuretls.NewSession()
	defer session.Close()

	ip, err := session.Ip()

	if err != nil {
		t.Fatal(err)
	}

	if os.Getenv("NON_SECURE_PROXY") == "" {
		t.Skip("NON_SECURE_PROXY is not set")
	}

	if err = session.SetProxy(os.Getenv("NON_SECURE_PROXY")); err != nil {
		t.Fatal(err)
	}

	ipAfter, err := session.Ip()

	if err != nil {
		t.Fatal(err)
	}

	if ip == ipAfter {
		t.Fatal("Proxy is not working")
	}
}

func TestHTTPSProxy(t *testing.T) {
	session := azuretls.NewSession()
	defer session.Close()

	ip, err := session.Ip()

	if err != nil {
		t.Fatal(err)
	}

	if os.Getenv("SECURE_PROXY") == "" {
		t.Skip("SECURE_PROXY is not set")
	}

	if err = session.SetProxy(os.Getenv("SECURE_PROXY")); err != nil {
		t.Fatal(err)
	}

	ipAfter, err := session.Ip()

	if err != nil {
		t.Fatal(err)
	}

	if ip == ipAfter {
		t.Fatal("Proxy is not working")
	}
}
