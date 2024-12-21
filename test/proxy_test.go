package azuretls

import (
	"github.com/Noooste/azuretls-client"
	http "github.com/Noooste/fhttp"
	"os"
	"testing"
)

func testAssignProxy(t *testing.T, proxy string) {
	s := azuretls.NewSession()
	defer s.Close()

	err := s.SetProxy(proxy)

	if err != nil {
		t.Fatal("TestProxyDialer failed with ", proxy, ", expected: ", nil, ", got: ", err)
		return
	}
}

func TestGoodProxyFormat(t *testing.T) {
	testAssignProxy(t, "http://username:password@aaaaa:9999")
	testAssignProxy(t, "http://username:password@aaaaa")
	testAssignProxy(t, "http://aaaaa:9999")
	testAssignProxy(t, "http://aaaaa")
	testAssignProxy(t, "https://aaaaa")
	testAssignProxy(t, "socks5://aaaaa:9999")
	testAssignProxy(t, "socks5://aaaaa")
	testAssignProxy(t, "socks5h://aaaaa:9999")
	testAssignProxy(t, "socks5h://aaaaa")
	testAssignProxy(t, "aaaaa")
}

func testAssignBadProxy(t *testing.T, proxy string) {
	s := azuretls.NewSession()
	defer s.Close()

	err := s.SetProxy(proxy)

	if err == nil {
		t.Fatal("TestProxyDialer failed with ", proxy, ", expected: ", "error", ", got: ", nil)
		return
	}
}

func TestBadProxyFormat(t *testing.T) {
	testAssignBadProxy(t, "unsupported-scheme://username")
	testAssignBadProxy(t, "://,")
	testAssignBadProxy(t, "http://only_username@aaaaa:9999:9999")
	testAssignBadProxy(t, "")
}

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

	session.ProxyHeader = http.Header{
		"User-Agent":        []string{"Mozilla/5.0"},
		http.HeaderOrderKey: []string{"User-Agent"},
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

	session.ProxyHeader = http.Header{
		"User-Agent": []string{"Mozilla/5.0"},
	}

	ipAfter, err := session.Ip()

	if err != nil {
		t.Fatal(err)
	}

	if ip == ipAfter {
		t.Fatal("Proxy is not working")
	}
}

func TestSOCKSProxy(t *testing.T) {
	session := azuretls.NewSession()
	defer session.Close()

	ip, err := session.Ip()

	if err != nil {
		t.Fatal(err)
	}

	if os.Getenv("SOCKS5_PROXY") == "" {
		t.Skip("SOCKS5_PROXY is not set")
	}

	if err = session.SetProxy(os.Getenv("SOCKS5_PROXY")); err != nil {
		t.Fatal(err)
	}

	session.ProxyHeader = http.Header{
		"User-Agent": []string{"Mozilla/5.0"},
	}

	ipAfter, err := session.Ip()

	if err != nil {
		t.Fatal(err)
	}

	if ip == ipAfter {
		t.Fatal("Proxy is not working")
	}
}
