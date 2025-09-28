package azuretls_test

import (
	"testing"
	"time"

	"github.com/Noooste/azuretls-client"
	"github.com/Noooste/azuretls-client/test/utils"
)

func TestSocks4ProxyServer(t *testing.T) {
	// Start SOCKS4 proxy server on random port
	server, addr, err := utils.StartSocks4ProxyServerOnRandomPort()
	if err != nil {
		t.Fatalf("Failed to start SOCKS4 proxy server: %v", err)
	}
	defer server.Stop()

	// Wait a moment for server to be ready
	time.Sleep(100 * time.Millisecond)

	// Create session with SOCKS4 proxy
	session := azuretls.NewSession()
	session.InsecureSkipVerify = true
	defer session.Close()

	err = session.SetProxy("socks4://" + addr)
	if err != nil {
		t.Fatalf("Failed to set SOCKS4 proxy: %v", err)
	}

	// Test request through SOCKS4 proxy
	response, err := session.Get("https://expired.badssl.com/")
	if err != nil {
		t.Fatalf("Failed to make request through SOCKS4 proxy: %v", err)
	}

	if response.StatusCode != 200 {
		t.Fatalf("Expected status code 200, got %d", response.StatusCode)
	}

	t.Logf("Successfully made request through SOCKS4 proxy. Response: %s", string(response.Body))
}

func TestSocks4ProxyServerHTTPS(t *testing.T) {
	// Start SOCKS4 proxy server on random port
	server, addr, err := utils.StartSocks4ProxyServerOnRandomPort()
	if err != nil {
		t.Fatalf("Failed to start SOCKS4 proxy server: %v", err)
	}
	defer server.Stop()

	// Wait a moment for server to be ready
	time.Sleep(100 * time.Millisecond)

	// Create session with SOCKS4 proxy
	session := azuretls.NewSession()
	defer session.Close()

	err = session.SetProxy("socks4://" + addr)
	if err != nil {
		t.Fatalf("Failed to set SOCKS4 proxy: %v", err)
	}

	// Test HTTPS request through SOCKS4 proxy
	response, err := session.Get("https://httpbingo.org/ip")
	if err != nil {
		t.Fatalf("Failed to make HTTPS request through SOCKS4 proxy: %v", err)
	}

	if response.StatusCode != 200 {
		t.Fatalf("Expected status code 200, got %d", response.StatusCode)
	}

	t.Logf("Successfully made HTTPS request through SOCKS4 proxy. Response: %s", string(response.Body))
}
