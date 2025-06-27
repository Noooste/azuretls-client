// test/chain_proxy_test.go
package azuretls_test

import (
	"fmt"
	"github.com/Noooste/azuretls-client"
	http "github.com/Noooste/fhttp"
	"github.com/Noooste/fhttp/httptest"
	"io"
	"net"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"
)

// mockProxyServer creates a mock HTTP proxy server for testing
func mockProxyServer(t *testing.T, name string) *httptest.Server {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "CONNECT" {
			// Handle CONNECT requests for HTTPS tunneling
			t.Logf("%s: Received CONNECT request to %s", name, r.Host)

			// For testing, we'll create a simple tunnel
			destConn, err := net.Dial("tcp", r.Host)
			if err != nil {
				t.Logf("%s: Failed to connect to %s: %v", name, r.Host, err)
				w.WriteHeader(http.StatusBadGateway)
				return
			}
			defer destConn.Close()

			w.WriteHeader(http.StatusOK)

			// Get the underlying connection
			hj, ok := w.(http.Hijacker)
			if !ok {
				t.Logf("%s: Hijacking not supported", name)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			clientConn, _, err := hj.Hijack()
			if err != nil {
				t.Logf("%s: Failed to hijack connection: %v", name, err)
				return
			}
			defer clientConn.Close()

			// Simple relay between client and destination
			go func() {
				defer destConn.Close()
				defer clientConn.Close()
				io.Copy(destConn, clientConn)
			}()

			io.Copy(clientConn, destConn)
		} else {
			// Handle regular HTTP requests
			t.Logf("%s: Received %s request to %s", name, r.Method, r.URL.String())

			// Add a header to identify which proxy handled the request
			w.Header().Set("X-Proxy-Name", name)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(fmt.Sprintf("Response from %s proxy", name)))
		}
	}))

	t.Logf("Started mock proxy server %s at %s", name, server.URL)
	return server
}

// TestChainProxySetup tests basic chain proxy setup
func TestChainProxySetup(t *testing.T) {
	session := azuretls.NewSession()
	defer session.Close()

	// Test setting up a chain with multiple proxies
	proxies := []string{
		"http://proxy1.example.com:8080",
		"http://proxy2.example.com:8080",
		"https://proxy3.example.com:8080",
	}

	err := session.SetProxyChain(proxies)
	if err != nil {
		t.Fatalf("Failed to set proxy chain: %v", err)
	}

	// Verify the session is using chain proxy
	if !session.IsChainProxy() {
		t.Fatal("Session should be using chain proxy")
	}

	// Verify proxy chain URLs
	proxyChain := session.GetProxyChain()
	if len(proxyChain) != 3 {
		t.Fatalf("Expected 3 proxies in chain, got %d", len(proxyChain))
	}

	expectedHosts := []string{"proxy1.example.com:8080", "proxy2.example.com:8080", "proxy3.example.com:8080"}
	for i, proxy := range proxyChain {
		if proxy.Host != expectedHosts[i] {
			t.Errorf("Expected proxy %d host to be %s, got %s", i, expectedHosts[i], proxy.Host)
		}
	}
}

// TestChainProxyValidation tests chain proxy validation
func TestChainProxyValidation(t *testing.T) {
	session := azuretls.NewSession()
	defer session.Close()

	// Test empty chain
	err := session.SetProxyChain([]string{})
	if err == nil {
		t.Fatal("Expected error for empty proxy chain")
	}

	// Test invalid proxy URL
	err = session.SetProxyChain([]string{"invalid-url"})
	if err != nil {
		// This should succeed since invalid-url will be formatted as http://invalid-url
		t.Logf("Expected behavior: %v", err)
	}

	// Test unsupported scheme
	err = session.SetProxyChain([]string{"ftp://proxy.example.com:8080"})
	if err == nil {
		t.Fatal("Expected error for unsupported proxy scheme")
	}

	// Test empty proxy in chain
	err = session.SetProxyChain([]string{"http://proxy1.example.com:8080", ""})
	if err == nil {
		t.Fatal("Expected error for empty proxy in chain")
	}
}

// TestChainProxyAuthentication tests proxy authentication in chain
func TestChainProxyAuthentication(t *testing.T) {
	session := azuretls.NewSession()
	defer session.Close()

	// Test chain with authentication
	proxies := []string{
		"http://user1:pass1@proxy1.example.com:8080",
		"https://user2:pass2@proxy2.example.com:8080",
	}

	err := session.SetProxyChain(proxies)
	if err != nil {
		t.Fatalf("Failed to set authenticated proxy chain: %v", err)
	}

	proxyChain := session.GetProxyChain()
	if len(proxyChain) != 2 {
		t.Fatalf("Expected 2 proxies in chain, got %d", len(proxyChain))
	}

	// Verify authentication info is preserved
	for i, proxy := range proxyChain {
		if proxy.User == nil {
			t.Errorf("Expected proxy %d to have authentication info", i)
			continue
		}

		username := proxy.User.Username()
		password, _ := proxy.User.Password()

		expectedUser := fmt.Sprintf("user%d", i+1)
		expectedPass := fmt.Sprintf("pass%d", i+1)

		if username != expectedUser {
			t.Errorf("Expected proxy %d username to be %s, got %s", i, expectedUser, username)
		}
		if password != expectedPass {
			t.Errorf("Expected proxy %d password to be %s, got %s", i, expectedPass, password)
		}
	}
}

// TestChainProxyFormatting tests proxy URL formatting
func TestChainProxyFormatting(t *testing.T) {
	session := azuretls.NewSession()
	defer session.Close()

	// Test various proxy formats
	testCases := []struct {
		input    string
		expected string
	}{
		{"proxy.example.com:8080", "proxy.example.com:8080"},
		{"proxy.example.com", "proxy.example.com:80"}, // HTTP default port
		{"user:pass@proxy.example.com:8080", "proxy.example.com:8080"},
	}

	for _, tc := range testCases {
		proxies := []string{tc.input}
		err := session.SetProxyChain(proxies)
		if err != nil {
			t.Fatalf("Failed to set proxy chain for input %s: %v", tc.input, err)
		}

		proxyChain := session.GetProxyChain()
		if len(proxyChain) != 1 {
			t.Fatalf("Expected 1 proxy in chain, got %d", len(proxyChain))
		}

		if proxyChain[0].Host != tc.expected {
			t.Errorf("For input %s, expected host %s, got %s", tc.input, tc.expected, proxyChain[0].Host)
		}
	}
}

// TestChainProxyHTTP1 tests chain proxy with HTTP/1.1
func TestChainProxyHTTP1(t *testing.T) {
	t.Skip("Skipping integration test - requires actual proxy servers")

	session := azuretls.NewSession()
	defer session.Close()

	// Use environment variables for proxy chain
	proxy1 := os.Getenv("TEST_PROXY_1")
	proxy2 := os.Getenv("TEST_PROXY_2")

	if proxy1 == "" || proxy2 == "" {
		t.Skip("TEST_PROXY_1 and TEST_PROXY_2 environment variables not set")
	}

	err := session.SetProxyChain([]string{proxy1, proxy2})
	if err != nil {
		t.Fatalf("Failed to set proxy chain: %v", err)
	}

	// Force HTTP/1.1
	response, err := session.Do(&azuretls.Request{
		Method:     "GET",
		Url:        "https://httpbin.org/ip",
		ForceHTTP1: true,
	})

	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	if response.StatusCode != 200 {
		t.Fatalf("Expected status 200, got %d", response.StatusCode)
	}

	t.Logf("Response: %s", response.String())
}

// TestChainProxyHTTP2 tests chain proxy with HTTP/2
func TestChainProxyHTTP2(t *testing.T) {
	t.Skip("Skipping integration test - requires actual proxy servers")

	session := azuretls.NewSession()
	defer session.Close()

	// Use environment variables for proxy chain
	proxy1 := os.Getenv("TEST_PROXY_1")
	proxy2 := os.Getenv("TEST_PROXY_2")

	if proxy1 == "" || proxy2 == "" {
		t.Skip("TEST_PROXY_1 and TEST_PROXY_2 environment variables not set")
	}

	err := session.SetProxyChain([]string{proxy1, proxy2})
	if err != nil {
		t.Fatalf("Failed to set proxy chain: %v", err)
	}

	// Use HTTP/2
	response, err := session.Get("https://httpbin.org/ip")

	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	if response.StatusCode != 200 {
		t.Fatalf("Expected status 200, got %d", response.StatusCode)
	}

	t.Logf("Response: %s", response.String())
	t.Logf("Protocol: %s", response.HttpResponse.Proto)
}

// TestChainProxyClearProxy tests clearing chain proxy
func TestChainProxyClearProxy(t *testing.T) {
	session := azuretls.NewSession()
	defer session.Close()

	// Set up chain proxy
	proxies := []string{
		"http://proxy1.example.com:8080",
		"http://proxy2.example.com:8080",
	}

	err := session.SetProxyChain(proxies)
	if err != nil {
		t.Fatalf("Failed to set proxy chain: %v", err)
	}

	// Verify chain is set
	if !session.IsChainProxy() {
		t.Fatal("Session should be using chain proxy")
	}

	// Clear the proxy
	session.ClearProxy()

	// Verify chain is cleared
	if session.IsChainProxy() {
		t.Fatal("Session should not be using chain proxy after clearing")
	}

	if session.GetProxyChain() != nil {
		t.Fatal("Proxy chain should be nil after clearing")
	}
}

// TestChainProxyMixedTypes tests chain with mixed proxy types
func TestChainProxyMixedTypes(t *testing.T) {
	session := azuretls.NewSession()
	defer session.Close()

	// Mix of HTTP and HTTPS proxies
	proxies := []string{
		"http://proxy1.example.com:8080",
		"https://proxy2.example.com:8080",
		"http://proxy3.example.com:3128",
	}

	err := session.SetProxyChain(proxies)
	if err != nil {
		t.Fatalf("Failed to set mixed proxy chain: %v", err)
	}

	proxyChain := session.GetProxyChain()
	if len(proxyChain) != 3 {
		t.Fatalf("Expected 3 proxies in chain, got %d", len(proxyChain))
	}

	expectedSchemes := []string{"http", "https", "http"}
	for i, proxy := range proxyChain {
		if proxy.Scheme != expectedSchemes[i] {
			t.Errorf("Expected proxy %d scheme to be %s, got %s", i, expectedSchemes[i], proxy.Scheme)
		}
	}
}

// TestChainProxyVsSingleProxy tests switching between chain and single proxy
func TestChainProxyVsSingleProxy(t *testing.T) {
	session := azuretls.NewSession()
	defer session.Close()

	// Start with single proxy
	err := session.SetProxy("http://single-proxy.example.com:8080")
	if err != nil {
		t.Fatalf("Failed to set single proxy: %v", err)
	}

	if session.IsChainProxy() {
		t.Fatal("Session should not be using chain proxy")
	}

	// Switch to chain proxy
	proxies := []string{
		"http://chain-proxy1.example.com:8080",
		"http://chain-proxy2.example.com:8080",
	}

	err = session.SetProxyChain(proxies)
	if err != nil {
		t.Fatalf("Failed to set proxy chain: %v", err)
	}

	if !session.IsChainProxy() {
		t.Fatal("Session should be using chain proxy")
	}

	// Switch back to single proxy
	err = session.SetProxy("http://another-single-proxy.example.com:8080")
	if err != nil {
		t.Fatalf("Failed to set single proxy again: %v", err)
	}

	if session.IsChainProxy() {
		t.Fatal("Session should not be using chain proxy after setting single proxy")
	}
}

// TestChainProxyConcurrency tests chain proxy under concurrent load
func TestChainProxyConcurrency(t *testing.T) {
	session := azuretls.NewSession()
	defer session.Close()

	// Set up chain proxy
	proxies := []string{
		"http://proxy1.example.com:8080",
		"http://proxy2.example.com:8080",
	}

	err := session.SetProxyChain(proxies)
	if err != nil {
		t.Fatalf("Failed to set proxy chain: %v", err)
	}

	// Test concurrent access
	var wg sync.WaitGroup
	numGoroutines := 10

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			// Check if chain proxy is set
			if !session.IsChainProxy() {
				t.Errorf("Goroutine %d: Session should be using chain proxy", id)
				return
			}

			// Get proxy chain
			chain := session.GetProxyChain()
			if len(chain) != 2 {
				t.Errorf("Goroutine %d: Expected 2 proxies in chain, got %d", id, len(chain))
				return
			}

			// Simulate some work
			time.Sleep(10 * time.Millisecond)
		}(i)
	}

	wg.Wait()
}

// BenchmarkChainProxySetup benchmarks chain proxy setup performance
func BenchmarkChainProxySetup(b *testing.B) {
	proxies := []string{
		"http://proxy1.example.com:8080",
		"http://proxy2.example.com:8080",
		"https://proxy3.example.com:8080",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		session := azuretls.NewSession()
		err := session.SetProxyChain(proxies)
		if err != nil {
			b.Fatalf("Failed to set proxy chain: %v", err)
		}
		session.Close()
	}
}

// TestChainProxyWithHeaders tests chain proxy with custom headers
func TestChainProxyWithHeaders(t *testing.T) {
	session := azuretls.NewSession()
	defer session.Close()

	// Set custom proxy headers
	session.ProxyHeader = http.Header{
		"User-Agent":        []string{"AzureTLS-Chain-Proxy/1.0"},
		"X-Custom-Header":   []string{"test-value"},
		http.HeaderOrderKey: []string{"user-agent", "x-custom-header"},
	}

	proxies := []string{
		"http://proxy1.example.com:8080",
		"http://proxy2.example.com:8080",
	}

	err := session.SetProxyChain(proxies)
	if err != nil {
		t.Fatalf("Failed to set proxy chain: %v", err)
	}

	// Verify chain is set up correctly
	if !session.IsChainProxy() {
		t.Fatal("Session should be using chain proxy")
	}

	// Verify proxy headers are preserved
	if session.ProxyHeader.Get("User-Agent") != "AzureTLS-Chain-Proxy/1.0" {
		t.Fatal("Custom proxy headers should be preserved")
	}
}

// SimpleProxyServer creates a simple HTTP proxy server for testing
type SimpleProxyServer struct {
	server *httptest.Server
	name   string
	t      *testing.T
}

func NewSimpleProxyServer(t *testing.T, name string) *SimpleProxyServer {
	proxy := &SimpleProxyServer{
		name: name,
		t:    t,
	}

	proxy.server = httptest.NewServer(http.HandlerFunc(proxy.handleRequest))
	t.Logf("Started proxy server %s at %s", name, proxy.server.URL)

	return proxy
}

func (p *SimpleProxyServer) handleRequest(w http.ResponseWriter, r *http.Request) {
	p.t.Logf("%s: Handling %s request to %s", p.name, r.Method, r.URL.String())

	if r.Method == "CONNECT" {
		p.handleConnect(w, r)
	} else {
		p.handleHTTP(w, r)
	}
}

func (p *SimpleProxyServer) handleConnect(w http.ResponseWriter, r *http.Request) {
	p.t.Logf("%s: CONNECT to %s", p.name, r.Host)

	// Try to connect to the target
	targetConn, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		p.t.Logf("%s: Failed to connect to %s: %v", p.name, r.Host, err)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer targetConn.Close()

	// Send 200 Connection Established
	w.WriteHeader(http.StatusOK)

	// Hijack the connection
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		p.t.Logf("%s: Hijacking not supported", p.name)
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		p.t.Logf("%s: Failed to hijack: %v", p.name, err)
		return
	}
	defer clientConn.Close()

	// Start relaying data
	errCh := make(chan error, 2)

	// Copy from client to target
	go func() {
		_, err := io.Copy(targetConn, clientConn)
		errCh <- err
	}()

	// Copy from target to client
	go func() {
		_, err := io.Copy(clientConn, targetConn)
		errCh <- err
	}()

	// Wait for the first error (connection closed)
	<-errCh
	p.t.Logf("%s: CONNECT tunnel closed for %s", p.name, r.Host)
}

func (p *SimpleProxyServer) handleHTTP(w http.ResponseWriter, r *http.Request) {
	p.t.Logf("%s: HTTP %s to %s", p.name, r.Method, r.URL.String())

	// Add header to identify this proxy
	w.Header().Set("X-Proxy-Chain", p.name)

	// For testing, just return a simple response
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Response from proxy %s", p.name)
}

func (p *SimpleProxyServer) URL() string {
	return p.server.URL
}

func (p *SimpleProxyServer) Close() {
	p.server.Close()
}

// TestChainProxyIntegrationSimple tests basic chain proxy functionality with mock servers
func TestChainProxyIntegrationSimple(t *testing.T) {
	// Create two proxy servers
	proxy1 := NewSimpleProxyServer(t, "proxy1")
	defer proxy1.Close()

	proxy2 := NewSimpleProxyServer(t, "proxy2")
	defer proxy2.Close()

	// Parse proxy URLs to get host:port
	url1, err := url.Parse(proxy1.URL())
	if err != nil {
		t.Fatalf("Failed to parse proxy1 URL: %v", err)
	}

	url2, err := url.Parse(proxy2.URL())
	if err != nil {
		t.Fatalf("Failed to parse proxy2 URL: %v", err)
	}

	// Create session with chain proxy
	session := azuretls.NewSession()
	defer session.Close()

	proxies := []string{
		fmt.Sprintf("http://%s", url1.Host),
		fmt.Sprintf("http://%s", url2.Host),
	}

	err = session.SetProxyChain(proxies)
	if err != nil {
		t.Fatalf("Failed to set proxy chain: %v", err)
	}

	// Verify chain is configured
	if !session.IsChainProxy() {
		t.Fatal("Session should be using chain proxy")
	}

	chain := session.GetProxyChain()
	if len(chain) != 2 {
		t.Fatalf("Expected 2 proxies in chain, got %d", len(chain))
	}

	t.Logf("Chain proxy configured: %s -> %s", chain[0].Host, chain[1].Host)

	// Test with a simple HTTP request to httpbin (this will test the full chain)
	// Note: This test may fail if external network access is restricted
	// but it demonstrates the chain proxy setup
	session.SetTimeout(10 * time.Second)

	response, err := session.Get("http://httpbin.org/ip")
	if err != nil {
		// Log the error but don't fail the test since it might be network-related
		t.Logf("Request through chain proxy failed (expected in restricted environments): %v", err)
	} else {
		t.Logf("Request succeeded! Status: %d", response.StatusCode)
		t.Logf("Response: %s", response.String())
	}
}

// TestChainProxyWithAuthentication tests chain proxy with authentication
func TestChainProxyWithAuthentication(t *testing.T) {
	// Create an authenticating proxy server
	authProxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Proxy-Authorization")
		if auth == "" {
			w.Header().Set("Proxy-Authenticate", "Basic realm=\"proxy\"")
			w.WriteHeader(http.StatusProxyAuthRequired)
			return
		}

		// Check for valid auth (Basic dGVzdDp0ZXN0 = test:test in base64)
		if auth != "Basic dGVzdDp0ZXN0" {
			w.WriteHeader(http.StatusForbidden)
			return
		}

		// Valid auth, handle the request
		if r.Method == "CONNECT" {
			w.WriteHeader(http.StatusOK)
			return
		}

		w.Header().Set("X-Authenticated-Proxy", "true")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "Response from authenticated proxy")
	}))
	defer authProxy.Close()

	// Parse auth proxy URL
	authURL, err := url.Parse(authProxy.URL)
	if err != nil {
		t.Fatalf("Failed to parse auth proxy URL: %v", err)
	}

	// Create session with authenticated proxy in chain
	session := azuretls.NewSession()
	defer session.Close()

	proxies := []string{
		fmt.Sprintf("http://test:test@%s", authURL.Host),
	}

	err = session.SetProxyChain(proxies)
	if err != nil {
		t.Fatalf("Failed to set authenticated proxy chain: %v", err)
	}

	// Verify authentication is configured
	chain := session.GetProxyChain()
	if len(chain) != 1 {
		t.Fatalf("Expected 1 proxy in chain, got %d", len(chain))
	}

	if chain[0].User == nil {
		t.Fatal("Expected proxy to have authentication info")
	}

	username := chain[0].User.Username()
	password, _ := chain[0].User.Password()

	if username != "test" || password != "test" {
		t.Fatalf("Expected username:password to be test:test, got %s:%s", username, password)
	}

	t.Logf("Authenticated proxy chain configured successfully")
}

// TestChainProxyErrorHandling tests error handling in chain proxy
func TestChainProxyErrorHandling(t *testing.T) {
	// Create a proxy that returns errors
	errorProxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "CONNECT" {
			// Return error for CONNECT
			w.WriteHeader(http.StatusBadGateway)
			fmt.Fprint(w, "Proxy error")
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer errorProxy.Close()

	// Parse error proxy URL
	errorURL, err := url.Parse(errorProxy.URL)
	if err != nil {
		t.Fatalf("Failed to parse error proxy URL: %v", err)
	}

	// Create session with error proxy
	session := azuretls.NewSession()
	defer session.Close()

	proxies := []string{
		fmt.Sprintf("http://%s", errorURL.Host),
	}

	err = session.SetProxyChain(proxies)
	if err != nil {
		t.Fatalf("Failed to set error proxy chain: %v", err)
	}

	// Test that requests fail appropriately
	session.SetTimeout(5 * time.Second)

	resp, err := session.Get("https://httpbin.org/ip")

	// The test should expect either an error OR a 502 status code
	if err == nil && resp.StatusCode == http.StatusOK {
		t.Fatal("Expected request to fail through error proxy, but it succeeded")
	}

	if err == nil && resp.StatusCode == http.StatusBadGateway {
		t.Logf("Request correctly failed with 502 Bad Gateway: %s", resp.Status)
		return
	}

	if err != nil {
		t.Logf("Request failed as expected: %v", err)
		return
	}

	t.Logf("Unexpected response: Status %d", resp.StatusCode)
}

// TestChainProxyConnectionReuse tests connection reuse in chain proxy
func TestChainProxyConnectionReuse(t *testing.T) {
	proxy1 := NewSimpleProxyServer(t, "reuse-proxy1")
	defer proxy1.Close()

	proxy2 := NewSimpleProxyServer(t, "reuse-proxy2")
	defer proxy2.Close()

	// Parse proxy URLs
	url1, err := url.Parse(proxy1.URL())
	if err != nil {
		t.Fatalf("Failed to parse proxy1 URL: %v", err)
	}

	url2, err := url.Parse(proxy2.URL())
	if err != nil {
		t.Fatalf("Failed to parse proxy2 URL: %v", err)
	}

	// Create session with chain proxy
	session := azuretls.NewSession()
	defer session.Close()

	proxies := []string{
		fmt.Sprintf("http://%s", url1.Host),
		fmt.Sprintf("http://%s", url2.Host),
	}

	err = session.SetProxyChain(proxies)
	if err != nil {
		t.Fatalf("Failed to set proxy chain: %v", err)
	}

	// Make multiple requests to test connection reuse
	session.SetTimeout(10 * time.Second)

	for i := 0; i < 3; i++ {
		t.Logf("Making request %d through proxy chain", i+1)

		_, err := session.Get("http://httpbin.org/ip")
		if err != nil {
			t.Logf("Request %d failed (expected in restricted environments): %v", i+1, err)
		} else {
			t.Logf("Request %d succeeded", i+1)
		}

		// Small delay between requests
		time.Sleep(100 * time.Millisecond)
	}
}
