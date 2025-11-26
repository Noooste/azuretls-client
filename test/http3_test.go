// test/http3_socks5_test.go
package azuretls_test

import (
	"fmt"
	"log"
	"testing"
	"time"

	"github.com/txthinking/socks5"

	"github.com/Noooste/azuretls-client"
)

func TestHTTP3Direct(t *testing.T) {
	// Create session
	session := azuretls.NewSession()
	defer session.Close()
	session.InsecureSkipVerify = true

	if err := session.ApplyHTTP3("1:16383;7:100;GREASE|m,s,a,p"); err != nil {
		t.Fatalf("Failed to apply HTTP/3 settings: %v", err)
	}

	session.Log()

	// Test direct HTTP/3
	resp, err := session.Do(&azuretls.Request{
		Method:     "GET",
		Url:        "https://fp.impersonate.pro/api/http3", // Cloudflare supports HTTP/3
		ForceHTTP3: true,
		TimeOut:    10 * time.Second,
		OrderedHeaders: azuretls.OrderedHeaders{
			{"Accept", "application/json"},
			{"User-Agent", "AzureTLS-Client/1.0"},
		},
	})

	if err != nil {
		t.Fatal(err)
	}

	// Check response
	if resp.StatusCode != 200 {
		t.Fatalf("Expected status 200, got %d", resp.StatusCode)
	}

	// Verify HTTP/3 was used
	if resp.HttpResponse.Proto != "HTTP/3.0" {
		t.Logf("Warning: Expected HTTP/3.0, got %s (server might not support HTTP/3)", resp.HttpResponse.Proto)
	}

	fmt.Println(resp.String())
}

func TestHTTP2ToHTTP3(t *testing.T) {
	// Create session
	session := azuretls.NewSession()
	defer session.Close()

	session.Log()

	session.EnableHTTP3()

	// Test direct HTTP/2
	resp, err := session.Do(&azuretls.Request{
		Method:  "GET",
		Url:     "https://fp.impersonate.pro/api/http3", // Cloudflare supports HTTP/3
		TimeOut: 10 * time.Second,
		OrderedHeaders: azuretls.OrderedHeaders{
			{"Accept", "application/json"},
			{"User-Agent", "AzureTLS-Client/1.0"},
		},
	})

	if err != nil {
		t.Fatal(err)
	}

	// Check response
	if resp.StatusCode != 200 {
		t.Fatalf("Expected status 200, got %d", resp.StatusCode)
	}

	// Verify HTTP/3 was used
	if resp.HttpResponse.Proto != "HTTP/2.0" {
		t.Logf("Warning: Expected HTTP/3.0, got %s (server might not support HTTP/3)", resp.HttpResponse.Proto)
	}

	t.Log(resp.HttpResponse.Header.Get("Alt-Svc"))

	// Test direct HTTP/2
	resp, err = session.Do(&azuretls.Request{
		Method:  "GET",
		Url:     "https://fp.impersonate.pro/api/http3", // Cloudflare supports HTTP/3
		TimeOut: 10 * time.Second,
		OrderedHeaders: azuretls.OrderedHeaders{
			{"Accept", "application/json"},
			{"User-Agent", "AzureTLS-Client/1.0"},
		},
	})

	if err != nil {
		t.Fatal(err)
	}

	// Check response
	if resp.StatusCode != 200 {
		t.Fatalf("Expected status 200, got %d", resp.StatusCode)
	}

	// Verify HTTP/3 was used
	if resp.HttpResponse.Proto != "HTTP/3.0" {
		t.Logf("Warning: Expected HTTP/3.0, got %s (server might not support HTTP/3)", resp.HttpResponse.Proto)
	}
}

func TestHTTP3WithSOCKS5(t *testing.T) {
	// Start a local SOCKS5 server for testing
	server, err := socks5.NewClassicServer("127.0.0.1:1080", "127.0.0.1", "", "", 0, 0)
	if err != nil {
		t.Fatal(err)
	}

	// Start the server in background
	go func() {
		if err := server.ListenAndServe(nil); err != nil {
			log.Printf("SOCKS5 server error: %v", err)
		}
	}()

	// Wait for server to start
	time.Sleep(time.Second)

	// Create session
	session := azuretls.NewSession()
	defer session.Close()

	// Set SOCKS5 proxy
	if err := session.SetProxy("socks5://127.0.0.1:1080"); err != nil {
		t.Fatal(err)
	}

	// Enable HTTP/3
	err = session.EnableHTTP3()
	if err != nil {
		t.Fatal(err)
	}

	// Enable logging
	session.Log()

	// Test direct HTTP/3
	resp, err := session.Do(&azuretls.Request{
		Method:     "GET",
		Url:        "https://cloudflare.com/cdn-cgi/trace", // Cloudflare supports HTTP/3
		ForceHTTP3: true,
		TimeOut:    10 * time.Second,
	})

	if err != nil {
		t.Fatal(err)
	}

	// Check response
	if resp.StatusCode != 200 {
		t.Fatalf("Expected status 200, got %d", resp.StatusCode)
	}

	// Verify HTTP/3 was used
	if resp.HttpResponse.Proto != "HTTP/3.0" {
		t.Logf("Warning: Expected HTTP/3.0, got %s (server might not support HTTP/3)", resp.HttpResponse.Proto)
	}

	t.Logf("Response body: %s", string(resp.Body))
}

func TestHTTP3MultipleRequests(t *testing.T) {
	// Start SOCKS5 server
	server, err := socks5.NewClassicServer("127.0.0.1:1082", "127.0.0.1", "", "", 0, 0)
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		if err := server.ListenAndServe(nil); err != nil {
			log.Printf("SOCKS5 server error: %v", err)
		}
	}()

	time.Sleep(time.Second)

	// Create session
	session := azuretls.NewSession()
	defer session.Close()

	if err := session.SetProxy("socks5://127.0.0.1:1082"); err != nil {
		t.Fatal(err)
	}

	err = session.EnableHTTP3()
	if err != nil {
		t.Fatal(err)
	}

	// Test multiple sites that support HTTP/3
	sites := []string{
		"https://cloudflare.com/cdn-cgi/trace",
		"https://blog.cloudflare.com/",
		"https://one.one.one.one/",
	}

	for _, site := range sites {
		t.Run(site, func(t *testing.T) {
			resp, err := session.Do(&azuretls.Request{
				Method:     "GET",
				Url:        site,
				ForceHTTP3: true,
				TimeOut:    10 * time.Second,
			})

			if err != nil {
				t.Errorf("Failed to fetch %s: %v", site, err)
				return
			}

			if resp.StatusCode != 200 {
				t.Errorf("Expected status 200 for %s, got %d", site, resp.StatusCode)
				return
			}

			t.Logf("%s - Protocol: %s, Status: %d", site, resp.HttpResponse.Proto, resp.StatusCode)
		})
	}
}

func TestHTTP3AndHTTP2(t *testing.T) {
	// Start a local SOCKS5 server for testing
	server, err := socks5.NewClassicServer("127.0.0.1:1080", "127.0.0.1", "", "", 0, 0)
	if err != nil {
		t.Fatal(err)
	}

	// Start the server in background
	go func() {
		if err := server.ListenAndServe(nil); err != nil {
			log.Printf("SOCKS5 server error: %v", err)
		}
	}()

	// Wait for server to start
	time.Sleep(time.Second)

	// Create session
	session := azuretls.NewSession()
	session.InsecureSkipVerify = true
	defer session.Close()

	// Set SOCKS5 proxy
	if err := session.SetProxy("socks5://127.0.0.1:1080"); err != nil {
		t.Fatal(err)
	}

	// Enable HTTP/3
	err = session.EnableHTTP3()
	if err != nil {
		t.Fatal(err)
	}

	// Enable logging
	session.Log()

	// Test direct HTTP/3
	resp, err := session.Do(&azuretls.Request{
		Method:     "GET",
		Url:        "https://fp.impersonate.pro/api/http3", // Cloudflare supports HTTP/3
		ForceHTTP3: true,
		TimeOut:    10 * time.Second,
	})

	if err != nil {
		t.Fatal(err)
	}

	// Check response
	if resp.StatusCode != 200 {
		t.Fatalf("Expected status 200, got %d", resp.StatusCode)
	}

	// Verify HTTP/3 was used
	if resp.HttpResponse.Proto != "HTTP/3.0" {
		t.Logf("Warning: Expected HTTP/3.0, got %s (server might not support HTTP/3)", resp.HttpResponse.Proto)
	}

	// Test direct HTTP/3
	resp, err = session.Do(&azuretls.Request{
		Method:  "GET",
		Url:     "https://www.google.com", // Cloudflare supports HTTP/3
		TimeOut: 10 * time.Second,
	})

	if err != nil {
		t.Fatal(err)
	}

	// Check response
	if resp.StatusCode != 200 {
		t.Fatalf("Expected status 200, got %d", resp.StatusCode)
	}

	// Verify HTTP/2 was used
	if resp.HttpResponse.Proto != "HTTP/2.0" {
		t.Logf("Warning: Expected HTTP/2.0, got %s (server might not support HTTP/2)", resp.HttpResponse.Proto)
	}
}

//
//func TestHTTP3Fallback(t *testing.T) {
//	// Start SOCKS5 server
//	server, err := socks5.NewClassicServer("127.0.0.1:1083", "127.0.0.1", "", "", 0, 0)
//	if err != nil {
//		t.Fatal(err)
//	}
//
//	go func() {
//		if err := server.ListenAndServe(nil); err != nil {
//			log.Printf("SOCKS5 server error: %v", err)
//		}
//	}()
//
//	time.Sleep(time.Second)
//
//	// Create session
//	session := azuretls.NewSession()
//	defer session.Close()
//
//	if err := session.SetProxy("socks5://127.0.0.1:1083"); err != nil {
//		t.Fatal(err)
//	}
//
//	err = session.EnableHTTP3()
//	if err != nil {
//		t.Fatal(err)
//	}
//
//	// Test site that might not support HTTP/3
//	resp, err := session.Get("https://example.com")
//
//	if err != nil {
//		t.Fatal(err)
//	}
//
//	if resp.StatusCode != 200 {
//		t.Fatalf("Expected status 200, got %d", resp.StatusCode)
//	}
//
//	// Should fall back to HTTP/2 or HTTP/1.1
//	t.Logf("Protocol used: %s (fallback is expected for sites without HTTP/3)", resp.HttpResponse.Proto)
//}
//
//// Helper function to build DNS query
//func buildDNSQuery(domain string) []byte {
//	query := make([]byte, 0, 512)
//
//	// Header
//	query = append(query, 0x00, 0x01) // ID
//	query = append(query, 0x01, 0x00) // Flags
//	query = append(query, 0x00, 0x01) // Questions
//	query = append(query, 0x00, 0x00) // Answers
//	query = append(query, 0x00, 0x00) // Authority
//	query = append(query, 0x00, 0x00) // Additional
//
//	// Question
//	parts := []string{}
//	for _, p := range strings.Split(domain, ".") {
//		if p != "" {
//			parts = append(parts, p)
//		}
//	}
//
//	for _, part := range parts {
//		query = append(query, byte(len(part)))
//		query = append(query, []byte(part)...)
//	}
//	query = append(query, 0x00)       // Root
//	query = append(query, 0x00, 0x01) // Type A
//	query = append(query, 0x00, 0x01) // Class IN
//
//	return query
//}
//
//func TestSOCKS5Authentication(t *testing.T) {
//	// Test with username/password authentication
//	server, err := socks5.NewClassicServer("127.0.0.1:1084", "127.0.0.1", "testuser", "testpass", 0, 0)
//	if err != nil {
//		t.Fatal(err)
//	}
//
//	go func() {
//		if err := server.ListenAndServe(nil); err != nil {
//			log.Printf("SOCKS5 server error: %v", err)
//		}
//	}()
//
//	time.Sleep(time.Second)
//
//	// Test with correct credentials
//	session := azuretls.NewSession()
//	defer session.Close()
//
//	if err := session.SetProxy("socks5://testuser:testpass@127.0.0.1:1084"); err != nil {
//		t.Fatal(err)
//	}
//
//	err = session.EnableHTTP3()
//	if err != nil {
//		t.Fatal(err)
//	}
//
//	resp, err := session.Get("https://cloudflare.com/cdn-cgi/trace")
//	if err != nil {
//		t.Fatal(err)
//	}
//
//	if resp.StatusCode != 200 {
//		t.Fatalf("Expected status 200, got %d", resp.StatusCode)
//	}
//
//	t.Log("Authentication successful")
//}
//
//// Benchmark SOCKS5 UDP performance
//func BenchmarkSOCKS5UDP(b *testing.B) {
//	// Start server
//	server, err := socks5.NewClassicServer("127.0.0.1:1085", "127.0.0.1", "", "", 0, 0)
//	if err != nil {
//		b.Fatal(err)
//	}
//
//	go func() {
//		if err := server.ListenAndServe(nil); err != nil {
//			log.Printf("SOCKS5 server error: %v", err)
//		}
//	}()
//
//	time.Sleep(time.Second)
//
//	dialer := azuretls.NewSOCKS5UDPDialer("127.0.0.1:1085", "", "")
//	ctx := context.Background()
//
//	conn, err := dialer.DialUDP(ctx, "udp", "8.8.8.8:53")
//	if err != nil {
//		b.Fatal(err)
//	}
//	defer conn.Close()
//
//	query := buildDNSQuery("example.com")
//	response := make([]byte, 512)
//
//	b.ResetTimer()
//
//	for i := 0; i < b.N; i++ {
//		_, err := conn.Write(query)
//		if err != nil {
//			b.Fatal(err)
//		}
//
//		_, err = conn.Read(response)
//		if err != nil {
//			b.Fatal(err)
//		}
//	}
//}

//func makeRequest(t *testing.T, url string) {
//	session := azuretls.NewSession()
//	defer session.Close()
//
//	for i := 0; i < 10; i++ {
//		resp, err := session.Do(&azuretls.Request{
//			Method:     "GET",
//			Url:        url,
//			ForceHTTP3: true,
//			TimeOut:    10 * time.Second,
//		})
//
//		if err != nil {
//			t.Errorf("Failed to fetch %s: %v", url, err)
//			return
//		}
//
//		if resp.StatusCode != 200 {
//			t.Errorf("Expected status 200 for %s, got %d", url, resp.StatusCode)
//			return
//		}
//
//		t.Logf("%s - Protocol: %s, Status: %d", url, resp.HttpResponse.Proto, resp.StatusCode)
//	}
//
//}
//
//func worker(t *testing.T, wg *sync.WaitGroup) {
//	defer wg.Done()
//	for range 10000 {
//		makeRequest(t, "https://cloudflare.com/cdn-cgi/trace")
//		time.Sleep(1 * time.Second) // Simulate some delay between requests
//	}
//}
//
//func TestConstantRequests(t *testing.T) {
//	workers := 2
//	wg := &sync.WaitGroup{}
//	wg.Add(workers)
//	for i := 0; i < workers; i++ {
//		go worker(t, wg)
//	}
//	wg.Wait()
//}
