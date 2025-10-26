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

func TestSession_PinVerificationShouldSucceed(t *testing.T) {
	session := azuretls.NewSession()
	defer session.Close()

	resp, err := session.Get("https://vk.com")
	if err != nil {
		t.Fatal(err)
	}

	if resp.StatusCode != 200 {
		t.Fatal("Expected 200")
	}
}

// BenchmarkPinGeneration_WithSession benchmarks pin generation using Session's ClientHello spec
func BenchmarkPinGeneration_WithSession(b *testing.B) {
	session := azuretls.NewSession()
	defer session.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pm := azuretls.NewPinManager()
		_ = pm.AddHost("vk.com:443", session)
	}
}

// BenchmarkPinGeneration_WithoutSession benchmarks pin generation using simple TLS dial
func BenchmarkPinGeneration_WithoutSession(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pm := azuretls.NewPinManager()
		_ = pm.AddHost("vk.com:443", nil)
	}
}

// TestCertificateChainDifference demonstrates the certificate chain difference
// between pin generation with and without Session for vk.com
func TestCertificateChainDifference(t *testing.T) {
	t.Log("Testing certificate chain differences for vk.com")

	// Generate pins WITH Session (uses ClientHello spec)
	t.Log("\n--- With Session (uses ClientHello spec) ---")
	session := azuretls.NewSession()
	defer session.Close()

	pmWithSession := azuretls.NewPinManager()
	if err := pmWithSession.AddHost("vk.com:443", session); err != nil {
		t.Fatal(err)
	}

	pinsWithSession := pmWithSession.GetHost("vk.com:443").GetPins()
	t.Logf("Pins generated WITH Session: %d pins", len(pinsWithSession))
	for _, pin := range pinsWithSession {
		t.Logf("  - %s", pin)
	}

	// Generate pins WITHOUT Session (simple TLS dial)
	t.Log("\n--- Without Session (simple TLS dial) ---")
	pmWithoutSession := azuretls.NewPinManager()
	if err := pmWithoutSession.AddHost("vk.com:443", nil); err != nil {
		t.Fatal(err)
	}

	pinsWithoutSession := pmWithoutSession.GetHost("vk.com:443").GetPins()
	t.Logf("Pins generated WITHOUT Session: %d pins", len(pinsWithoutSession))
	for _, pin := range pinsWithoutSession {
		t.Logf("  - %s", pin)
	}

	// Check if they're different
	withSessionMap := make(map[string]bool)
	for _, pin := range pinsWithSession {
		withSessionMap[pin] = true
	}

	withoutSessionMap := make(map[string]bool)
	for _, pin := range pinsWithoutSession {
		withoutSessionMap[pin] = true
	}

	// Find pins only in WithSession
	t.Log("\n--- Comparison ---")
	onlyInWithSession := []string{}
	for _, pin := range pinsWithSession {
		if !withoutSessionMap[pin] {
			onlyInWithSession = append(onlyInWithSession, pin)
		}
	}

	if len(onlyInWithSession) > 0 {
		t.Logf("Pins ONLY in WithSession (ECC chain): %d", len(onlyInWithSession))
		for _, pin := range onlyInWithSession {
			t.Logf("  - %s", pin)
		}
	}

	// Find pins only in WithoutSession
	onlyInWithoutSession := []string{}
	for _, pin := range pinsWithoutSession {
		if !withSessionMap[pin] {
			onlyInWithoutSession = append(onlyInWithoutSession, pin)
		}
	}

	if len(onlyInWithoutSession) > 0 {
		t.Logf("Pins ONLY in WithoutSession (RSA chain): %d", len(onlyInWithoutSession))
		for _, pin := range onlyInWithoutSession {
			t.Logf("  - %s", pin)
		}
	}

	if len(onlyInWithSession) == 0 && len(onlyInWithoutSession) == 0 {
		t.Log("All pins are identical")
	}
}
