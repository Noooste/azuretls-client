package azuretls

import (
	"bytes"
	"compress/gzip"
	"strings"
	"testing"

	"github.com/Noooste/azuretls-client"
)

func TestDisableAutoDecompression_Enabled(t *testing.T) {
	session := azuretls.NewSession()
	session.DisableAutoDecompression = true

	// Test with a gzip endpoint
	response, err := session.Get("https://httpbingo.org/gzip", azuretls.OrderedHeaders{
		{"accept-encoding", "gzip"},
	})
	if err != nil {
		t.Fatal("TestDisableAutoDecompression_Enabled failed:", err)
	}

	// When auto decompression is disabled, we should get the raw compressed data
	// The Content-Encoding header should still be present
	contentEncoding := response.Header.Get("Content-Encoding")
	if contentEncoding != "gzip" {
		t.Fatal("TestDisableAutoDecompression_Enabled failed, expected Content-Encoding: gzip, got:", contentEncoding)
	}

	// The body should be compressed (gzip format starts with 0x1f, 0x8b)
	if len(response.Body) < 2 || response.Body[0] != 0x1f || response.Body[1] != 0x8b {
		t.Fatal("TestDisableAutoDecompression_Enabled failed, expected compressed gzip data, got non-gzip data")
	}

	// Manually decompress to verify the content
	gzipReader, err := gzip.NewReader(bytes.NewReader(response.Body))
	if err != nil {
		t.Fatal("TestDisableAutoDecompression_Enabled failed to create gzip reader:", err)
	}
	defer gzipReader.Close()

	var decompressed bytes.Buffer
	if _, err := decompressed.ReadFrom(gzipReader); err != nil {
		t.Fatal("TestDisableAutoDecompression_Enabled failed to decompress:", err)
	}

	// Verify the decompressed content contains the expected JSON
	if !strings.Contains(decompressed.String(), "\"gzipped\": true") {
		t.Fatal("TestDisableAutoDecompression_Enabled failed, decompressed content doesn't contain expected data")
	}
}

func TestDisableAutoDecompression_Disabled(t *testing.T) {
	session := azuretls.NewSession()
	// DisableAutoDecompression is false by default

	// Test with a gzip endpoint
	response, err := session.Get("https://httpbingo.org/gzip")
	if err != nil {
		t.Fatal("TestDisableAutoDecompression_Disabled failed:", err)
	}

	// When auto decompression is enabled (default), we should get decompressed data
	// The response body should contain readable JSON
	if !strings.Contains(string(response.Body), "\"gzipped\": true") {
		t.Fatal("TestDisableAutoDecompression_Disabled failed, expected decompressed JSON content, got:", string(response.Body))
	}

	// The body should not be in gzip format (should be readable text/JSON)
	if len(response.Body) >= 2 && response.Body[0] == 0x1f && response.Body[1] == 0x8b {
		t.Fatal("TestDisableAutoDecompression_Disabled failed, received compressed data when decompression should be enabled")
	}
}

func TestDisableAutoDecompression_Brotli(t *testing.T) {
	session := azuretls.NewSession()
	session.DisableAutoDecompression = true

	// Test with brotli endpoint
	response, err := session.Get("https://httpbingo.org/brotli", azuretls.OrderedHeaders{
		{"Accept-Encoding", "br"},
	})
	if err != nil {
		t.Fatal("TestDisableAutoDecompression_Brotli failed:", err)
	}

	// When auto decompression is disabled, we should get the raw compressed data
	contentEncoding := response.Header.Get("Content-Encoding")
	if contentEncoding != "br" {
		t.Fatal("TestDisableAutoDecompression_Brotli failed, expected Content-Encoding: br, got:", contentEncoding)
	}

	// The body should be compressed data (not readable JSON)
	if strings.Contains(string(response.Body), "\"brotli\": true") {
		t.Fatal("TestDisableAutoDecompression_Brotli failed, received decompressed data when compression should be preserved")
	}
}
