package azuretls_test

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Noooste/azuretls-client"
	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

func init() {
	go startServer()
}

const (
	testServerURL  = "http://localhost:8080"
	httpbinBaseURL = "https://httpbingo.org"
)

// startTestServer starts the local test server if it's not already running
func startTestServer(t *testing.T) {
	// Check if server is already running
	resp, err := http.Get(testServerURL)
	if err == nil {
		resp.Body.Close()
		return // Server is already running
	}

	// Wait for server to be ready
	for i := 0; i < 10; i++ {
		time.Sleep(100 * time.Millisecond)
		resp, err := http.Get(testServerURL)
		if err == nil {
			resp.Body.Close()
			return
		}
	}
	t.Fatal("Test server failed to start")
}

func TestDecompressBody_Gzip(t *testing.T) {
	startTestServer(t)

	session := azuretls.NewSession()

	session.OrderedHeaders = azuretls.OrderedHeaders{
		{"Accept-Encoding", "gzip"},
	}

	response, err := session.Get(testServerURL + "/gzip")

	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(string(response.Body), "\"gzipped\":true") {
		t.Fatal("TestDecompressBody_Gzip failed, expected: ", "\"gzipped\":true", ", got: ", string(response.Body))
	}
}

func TestDecompressBody_GzipWithHTTP3Fingerprint(t *testing.T) {
	startTestServer(t)

	session := azuretls.NewSession()

	session.OrderedHeaders = azuretls.OrderedHeaders{
		{"Accept-Encoding", "gzip"},
	}

	if err := session.ApplyHTTP2("1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"); err != nil {
		t.Fatal(err)
	}

	response, err := session.Get(testServerURL + "/gzip")

	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(string(response.Body), "\"gzipped\":true") {
		t.Fatal("TestDecompressBody_Gzip failed, expected: ", "\"gzipped\":true", ", got: ", string(response.Body))
	}
}

func TestDecompressBody_Deflate(t *testing.T) {
	startTestServer(t)

	session := azuretls.NewSession()

	session.OrderedHeaders = azuretls.OrderedHeaders{
		{"Accept-Encoding", "deflate"},
	}

	response, err := session.Get(testServerURL + "/deflate")

	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(string(response.Body), "\"deflated\":true") {
		t.Fatal("TestDecompressBody_Deflate failed, expected: ", "\"deflated\":true", ", got: ", string(response.Body))
	}
}

func TestDecompressBody_Brotli(t *testing.T) {
	startTestServer(t)

	session := azuretls.NewSession()

	session.OrderedHeaders = azuretls.OrderedHeaders{
		{"Accept-Encoding", "br"},
	}

	response, err := session.Get(testServerURL + "/brotli")

	if err != nil {
		t.Fatal(err)
	}

	fmt.Println(response.HttpResponse.Proto)

	if response.StatusCode != 200 {
		t.Fatal("TestDecompressBody_Brotli failed, expected status code 200, got: ", response.StatusCode)
	}

	if !strings.Contains(string(response.Body), "\"brotli\":true") {
		t.Fatal("TestDecompressBody_Brotli failed, expected: ", "\"brotli\":true", ", got: ", string(response.Body))
	}

}

func TestDecompressBody_Zstd(t *testing.T) {
	startTestServer(t)

	session := azuretls.NewSession()

	session.OrderedHeaders = azuretls.OrderedHeaders{
		{"Accept-Encoding", "zstd"},
	}

	response, err := session.Get(testServerURL + "/zstd")

	if err != nil {
		t.Fatal(err)
	}

	if response.StatusCode != 200 {
		t.Fatal("TestDecompressBody_Zstd failed, expected status code 200, got: ", response.StatusCode)
	}

	if !strings.Contains(string(response.Body), "\"zstd\":true") {
		t.Fatal("TestDecompressBody_Zstd failed, expected: ", "\"zstd\":true", ", got: ", string(response.Body))
	}
}

func TestDecompressBody_Auto(t *testing.T) {
	startTestServer(t)

	session := azuretls.NewSession()

	session.OrderedHeaders = azuretls.OrderedHeaders{
		{"Accept-Encoding", "gzip, deflate, br, zstd"},
	}

	response, err := session.Get(testServerURL + "/auto")

	if err != nil {
		t.Fatal(err)
	}

	if response.StatusCode != 200 {
		t.Fatal("TestDecompressBody_Auto failed, expected status code 200, got: ", response.StatusCode)
	}

	// Le serveur devrait choisir brotli en priorité
	if !strings.Contains(string(response.Body), "\"brotli\":true") {
		t.Fatal("TestDecompressBody_Auto failed, expected brotli compression, got: ", string(response.Body))
	}
}

// Local compression tests
func createGzipData(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	gzipWriter := gzip.NewWriter(&buf)
	if _, err := gzipWriter.Write(data); err != nil {
		return nil, err
	}
	if err := gzipWriter.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func createBrotliData(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	brotliWriter := brotli.NewWriter(&buf)
	if _, err := brotliWriter.Write(data); err != nil {
		return nil, err
	}
	if err := brotliWriter.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func createZlibData(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	zlibWriter := zlib.NewWriter(&buf)
	if _, err := zlibWriter.Write(data); err != nil {
		return nil, err
	}
	if err := zlibWriter.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func createZstdData(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	zstdWriter, err := zstd.NewWriter(&buf)
	if err != nil {
		return nil, err
	}
	if _, err := zstdWriter.Write(data); err != nil {
		return nil, err
	}
	if err := zstdWriter.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func TestDecodeResponseBody_Local_Gzip(t *testing.T) {
	testData := []byte("Hello, World! This is a test message for gzip compression.")

	compressedData, err := createGzipData(testData)
	if err != nil {
		t.Fatalf("Failed to create gzip data: %v", err)
	}

	body := io.NopCloser(bytes.NewReader(compressedData))
	result, err := azuretls.DecodeResponseBody(body, "gzip")

	if err != nil {
		t.Fatalf("DecodeResponseBody failed: %v", err)
	}

	if !bytes.Equal(result, testData) {
		t.Fatalf("Expected %s, got %s", string(testData), string(result))
	}
}

func TestDecodeResponseBody_Local_Brotli(t *testing.T) {
	testData := []byte("Hello, World! This is a test message for brotli compression.")

	compressedData, err := createBrotliData(testData)
	if err != nil {
		t.Fatalf("Failed to create brotli data: %v", err)
	}

	body := io.NopCloser(bytes.NewReader(compressedData))
	result, err := azuretls.DecodeResponseBody(body, "br")

	if err != nil {
		t.Fatalf("DecodeResponseBody failed: %v", err)
	}

	if !bytes.Equal(result, testData) {
		t.Fatalf("Expected %s, got %s", string(testData), string(result))
	}
}

func TestDecodeResponseBody_Local_Deflate(t *testing.T) {
	testData := []byte("Hello, World! This is a test message for deflate compression.")

	compressedData, err := createZlibData(testData)
	if err != nil {
		t.Fatalf("Failed to create zlib data: %v", err)
	}

	body := io.NopCloser(bytes.NewReader(compressedData))
	result, err := azuretls.DecodeResponseBody(body, "deflate")

	if err != nil {
		t.Fatalf("DecodeResponseBody failed: %v", err)
	}

	if !bytes.Equal(result, testData) {
		t.Fatalf("Expected %s, got %s", string(testData), string(result))
	}
}

func TestDecodeResponseBody_Local_Zstd(t *testing.T) {
	testData := []byte("Hello, World! This is a test message for zstd compression.")

	compressedData, err := createZstdData(testData)
	if err != nil {
		t.Fatalf("Failed to create zstd data: %v", err)
	}

	body := io.NopCloser(bytes.NewReader(compressedData))
	result, err := azuretls.DecodeResponseBody(body, "zstd")

	if err != nil {
		t.Fatalf("DecodeResponseBody failed: %v", err)
	}

	if !bytes.Equal(result, testData) {
		t.Fatalf("Expected %s, got %s", string(testData), string(result))
	}
}

func TestDecodeResponseBody_Local_NoEncoding(t *testing.T) {
	testData := []byte("Hello, World! No compression here.")

	body := io.NopCloser(bytes.NewReader(testData))
	result, err := azuretls.DecodeResponseBody(body, "")

	if err != nil {
		t.Fatalf("DecodeResponseBody failed: %v", err)
	}

	if !bytes.Equal(result, testData) {
		t.Fatalf("Expected %s, got %s", string(testData), string(result))
	}
}

func TestDecodeResponseBody_Local_UnsupportedEncoding(t *testing.T) {
	testData := []byte("Hello, World!")

	body := io.NopCloser(bytes.NewReader(testData))
	_, err := azuretls.DecodeResponseBody(body, "unsupported")

	if err == nil {
		t.Fatal("Expected error for unsupported encoding")
	}

	expectedError := "Unsupported encoding: unsupported"
	if err.Error() != expectedError {
		t.Fatalf("Expected error %q, got %q", expectedError, err.Error())
	}
}

func TestDecompressBody_GzipHTTP2(t *testing.T) {
	session := azuretls.NewSession()

	session.OrderedHeaders = azuretls.OrderedHeaders{
		{"Accept-Encoding", "gzip"},
	}

	response, err := session.Get(httpbinBaseURL + "/gzip")

	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(string(response.Body), "\"gzipped\": true") {
		t.Fatal("TestDecompressBody_Gzip failed, expected: ", "\"gzipped\": true", ", got: ", string(response.Body))
	}
}

func TestDecompressBody_GzipWithHTTP2Fingerprint(t *testing.T) {
	session := azuretls.NewSession()

	session.OrderedHeaders = azuretls.OrderedHeaders{
		{"Accept-Encoding", "gzip"},
	}

	if err := session.ApplyHTTP2("1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"); err != nil {
		t.Fatal(err)
	}

	response, err := session.Get(httpbinBaseURL + "/gzip")

	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(string(response.Body), "\"gzipped\": true") {
		t.Fatal("TestDecompressBody_Gzip failed, expected: ", "\"gzipped\": true", ", got: ", string(response.Body))
	}
}

func TestDecompressBody_DeflateHTTP2(t *testing.T) {
	session := azuretls.NewSession()

	session.OrderedHeaders = azuretls.OrderedHeaders{
		{"Accept-Encoding", "deflate"},
	}

	response, err := session.Get(httpbinBaseURL + "/deflate")

	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(string(response.Body), "\"deflated\": true") {
		t.Fatal("TestDecompressBody_Deflate failed, expected: ", "\"deflated\": true", ", got: ", string(response.Body))
	}
}
