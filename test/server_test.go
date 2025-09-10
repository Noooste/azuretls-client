package azuretls_test

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

type Response struct {
	Message    string            `json:"message"`
	Headers    map[string]string `json:"headers"`
	Compressed string            `json:"compressed"`
	Gzipped    bool              `json:"gzipped,omitempty"`
	Deflated   bool              `json:"deflated,omitempty"`
	Brotli     bool              `json:"brotli,omitempty"`
	Zstd       bool              `json:"zstd,omitempty"`
	Method     string            `json:"method"`
	URL        string            `json:"url"`
}

func compressGzip(data []byte) ([]byte, error) {
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

func compressDeflate(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	deflateWriter := zlib.NewWriter(&buf)
	if _, err := deflateWriter.Write(data); err != nil {
		return nil, err
	}
	if err := deflateWriter.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func compressBrotli(data []byte) ([]byte, error) {
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

func compressZstd(data []byte) ([]byte, error) {
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

func getHeaders(r *http.Request) map[string]string {
	headers := make(map[string]string)
	for name, values := range r.Header {
		headers[name] = strings.Join(values, ", ")
	}
	return headers
}

func gzipHandler(w http.ResponseWriter, r *http.Request) {
	resp := Response{
		Message:    "This is a gzip compressed response",
		Headers:    getHeaders(r),
		Compressed: "gzip",
		Gzipped:    true,
		Method:     r.Method,
		URL:        r.URL.String(),
	}

	jsonData, err := json.Marshal(resp)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	compressedData, err := compressGzip(jsonData)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Encoding", "gzip")
	w.Write(compressedData)
}

func deflateHandler(w http.ResponseWriter, r *http.Request) {
	resp := Response{
		Message:    "This is a deflate compressed response",
		Headers:    getHeaders(r),
		Compressed: "deflate",
		Deflated:   true,
		Method:     r.Method,
		URL:        r.URL.String(),
	}

	jsonData, err := json.Marshal(resp)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	compressedData, err := compressDeflate(jsonData)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Encoding", "deflate")
	w.Write(compressedData)
}

func brotliHandler(w http.ResponseWriter, r *http.Request) {
	resp := Response{
		Message:    "This is a brotli compressed response",
		Headers:    getHeaders(r),
		Compressed: "brotli",
		Brotli:     true,
		Method:     r.Method,
		URL:        r.URL.String(),
	}

	jsonData, err := json.Marshal(resp)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	compressedData, err := compressBrotli(jsonData)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Encoding", "br")
	w.Write(compressedData)
}

func zstdHandler(w http.ResponseWriter, r *http.Request) {
	resp := Response{
		Message:    "This is a zstd compressed response",
		Headers:    getHeaders(r),
		Compressed: "zstd",
		Zstd:       true,
		Method:     r.Method,
		URL:        r.URL.String(),
	}

	jsonData, err := json.Marshal(resp)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	compressedData, err := compressZstd(jsonData)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Encoding", "zstd")
	w.Write(compressedData)
}

func plainHandler(w http.ResponseWriter, r *http.Request) {
	resp := Response{
		Message:    "This is a plain uncompressed response",
		Headers:    getHeaders(r),
		Compressed: "none",
		Method:     r.Method,
		URL:        r.URL.String(),
	}

	jsonData, err := json.Marshal(resp)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonData)
}

// Handler qui choisit la compression selon l'Accept-Encoding
func autoHandler(w http.ResponseWriter, r *http.Request) {
	acceptEncoding := r.Header.Get("Accept-Encoding")

	resp := Response{
		Message: "This response uses auto-negotiated compression",
		Headers: getHeaders(r),
		Method:  r.Method,
		URL:     r.URL.String(),
	}

	// Priorité: brotli > gzip > deflate > zstd > plain
	if strings.Contains(acceptEncoding, "br") {
		resp.Compressed = "brotli"
		resp.Brotli = true
		w.Header().Set("Content-Encoding", "br")
		jsonData, err := json.Marshal(resp)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		compressedData, err := compressBrotli(jsonData)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(compressedData)
	} else if strings.Contains(acceptEncoding, "gzip") {
		resp.Compressed = "gzip"
		resp.Gzipped = true
		jsonData, err := json.Marshal(resp)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		compressedData, err := compressGzip(jsonData)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Encoding", "gzip")
		w.Write(compressedData)
	} else if strings.Contains(acceptEncoding, "deflate") {
		resp.Compressed = "deflate"
		resp.Deflated = true

		jsonData, err := json.Marshal(resp)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		compressedData, err := compressDeflate(jsonData)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Encoding", "deflate")
		w.Write(compressedData)
	} else if strings.Contains(acceptEncoding, "zstd") {
		resp.Compressed = "zstd"
		resp.Zstd = true

		jsonData, err := json.Marshal(resp)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		compressedData, err := compressZstd(jsonData)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Encoding", "zstd")
		w.Write(compressedData)
	} else {
		jsonData, err := json.Marshal(resp)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		resp.Compressed = "none"
		w.Write(jsonData)
	}

}

func startServer() {
	http.HandleFunc("/gzip", gzipHandler)
	http.HandleFunc("/deflate", deflateHandler)
	http.HandleFunc("/brotli", brotliHandler)
	http.HandleFunc("/zstd", zstdHandler)
	http.HandleFunc("/plain", plainHandler)
	http.HandleFunc("/auto", autoHandler)

	// Handler pour afficher les endpoints disponibles
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		endpoints := map[string]string{
			"/gzip":    "Returns gzip compressed JSON response",
			"/deflate": "Returns deflate compressed JSON response",
			"/brotli":  "Returns brotli compressed JSON response",
			"/zstd":    "Returns zstd compressed JSON response",
			"/plain":   "Returns uncompressed JSON response",
			"/auto":    "Returns response compressed based on Accept-Encoding header",
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"message":   "Local compression test server",
			"endpoints": endpoints,
		})
	})

	fmt.Println("Starting compression test server on :8080")
	fmt.Println("Available endpoints:")
	fmt.Println("  GET /         - Show this help")
	fmt.Println("  GET /gzip     - Gzip compressed response")
	fmt.Println("  GET /deflate  - Deflate compressed response")
	fmt.Println("  GET /brotli   - Brotli compressed response")
	fmt.Println("  GET /zstd     - Zstd compressed response")
	fmt.Println("  GET /plain    - Plain uncompressed response")
	fmt.Println("  GET /auto     - Auto-negotiate compression")

	log.Fatal(http.ListenAndServe(":8080", nil))
}
