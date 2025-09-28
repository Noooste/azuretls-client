package utils

import (
	"fmt"
	"strings"
)

type ImpersonateResponse struct {
	Http3 struct {
		PerkText string `json:"perk_text"`
		PerkHash string `json:"perk_hash"`
		Settings []struct {
			Id    int    `json:"id"`
			Name  string `json:"name"`
			Value int    `json:"value"`
		} `json:"settings"`
		Headers *OrderedMap `json:"headers"`
	} `json:"http3"`
	Tls struct {
		CipherSuites []struct {
			Name  string `json:"name"`
			Value int    `json:"value"`
		} `json:"cipher_suites"`
		Extensions []struct {
			Id   int         `json:"id"`
			Name string      `json:"name"`
			Data interface{} `json:"data,omitempty"`
		} `json:"extensions"`
	} `json:"tls"`
}

// ValidateHTTP3HeaderOrder validates header order for HTTP/3 responses
// expectedOrder contains the expected order of headers (case-insensitive)
// impersonateResponse contains the parsed response from fp.impersonate.pro
func ValidateHTTP3HeaderOrder(expectedOrder []string, impersonateResponse *ImpersonateResponse) error {
	if impersonateResponse.Http3.Headers == nil || len(impersonateResponse.Http3.Headers.Keys) == 0 {
		return fmt.Errorf("no HTTP/3 headers found in response")
	}

	var startIndex int

	for _, header := range impersonateResponse.Http3.Headers.Keys {
		if strings.HasPrefix(header, ":") {
			startIndex++
		}
	}

	for i, header := range expectedOrder {
		if i+startIndex >= len(impersonateResponse.Http3.Headers.Keys) {
			return fmt.Errorf("expected header '%s' not found in HTTP/3 response", header)
		}

		actualHeader := strings.ToLower(impersonateResponse.Http3.Headers.Keys[i+startIndex])
		expectedHeader := strings.ToLower(header)

		if actualHeader != expectedHeader {
			return fmt.Errorf("header order mismatch: expected '%s', got '%s'", expectedHeader, actualHeader)
		}
	}

	return nil
}
