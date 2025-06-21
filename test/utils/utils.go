package utils

import (
	"encoding/json"
	"fmt"
	"strings"
)

// OrderedMap preserves the order of JSON keys during unmarshaling
type OrderedMap struct {
	Keys   []string
	Values map[string]interface{}
}

// UnmarshalJSON implements custom unmarshaling to preserve key order
func (om *OrderedMap) UnmarshalJSON(data []byte) error {
	// Initialize the map
	om.Values = make(map[string]interface{})
	om.Keys = []string{}

	// Use json.RawMessage to parse without losing order
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	// We need a different approach - parse manually to preserve order
	decoder := json.NewDecoder(strings.NewReader(string(data)))

	// Expect opening brace
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if token != json.Delim('{') {
		return fmt.Errorf("expected {, got %v", token)
	}

	// Parse key-value pairs in order
	for decoder.More() {
		// Get key
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		key, ok := token.(string)
		if !ok {
			return fmt.Errorf("expected string key, got %T", token)
		}

		// Store key in order
		om.Keys = append(om.Keys, key)

		// Get value
		var value interface{}
		if err := decoder.Decode(&value); err != nil {
			return err
		}
		om.Values[key] = value
	}

	// Expect closing brace
	token, err = decoder.Token()
	if err != nil {
		return err
	}
	if token != json.Delim('}') {
		return fmt.Errorf("expected }, got %v", token)
	}

	return nil
}

// GetJSONKeyOrder extracts the order of keys from a JSON string
func GetJSONKeyOrder(jsonStr string) ([]string, error) {
	var om OrderedMap
	if err := json.Unmarshal([]byte(jsonStr), &om); err != nil {
		return nil, err
	}
	return om.Keys, nil
}

// Alternative simpler approach using a different method
func GetJSONKeyOrderSimple(jsonStr string) ([]string, error) {
	decoder := json.NewDecoder(strings.NewReader(jsonStr))

	// Expect opening brace
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	if token != json.Delim('{') {
		return nil, fmt.Errorf("expected {, got %v", token)
	}

	var keys []string

	// Parse key-value pairs in order
	for decoder.More() {
		// Get key
		token, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		key, ok := token.(string)
		if !ok {
			return nil, fmt.Errorf("expected string key, got %T", token)
		}

		keys = append(keys, key)

		// Skip the value
		var value interface{}
		if err := decoder.Decode(&value); err != nil {
			return nil, err
		}
	}

	return keys, nil
}

// ValidateHTTP1HeaderOrder validates header order for HTTP/1.1 responses
// expectedOrder contains the expected order of headers (case-insensitive)
// actualHeaders contains the actual headers from the response
func ValidateHTTP1HeaderOrder(expectedOrder []string, actualHeaders []string) error {
	if len(actualHeaders) == 0 {
		return fmt.Errorf("no headers found in response")
	}

	// Convert expected order to lowercase for comparison
	expectedLower := make([]string, len(expectedOrder))
	for i, header := range expectedOrder {
		expectedLower[i] = strings.ToLower(header)
	}

	// Find positions of expected headers in actual headers
	var foundHeaders []string
	var positions []int

	for _, actualHeader := range actualHeaders {
		// Extract header name (everything before the first colon)
		parts := strings.SplitN(actualHeader, ":", 2)
		if len(parts) < 2 {
			continue
		}
		headerName := strings.ToLower(strings.TrimSpace(parts[0]))

		// Check if this header is in our expected list
		for i, expectedHeader := range expectedLower {
			if headerName == expectedHeader {
				foundHeaders = append(foundHeaders, headerName)
				positions = append(positions, i)
				break
			}
		}
	}

	// Check if we found all expected headers
	if len(foundHeaders) != len(expectedOrder) {
		return fmt.Errorf("not all expected headers found. Expected: %v, Found: %v", expectedOrder, foundHeaders)
	}

	// Check if headers are in the correct order
	for i := 1; i < len(positions); i++ {
		if positions[i] <= positions[i-1] {
			return fmt.Errorf("headers not in expected order. Expected order: %v, Actual order: %v", expectedOrder, foundHeaders)
		}
	}

	return nil
}

// ValidateHTTP2HeaderOrder validates header order for HTTP/2 responses
// expectedOrder contains the expected order of headers (case-insensitive)
// peetResponse contains the parsed response from tls.peet.ws
func ValidateHTTP2HeaderOrder(expectedOrder []string, peetResponse *PeetResponse) error {
	if peetResponse.Http2.SentFrames == nil || len(peetResponse.Http2.SentFrames) == 0 {
		return fmt.Errorf("no HTTP/2 frames found in response")
	}

	// Find HEADERS frame
	var headersFrame *struct {
		FrameType string   `json:"frame_type"`
		Length    int      `json:"length"`
		Settings  []string `json:"settings,omitempty"`
		Increment int      `json:"increment,omitempty"`
		StreamId  int      `json:"stream_id,omitempty"`
		Headers   []string `json:"headers,omitempty"`
		Flags     []string `json:"flags,omitempty"`
		Priority  struct {
			Weight    int `json:"weight"`
			DependsOn int `json:"depends_on"`
			Exclusive int `json:"exclusive"`
		} `json:"priority,omitempty"`
	}

	for i := range peetResponse.Http2.SentFrames {
		if peetResponse.Http2.SentFrames[i].FrameType == "HEADERS" {
			headersFrame = &peetResponse.Http2.SentFrames[i]
			break
		}
	}

	if headersFrame == nil || headersFrame.Headers == nil {
		return fmt.Errorf("no HEADERS frame found in HTTP/2 response")
	}

	// Convert expected order to lowercase for comparison
	expectedLower := make([]string, len(expectedOrder))
	for i, header := range expectedOrder {
		expectedLower[i] = strings.ToLower(header)
	}

	// Extract header names from the HEADERS frame (skip pseudo-headers that start with :)
	var actualHeaderNames []string
	for _, header := range headersFrame.Headers {
		parts := strings.SplitN(header, ":", 2)
		if len(parts) < 2 {
			continue
		}
		headerName := strings.ToLower(strings.TrimSpace(parts[0]))

		// Skip pseudo-headers (they start with :)
		if !strings.HasPrefix(headerName, ":") {
			actualHeaderNames = append(actualHeaderNames, headerName)
		}
	}

	// Find positions of expected headers in actual headers
	var foundHeaders []string
	var positions []int

	for _, actualHeader := range actualHeaderNames {
		for i, expectedHeader := range expectedLower {
			if actualHeader == expectedHeader {
				foundHeaders = append(foundHeaders, actualHeader)
				positions = append(positions, i)
				break
			}
		}
	}

	// Check if we found all expected headers
	if len(foundHeaders) != len(expectedOrder) {
		return fmt.Errorf("not all expected headers found. Expected: %v, Found: %v", expectedOrder, foundHeaders)
	}

	// Check if headers are in the correct order
	for i := 1; i < len(positions); i++ {
		if positions[i] <= positions[i-1] {
			return fmt.Errorf("headers not in expected order. Expected order: %v, Actual order: %v", expectedOrder, foundHeaders)
		}
	}

	return nil
}
