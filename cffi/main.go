package main

/*
#include <stdlib.h>
#include <string.h>

// Response structure for C
typedef struct {
    int status_code;
    char* body;
    int body_len;
    char* headers;
    char* url;
    char* error;
    char* protocol;
} CFfiResponse;

// Request structure for C
typedef struct {
    char* method;
    char* url;
    char* body;
    char* headers;
    char* proxy;
    int timeout_ms;
    int force_http1;
    int force_http3;
    int ignore_body;
    int no_cookie;
    int disable_redirects;
    int max_redirects;
    int insecure_skip_verify;
} CFfiRequest;

// Session configuration structure
typedef struct {
    char* browser;
    char* user_agent;
    char* proxy;
    int timeout_ms;
    int max_redirects;
    int insecure_skip_verify;
    char* ordered_headers;
} CFfiSessionConfig;
*/
import "C"

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"runtime"
	"sync"
	"time"
	"unsafe"

	"github.com/Noooste/azuretls-client"
)

// Version information - will be set during build
var Version = "dev"

// SessionManager manages active sessions with thread safety
type SessionManager struct {
	mu       sync.RWMutex
	sessions map[uintptr]*azuretls.Session
	nextID   uintptr
}

var sessionManager = &SessionManager{
	sessions: make(map[uintptr]*azuretls.Session),
	nextID:   1,
}

// Request structure for JSON marshaling/unmarshaling
type RequestData struct {
	Method             string            `json:"method,omitempty"`
	URL                string            `json:"url"`
	Body               interface{}       `json:"body,omitempty"`
	BodyB64            string            `json:"body_b64,omitempty"` // Base64 encoded binary body
	Headers            map[string]string `json:"headers,omitempty"`
	OrderedHeaders     [][]string        `json:"ordered_headers,omitempty"`
	Proxy              string            `json:"proxy,omitempty"`
	TimeoutMs          int               `json:"timeout_ms,omitempty"`
	ForceHTTP1         bool              `json:"force_http1,omitempty"`
	ForceHTTP3         bool              `json:"force_http3,omitempty"`
	IgnoreBody         bool              `json:"ignore_body,omitempty"`
	NoCookie           bool              `json:"no_cookie,omitempty"`
	DisableRedirects   bool              `json:"disable_redirects,omitempty"`
	MaxRedirects       uint              `json:"max_redirects,omitempty"`
	InsecureSkipVerify bool              `json:"insecure_skip_verify,omitempty"`
}

// SessionConfig structure for JSON marshaling
type SessionConfig struct {
	Browser            string            `json:"browser,omitempty"`
	UserAgent          string            `json:"user_agent,omitempty"`
	Proxy              string            `json:"proxy,omitempty"`
	TimeoutMs          int               `json:"timeout_ms,omitempty"`
	MaxRedirects       uint              `json:"max_redirects,omitempty"`
	InsecureSkipVerify bool              `json:"insecure_skip_verify,omitempty"`
	OrderedHeaders     [][]string        `json:"ordered_headers,omitempty"`
	Headers            map[string]string `json:"headers,omitempty"`
}

// Helper function to convert Go string to C string
func goStringToCString(s string) *C.char {
	if s == "" {
		return nil
	}
	return C.CString(s)
}

// Helper function to convert C string to Go string
func cStringToGoString(cs *C.char) string {
	if cs == nil {
		return ""
	}
	return C.GoString(cs)
}

// Helper function to create a C response structure
func createCResponse(resp *azuretls.Response, err error) *C.CFfiResponse {
	cResp := (*C.CFfiResponse)(C.malloc(C.sizeof_CFfiResponse))
	if cResp == nil {
		return nil
	}

	// Initialize all fields to zero/null
	cResp.status_code = 0
	cResp.body = nil
	cResp.body_len = 0
	cResp.headers = nil
	cResp.url = nil
	cResp.error = nil
	cResp.protocol = nil

	if err != nil {
		cResp.error = goStringToCString(err.Error())
		return cResp
	}

	if resp == nil {
		cResp.error = goStringToCString("response is nil")
		return cResp
	}

	cResp.status_code = C.int(resp.StatusCode)

	if resp.Body != nil {
		cResp.body = goStringToCString(string(resp.Body))
		cResp.body_len = C.int(len(resp.Body))
	}

	if resp.Header != nil {
		headerBytes, _ := json.Marshal(resp.Header)
		cResp.headers = goStringToCString(string(headerBytes))
	}

	cResp.url = goStringToCString(resp.Url)

	// Determine protocol from response
	protocol := "HTTP/1.1"
	if resp.HttpResponse != nil {
		if resp.HttpResponse.ProtoMajor == 2 {
			protocol = "HTTP/2"
		} else if resp.HttpResponse.Proto != "" {
			protocol = resp.HttpResponse.Proto
		}
	}

	cResp.protocol = goStringToCString(protocol)

	return cResp
}

// Thread-safe method to get a session
func (sm *SessionManager) getSession(sessionID uintptr) (*azuretls.Session, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	session, exists := sm.sessions[sessionID]
	return session, exists
}

// Thread-safe method to add a session
func (sm *SessionManager) addSession(session *azuretls.Session) uintptr {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sessionID := sm.nextID
	sm.sessions[sessionID] = session
	sm.nextID++
	return sessionID
}

// Thread-safe method to remove a session
func (sm *SessionManager) removeSession(sessionID uintptr) *azuretls.Session {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	if session, exists := sm.sessions[sessionID]; exists {
		delete(sm.sessions, sessionID)
		return session
	}
	return nil
}

// Thread-safe method to close all sessions
func (sm *SessionManager) closeAllSessions() {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	for id, session := range sm.sessions {
		session.Close()
		delete(sm.sessions, id)
	}
}

//export azuretls_session_new
func azuretls_session_new(configJSON *C.char) uintptr {
	session := azuretls.NewSession()

	if configJSON != nil {
		configStr := cStringToGoString(configJSON)
		var config SessionConfig
		if err := json.Unmarshal([]byte(configStr), &config); err == nil {
			// Apply configuration
			if config.Browser != "" {
				session.Browser = config.Browser
			}
			if config.UserAgent != "" {
				session.UserAgent = config.UserAgent
			}
			if config.Proxy != "" {
				session.SetProxy(config.Proxy)
			}
			if config.TimeoutMs > 0 {
				session.SetTimeout(time.Duration(config.TimeoutMs) * time.Millisecond)
			}
			if config.MaxRedirects > 0 {
				session.MaxRedirects = config.MaxRedirects
			}
			session.InsecureSkipVerify = config.InsecureSkipVerify

			if len(config.OrderedHeaders) > 0 {
				session.OrderedHeaders = make(azuretls.OrderedHeaders, len(config.OrderedHeaders))
				for i, header := range config.OrderedHeaders {
					session.OrderedHeaders[i] = header
				}
			}

			if len(config.Headers) > 0 {
				for k, v := range config.Headers {
					session.Header.Set(k, v)
				}
			}
		}
	}

	sessionID := sessionManager.addSession(session)

	// Prevent session from being garbage collected
	runtime.SetFinalizer(session, nil)

	return sessionID
}

//export azuretls_session_close
func azuretls_session_close(sessionID uintptr) {
	if session := sessionManager.removeSession(sessionID); session != nil {
		session.Close()
	}
}

//export azuretls_session_do
func azuretls_session_do(sessionID uintptr, requestJSON *C.char) *C.CFfiResponse {
	session, exists := sessionManager.getSession(sessionID)
	if !exists {
		return createCResponse(nil, fmt.Errorf("session not found"))
	}

	if requestJSON == nil {
		return createCResponse(nil, fmt.Errorf("request JSON is null"))
	}

	requestStr := cStringToGoString(requestJSON)
	var reqData RequestData
	if err := json.Unmarshal([]byte(requestStr), &reqData); err != nil {
		return createCResponse(nil, fmt.Errorf("failed to parse request JSON: %v", err))
	}

	// Create request
	req := &azuretls.Request{
		Method: reqData.Method,
		Url:    reqData.URL,
		Body:   reqData.Body,
	}

	if reqData.TimeoutMs > 0 {
		req.TimeOut = time.Duration(reqData.TimeoutMs) * time.Millisecond
	}

	req.ForceHTTP1 = reqData.ForceHTTP1
	req.ForceHTTP3 = reqData.ForceHTTP3
	req.IgnoreBody = reqData.IgnoreBody
	req.NoCookie = reqData.NoCookie
	req.DisableRedirects = reqData.DisableRedirects
	req.InsecureSkipVerify = reqData.InsecureSkipVerify

	if reqData.MaxRedirects > 0 {
		req.MaxRedirects = reqData.MaxRedirects
	}

	// Handle headers
	if len(reqData.OrderedHeaders) > 0 {
		req.OrderedHeaders = make(azuretls.OrderedHeaders, len(reqData.OrderedHeaders))
		for i, header := range reqData.OrderedHeaders {
			req.OrderedHeaders[i] = header
		}
	} else if len(reqData.Headers) > 0 {
		req.Header = make(map[string][]string)
		for k, v := range reqData.Headers {
			req.Header[k] = []string{v}
		}
	}

	// Decode Base64 body if present
	if reqData.BodyB64 != "" {
		bodyBytes, err := base64.StdEncoding.DecodeString(reqData.BodyB64)
		if err == nil {
			req.Body = bodyBytes
		}
	}

	// Execute request
	resp, err := session.Do(req)
	return createCResponse(resp, err)
}

//export azuretls_session_do_bytes
func azuretls_session_do_bytes(sessionID uintptr, method *C.char, url *C.char, headersJSON *C.char, body *C.uchar, bodyLen C.size_t) *C.CFfiResponse {
	session, exists := sessionManager.getSession(sessionID)
	if !exists {
		return createCResponse(nil, fmt.Errorf("session not found"))
	}

	if method == nil || url == nil {
		return createCResponse(nil, fmt.Errorf("method and URL are required"))
	}

	methodStr := cStringToGoString(method)
	urlStr := cStringToGoString(url)

	// Create request
	req := &azuretls.Request{
		Method: methodStr,
		Url:    urlStr,
	}

	// Handle binary body
	if body != nil && bodyLen > 0 {
		// Convert C bytes to Go slice
		bodyBytes := C.GoBytes(unsafe.Pointer(body), C.int(bodyLen))
		req.Body = bodyBytes
	}

	// Parse headers if provided
	if headersJSON != nil {
		headersStr := cStringToGoString(headersJSON)
		var headers map[string]string
		if err := json.Unmarshal([]byte(headersStr), &headers); err == nil {
			req.Header = make(map[string][]string)
			for k, v := range headers {
				req.Header[k] = []string{v}
			}
		}
	}

	// Execute request
	resp, err := session.Do(req)
	return createCResponse(resp, err)
}

//export azuretls_session_apply_ja3
func azuretls_session_apply_ja3(sessionID uintptr, ja3 *C.char, navigator *C.char) *C.char {
	session, exists := sessionManager.getSession(sessionID)
	if !exists {
		return goStringToCString("session not found")
	}

	ja3Str := cStringToGoString(ja3)
	navStr := cStringToGoString(navigator)

	if navStr == "" {
		navStr = azuretls.Chrome
	}

	if err := session.ApplyJa3(ja3Str, navStr); err != nil {
		return goStringToCString(err.Error())
	}

	return nil
}

//export azuretls_session_apply_http2
func azuretls_session_apply_http2(sessionID uintptr, fingerprint *C.char) *C.char {
	session, exists := sessionManager.getSession(sessionID)
	if !exists {
		return goStringToCString("session not found")
	}

	fpStr := cStringToGoString(fingerprint)
	if err := session.ApplyHTTP2(fpStr); err != nil {
		return goStringToCString(err.Error())
	}

	return nil
}

//export azuretls_session_apply_http3
func azuretls_session_apply_http3(sessionID uintptr, fingerprint *C.char) *C.char {
	session, exists := sessionManager.getSession(sessionID)
	if !exists {
		return goStringToCString("session not found")
	}

	fpStr := cStringToGoString(fingerprint)
	if err := session.ApplyHTTP3(fpStr); err != nil {
		return goStringToCString(err.Error())
	}

	return nil
}

//export azuretls_session_set_proxy
func azuretls_session_set_proxy(sessionID uintptr, proxy *C.char) *C.char {
	session, exists := sessionManager.getSession(sessionID)
	if !exists {
		return goStringToCString("session not found")
	}

	proxyStr := cStringToGoString(proxy)
	if err := session.SetProxy(proxyStr); err != nil {
		return goStringToCString(err.Error())
	}

	return nil
}

//export azuretls_session_clear_proxy
func azuretls_session_clear_proxy(sessionID uintptr) {
	session, exists := sessionManager.getSession(sessionID)
	if exists {
		session.ClearProxy()
	}
}

//export azuretls_session_add_pins
func azuretls_session_add_pins(sessionID uintptr, urlStr *C.char, pinsJSON *C.char) *C.char {
	session, exists := sessionManager.getSession(sessionID)
	if !exists {
		return goStringToCString("session not found")
	}

	urlString := cStringToGoString(urlStr)
	pinsString := cStringToGoString(pinsJSON)

	parsedURL, err := url.Parse(urlString)
	if err != nil {
		return goStringToCString(fmt.Sprintf("invalid URL: %v", err))
	}

	var pins []string
	if err := json.Unmarshal([]byte(pinsString), &pins); err != nil {
		return goStringToCString(fmt.Sprintf("failed to parse pins JSON: %v", err))
	}

	if err := session.AddPins(parsedURL, pins); err != nil {
		return goStringToCString(err.Error())
	}

	return nil
}

//export azuretls_session_clear_pins
func azuretls_session_clear_pins(sessionID uintptr, urlStr *C.char) *C.char {
	session, exists := sessionManager.getSession(sessionID)
	if !exists {
		return goStringToCString("session not found")
	}

	urlString := cStringToGoString(urlStr)
	parsedURL, err := url.Parse(urlString)
	if err != nil {
		return goStringToCString(fmt.Sprintf("invalid URL: %v", err))
	}

	if err := session.ClearPins(parsedURL); err != nil {
		return goStringToCString(err.Error())
	}

	return nil
}

//export azuretls_session_get_ip
func azuretls_session_get_ip(sessionID uintptr) *C.char {
	session, exists := sessionManager.getSession(sessionID)
	if !exists {
		return goStringToCString("session not found")
	}

	ip, err := session.Ip()
	if err != nil {
		return goStringToCString(fmt.Sprintf("error: %v", err))
	}

	return goStringToCString(ip)
}

//export azuretls_free_string
func azuretls_free_string(str *C.char) {
	if str != nil {
		C.free(unsafe.Pointer(str))
	}
}

//export azuretls_free_response
func azuretls_free_response(resp *C.CFfiResponse) {
	if resp != nil {
		if resp.body != nil {
			C.free(unsafe.Pointer(resp.body))
		}
		if resp.headers != nil {
			C.free(unsafe.Pointer(resp.headers))
		}
		if resp.url != nil {
			C.free(unsafe.Pointer(resp.url))
		}
		if resp.error != nil {
			C.free(unsafe.Pointer(resp.error))
		}
		if resp.protocol != nil {
			C.free(unsafe.Pointer(resp.protocol))
		}
		C.free(unsafe.Pointer(resp))
	}
}

//export azuretls_version
func azuretls_version() *C.char {
	return goStringToCString(Version)
}

//export azuretls_init
func azuretls_init() {
	// Initialize the library if needed
}

//export azuretls_cleanup
func azuretls_cleanup() {
	// Close all active sessions using thread-safe method
	sessionManager.closeAllSessions()
}

func main() {
	// Required for building as shared library
}
