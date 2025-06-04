package azuretls

import (
	"errors"
	http "github.com/Noooste/fhttp"
	"sync"
)

// HTTP3Config holds HTTP/3 specific configuration
type HTTP3Config struct {
	// Enable HTTP/3 support
	Enabled bool

	// Force HTTP/3 for all requests (no fallback)
	ForceHTTP3 bool

	// Alt-Svc cache for HTTP/3 discovery
	altSvcCache sync.Map

	// HTTP/3 transport
	transport *HTTP3Transport
}

// EnableHTTP3 enables HTTP/3 support for the session
func (s *Session) EnableHTTP3() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.HTTP3Config == nil {
		s.HTTP3Config = &HTTP3Config{
			Enabled: true,
		}
	}

	transport, err := s.NewHTTP3Transport()
	if err != nil {
		return err
	}

	s.HTTP3Config.transport = transport
	return nil
}

// DisableHTTP3 disables HTTP/3 support
func (s *Session) DisableHTTP3() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.HTTP3Config != nil {
		s.HTTP3Config.Enabled = false
		if s.HTTP3Config.transport != nil {
			_ = s.HTTP3Config.transport.Close()
		}
	}
}

// selectTransport chooses the appropriate transport for a request
func (s *Session) selectTransport(req *Request) (rt http.RoundTripper, err error) {
	defer func() {
		if s.HTTP3Config != nil && rt == s.HTTP3Config.transport {
			req.HttpRequest.Header.Del(http.HeaderOrderKey)
			req.HttpRequest.Header.Del(http.PHeaderOrderKey)
		}
	}()

	// Check if HTTP/3 is forced for this request
	if req.ForceHTTP3 {
		if s.HTTP3Config == nil || !s.HTTP3Config.Enabled {
			return nil, errors.New("HTTP/3 not enabled")
		}
		rt = s.HTTP3Config.transport
		return rt, nil
	}

	// Check if HTTP/3 is available for this host
	if s.HTTP3Config != nil && s.HTTP3Config.Enabled {
		if s.shouldUseHTTP3(req.parsedUrl.Host) {
			rt = s.HTTP3Config.transport
			return rt, nil
		}
	}

	// Fall back to HTTP/2 or HTTP/1.1
	return s.Transport, nil
}

// shouldUseHTTP3 checks if HTTP/3 should be used for a host
func (s *Session) shouldUseHTTP3(host string) bool {
	if s.HTTP3Config == nil || !s.HTTP3Config.Enabled {
		return false
	}

	// Check Alt-Svc cache
	if _, ok := s.HTTP3Config.altSvcCache.Load(host); ok {
		return true
	}

	// Check if ForceHTTP3 is set globally
	return s.HTTP3Config.ForceHTTP3
}

// handleAltSvc processes Alt-Svc headers for HTTP/3 discovery
func (s *Session) handleAltSvc(resp *Response) {
	if s.HTTP3Config == nil || !s.HTTP3Config.Enabled {
		return
	}

	altSvc := resp.Header.Get("Alt-Svc")
	if altSvc == "" {
		return
	}

	if containsHTTP3(altSvc) {
		s.HTTP3Config.altSvcCache.Store(resp.Request.parsedUrl.Host, true)
	}
}

// containsHTTP3 checks if the Alt-Svc header contains HTTP/3
func containsHTTP3(altSvc string) bool {
	// Check for h3 or h3-xx versions
	return contains(altSvc, "h3") || contains(altSvc, "h3-")
}

// contains checks if a string contains a substring
func contains(str, substr string) bool {
	return len(str) >= len(substr) && str[:len(substr)] == substr
}

func listContains[T comparable](list []T, item T) bool {
	for _, v := range list {
		if v == item {
			return true
		}
	}
	return false
}
