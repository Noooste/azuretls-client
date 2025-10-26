package azuretls

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	tls "github.com/Noooste/utls"
	"net"
	"net/url"
	"sync"
	"time"
)

var DefaultPinManager *PinManager

func init() {
	DefaultPinManager = NewPinManager()
}

// Fingerprint computes the SHA256 Fingerprint of a given certificate's
// RawSubjectPublicKeyInfo. This is useful for obtaining a consistent
// identifier for a certificate's public key. The result is then base64-encoded
// to give a string representation which can be conveniently stored or compared.
func Fingerprint(c *x509.Certificate) string {
	digest := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(digest[:])
}

type PinHost struct {
	mu sync.RWMutex    // Read-Write mutex ensuring concurrent access safety.
	m  map[string]bool // A map representing the certificate pins. If a pin exists and is set to true, it is considered valid.
}

// PinManager is a concurrency-safe struct designed to manage
// and verify public key pinning for SSL/TLS certificates. Public key pinning
// is a security feature which can be used to specify a set of valid public keys
// for a particular web service, thus preventing man-in-the-middle attacks
// due to rogue certificates.
type PinManager struct {
	hosts map[string]*PinHost // A map of PinHost instances, each representing a set of pins for a specific host.
	mu    sync.RWMutex        // Read-Write mutex ensuring concurrent access safety.
}

// NewPinManager initializes a new instance of PinManager with
// an empty set of pins. This is the entry point to begin using
// the pinning functionality.
func NewPinManager() *PinManager {
	return &PinManager{
		hosts: make(map[string]*PinHost),
	}
}

// AddPin safely adds a new pin (Fingerprint) to the PinManager.
// If a service's certificate changes (e.g., due to renewal), new pins
// should be added to continue trusting the service.
func (p *PinHost) AddPin(pin string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.m[pin] = true
}

func (p *PinHost) AddPins(pin []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, v := range pin {
		p.m[v] = true
	}
}

// Verify checks whether a given certificate's public key is
// currently pinned in the PinManager. This method should be
// used during the SSL/TLS handshake to ensure the remote service's
// certificate matches a previously pinned public key.
func (p *PinHost) Verify(c *x509.Certificate) bool {
	fp := Fingerprint(c)

	p.mu.RLock()
	defer p.mu.RUnlock()

	v, ok := p.m[fp]

	return ok && v
}

// New establishes a connection to the provided address, retrieves
// its SSL/TLS certificates, and pins their public keys in the
// PinManager. This can be used initially to populate the PinManager
// with pins from a trusted service.
//
// If a Session is provided, it will use the same TLS configuration
// (including ClientHello spec) as the actual connection to ensure
// the same certificate chain is obtained.
func (p *PinHost) New(addr string, s *Session) (err error) {
	var cs tls.ConnectionState

	if s != nil {
		// Use the same TLS configuration as the actual connection
		// Split addr and port to get hostname
		hostname, _, err := net.SplitHostPort(addr)
		if err != nil {
			return errors.New("failed to split addr and port: " + err.Error())
		}

		// Create a raw TCP connection first (not TLS)
		dialer := &net.Dialer{
			Timeout:   s.TimeOut,
			KeepAlive: 30 * time.Second,
		}

		conn, err := dialer.Dial("tcp", addr)
		if err != nil {
			return errors.New("failed to dial for pin generation: " + err.Error())
		}

		// Create TLS config
		config := &tls.Config{
			ServerName:         hostname,
			InsecureSkipVerify: true,
		}

		if s.ModifyConfig != nil {
			if err := s.ModifyConfig(config); err != nil {
				conn.Close()
				return err
			}
		}

		// Use UClient with the same ClientHello spec as actual connections
		tlsConn := tls.UClient(conn, config, tls.HelloCustom)

		var fn = s.GetClientHelloSpec
		if fn == nil {
			fn = GetBrowserClientHelloFunc(s.Browser)
		}

		specs := fn()

		if err = tlsConn.ApplyPreset(specs); err != nil {
			conn.Close()
			return errors.New("failed to apply preset for pin generation: " + err.Error())
		}

		if err = tlsConn.Handshake(); err != nil {
			conn.Close()
			return errors.New("failed to handshake for pin generation: " + err.Error())
		}

		cs = tlsConn.ConnectionState()
		_ = tlsConn.Close()
	} else {
		// Fallback to simple dial if no Session is provided
		dial, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true})
		if err != nil {
			return errors.New("failed to generate pins for " + addr + ": " + err.Error())
		}
		cs = dial.ConnectionState()
		_ = dial.Close()
	}

	var pins = make([]string, 0, len(cs.PeerCertificates))
	for _, c := range cs.PeerCertificates {
		pins = append(pins, Fingerprint(c))
	}

	p.mu.Lock()
	for _, c := range pins {
		p.m[c] = true
	}
	p.mu.Unlock()

	return nil
}

func (p *PinHost) GetPins() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()

	var pins = make([]string, 0, len(p.m))
	for k, v := range p.m {
		if !v {
			continue
		}
		pins = append(pins, k)
	}

	return pins
}

func (p *PinManager) Clear(host string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.hosts[host]; !ok {
		return
	}
	delete(p.hosts, host)
}

func (p *PinManager) AddHost(host string, s *Session) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.hosts[host]; !ok {
		ph := &PinHost{
			m: make(map[string]bool),
		}
		if err := ph.New(host, s); err != nil {
			return err
		}
		p.hosts[host] = ph
	}
	return nil
}

func (p *PinManager) AddPins(host string, pins []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if v, ok := p.hosts[host]; !ok {
		var gp = make(map[string]bool, len(pins))
		for _, v := range pins {
			gp[v] = true
		}
		p.hosts[host] = &PinHost{
			m: gp,
		}
	} else {
		v.AddPins(pins)
	}
}

// GetHost retrieves the PinHost associated with a specific host.
// This is useful for checking if a host has any pinned certificates
// and for verifying certificates against the pins.
func (p *PinManager) GetHost(host string) *PinHost {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.hosts[host]
}

// AddPins associates a set of certificate pins with a given URL within
// a session. This allows for URL-specific pinning, useful in scenarios
// where different services (URLs) are trusted with different certificates.
func (s *Session) AddPins(u *url.URL, pins []string) error {
	s.PinManager.AddPins(getHost(u), pins)
	return nil
}

// ClearPins removes all pinned certificates associated
// with a specific URL in the session. This can be used to reset trust
// settings or in scenarios where a service's certificate is no longer deemed trustworthy.
func (s *Session) ClearPins(u *url.URL) error {
	s.PinManager.Clear(getHost(u))
	return nil
}
