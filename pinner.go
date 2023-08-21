package azuretls

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	tls "github.com/Noooste/utls"
	"net/url"
	"sync"
)

// Fingerprint computes the SHA256 Fingerprint of a given certificate's
// RawSubjectPublicKeyInfo. This is useful for obtaining a consistent
// identifier for a certificate's public key. The result is then base64-encoded
// to give a string representation which can be conveniently stored or compared.
func Fingerprint(c *x509.Certificate) string {
	digest := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(digest[:])
}

// PinManager is a concurrency-safe struct designed to manage
// and verify public key pinning for SSL/TLS certificates. Public key pinning
// is a security feature which can be used to specify a set of valid public keys
// for a particular web service, thus preventing man-in-the-middle attacks
// due to rogue certificates.
type PinManager struct {
	redo bool
	mu   *sync.RWMutex   // Read-Write mutex ensuring concurrent access safety.
	m    map[string]bool // A map representing the certificate pins. If a pin exists and is set to true, it is considered valid.
}

// NewPinManager initializes a new instance of PinManager with
// an empty set of pins. This is the entry point to begin using
// the pinning functionality.
func NewPinManager() *PinManager {
	return &PinManager{
		mu: new(sync.RWMutex),
		m:  make(map[string]bool),
	}
}

// AddPin safely adds a new pin (Fingerprint) to the PinManager.
// If a service's certificate changes (e.g., due to renewal), new pins
// should be added to continue trusting the service.
func (p *PinManager) AddPin(pin string) {
	p.mu.Lock()
	p.m[pin] = true
	p.mu.Unlock()
}

// Verify checks whether a given certificate's public key is
// currently pinned in the PinManager. This method should be
// used during the SSL/TLS handshake to ensure the remote service's
// certificate matches a previously pinned public key.
func (p *PinManager) Verify(c *x509.Certificate) bool {
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
func (p *PinManager) New(addr string) (err error) {
	dial, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return errors.New("failed to generate pins for " + addr + ": " + err.Error())
	}

	cs := dial.ConnectionState()
	_ = dial.Close()

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

// AddPins associates a set of certificate pins with a given URL within
// a session. This allows for URL-specific pinning, useful in scenarios
// where different services (URLs) are trusted with different certificates.
func (s *Session) AddPins(u *url.URL, pins []string) error {
	conn := s.Connections.Get(u)
	conn.mu.Lock()
	defer conn.mu.Unlock()

	if conn.Pins == nil {
		conn.Pins = NewPinManager()
	}

	for _, pin := range pins {
		conn.Pins.m[pin] = true
	}

	return nil
}

// ClearPins removes all pinned certificates associated
// with a specific URL in the session. This can be used to reset trust
// settings or in scenarios where a service's certificate is no longer deemed trustworthy.
func (s *Session) ClearPins(u *url.URL) error {
	conn := s.Connections.Get(u)

	conn.mu.Lock()
	defer conn.mu.Unlock()

	for k := range conn.Pins.m {
		conn.Pins.m[k] = false
	}

	conn.Pins.redo = true

	return nil
}
