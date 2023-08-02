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

func fingerprint(c *x509.Certificate) string {
	digest := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(digest[:])
}

type PinManager struct {
	mu *sync.RWMutex
	m  map[string]bool
}

func NewPinManager() *PinManager {
	return &PinManager{
		mu: new(sync.RWMutex),
		m:  make(map[string]bool),
	}
}

func (p *PinManager) AddPin(pin string) {
	p.mu.Lock()
	p.m[pin] = true
	p.mu.Unlock()
}

func (p *PinManager) Verify(c *x509.Certificate) bool {
	fp := fingerprint(c)

	p.mu.RLock()
	defer p.mu.RUnlock()

	if v, ok := p.m[fp]; ok && v {
		return true
	}

	return false
}

func (p *PinManager) New(addr string) (err error) {
	dial, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return errors.New("failed to generate pins for " + addr + ": " + err.Error())
	}

	defer dial.Close()

	cs := dial.ConnectionState()

	var pins = make([]string, 0, len(cs.PeerCertificates))
	for _, c := range cs.PeerCertificates {
		pins = append(pins, fingerprint(c))
	}

	p.mu.Lock()
	for _, c := range pins {
		p.m[c] = true
	}
	p.mu.Unlock()

	return
}

func (s *Session) AddPins(u *url.URL, pins []string) error {
	conn, err := s.Connections.Get(u)

	if err != nil {
		return err
	}

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

func (s *Session) ClearPins(u *url.URL) error {
	conn, err := s.Connections.Get(u)

	if err != nil {
		return err
	}

	conn.mu.Lock()
	defer conn.mu.Unlock()

	for k := range conn.Pins.m {
		conn.Pins.m[k] = false
	}

	return nil
}
