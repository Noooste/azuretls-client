package azuretls

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	tls "github.com/Noooste/utls"
	"net/url"
)

func fingerprint(c *x509.Certificate) string {
	digest := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(digest[:])
}

func Contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func generatePins(addr string) (pins []string, err error) {
	dial, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return nil, errors.New("failed to connect to generate pins")
	}

	defer dial.Close()

	cs := dial.ConnectionState()

	pins = make([]string, 0, len(cs.PeerCertificates))
	for _, cert := range cs.PeerCertificates {
		pins = append(pins, fingerprint(cert))
	}

	return
}

func verifyPins(tlsConn *tls.UConn, pins []string) bool {
	for _, cert := range tlsConn.ConnectionState().PeerCertificates {
		if Contains(pins, fingerprint(cert)) {
			return true
		}
	}
	return false
}

func (s *Session) AddPins(u *url.URL, pins []string) error {
	conn, err := s.conns.get(u)

	if err != nil {
		return err
	}

	conn.mu.Lock()
	defer conn.mu.Unlock()

	if conn.pins == nil {
		conn.pins = pins
	} else {
		conn.pins = append(conn.pins, pins...)
	}

	s.VerifyPins = true

	return nil
}
