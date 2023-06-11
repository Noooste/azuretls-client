package azuretls

import (
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	tls "github.com/Noooste/utls"
	"strings"
)

func Contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

// Fingerprint returns the hpkp signature of an x509 certificate
func fingerprint(c *x509.Certificate) string {
	digest := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return fmt.Sprintf("%x", digest[:])
}

func generatePins(addr string) (pins []string) {
	dial, _ := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true})
	cs := dial.ConnectionState()
	pins = make([]string, len(cs.PeerCertificates))

	addr = strings.Split(addr, ":")[0]

	for i, cert := range cs.PeerCertificates {
		for _, name := range cert.DNSNames {
			if name == addr {
				break
			}
		}
		pins[i] = fingerprint(cert)
	}
	return
}

func verifyPins(tlsConn *tls.UConn, pins []string) bool {
	for _, cert := range tlsConn.ConnectionState().PeerCertificates {
		if !Contains(pins, fingerprint(cert)) {
			return false
		}
	}
	return true
}
