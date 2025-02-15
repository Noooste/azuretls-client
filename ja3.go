package azuretls

import (
	"errors"
	"fmt"
	tls "github.com/Noooste/utls"
	"strconv"
	"strings"
)

// TlsSpecifications struct contains various fields representing TLS handshake settings.
type TlsSpecifications struct {
	AlpnProtocols                           []string
	SignatureAlgorithms                     []tls.SignatureScheme
	SupportedVersions                       []uint16
	CertCompressionAlgos                    []tls.CertCompressionAlgo
	DelegatedCredentialsAlgorithmSignatures []tls.SignatureScheme
	PSKKeyExchangeModes                     []uint8
	SignatureAlgorithmsCert                 []tls.SignatureScheme
	ApplicationSettingsProtocols            []string
	RenegotiationSupport                    tls.RenegotiationSupport
	RecordSizeLimit                         uint16
}

func DefaultTlsSpecifications(navigator string) *TlsSpecifications {
	var signatureAlg []tls.SignatureScheme
	var recordSizeLimit uint16

	var supportedVersions []uint16

	switch navigator {
	case Firefox:
		signatureAlg = []tls.SignatureScheme{
			tls.ECDSAWithP256AndSHA256,
			tls.ECDSAWithP384AndSHA384,
			tls.ECDSAWithP521AndSHA512,
			tls.PSSWithSHA256,
			tls.PSSWithSHA384,
			tls.PSSWithSHA512,
			tls.PKCS1WithSHA256,
			tls.PKCS1WithSHA384,
			tls.PKCS1WithSHA512,
			tls.ECDSAWithSHA1,
			tls.PKCS1WithSHA1,
		}
		supportedVersions = []uint16{
			tls.VersionTLS13,
			tls.VersionTLS12,
		}

		recordSizeLimit = 0x4001
	default:
		signatureAlg = []tls.SignatureScheme{
			tls.ECDSAWithP256AndSHA256,
			tls.PSSWithSHA256,
			tls.PKCS1WithSHA256,
			tls.ECDSAWithP384AndSHA384,
			tls.PSSWithSHA384,
			tls.PKCS1WithSHA384,
			tls.PSSWithSHA512,
			tls.PKCS1WithSHA512,
		}

		supportedVersions = []uint16{
			tls.GREASE_PLACEHOLDER,
			tls.VersionTLS13,
			tls.VersionTLS12,
		}
	}

	return &TlsSpecifications{
		AlpnProtocols:        []string{"h2", "http/1.1"},
		SignatureAlgorithms:  signatureAlg,
		SupportedVersions:    supportedVersions,
		CertCompressionAlgos: []tls.CertCompressionAlgo{tls.CertCompressionBrotli},
		DelegatedCredentialsAlgorithmSignatures: []tls.SignatureScheme{ // only for firefox
			tls.ECDSAWithP256AndSHA256,
			tls.ECDSAWithP384AndSHA384,
			tls.ECDSAWithP521AndSHA512,
			tls.ECDSAWithSHA1,
		},
		PSKKeyExchangeModes: []uint8{
			tls.PskModeDHE,
		},
		SignatureAlgorithmsCert:      signatureAlg,
		ApplicationSettingsProtocols: []string{"h2"},
		RenegotiationSupport:         tls.RenegotiateOnceAsClient,
		RecordSizeLimit:              recordSizeLimit,
	}
}

// ApplyJa3 applies JA3 settings to the session from a fingerprint.
// JA3 is a method for creating fingerprints from SSL/TLS client hellos,
// which can be used for client identification or detection. The fingerprint is
// constructed from an MD5 hash of string representations of various handshake
// parameters, specifically:
//
//	<SSL Version>|<Accepted Ciphers>|<List of Extensions>|<Elliptic Curves>|<Elliptic Curve Formats>
//
// e.g.,
//
//	769,4865-4866-4867-49196-49195-52393-49200-49199-49172...|0-5-10-11-...|23-24-25|0
//
// This string is then MD5-hashed to produce a 32-character representation, which is the JA3 fingerprint.
//
// Any absent field in the client hello will raise an error.
func (s *Session) ApplyJa3(ja3, navigator string) error {
	return s.ApplyJa3WithSpecifications(ja3, DefaultTlsSpecifications(navigator), navigator)
}

// ApplyJa3WithSpecifications applies JA3 settings to the session from a fingerprint.
// JA3 is a method for creating fingerprints from SSL/TLS client hellos,
// which can be used for client identification or detection. The fingerprint is
// constructed from an MD5 hash of string representations of various handshake
// parameters, specifically:
//
//	<SSL Version>|<Accepted Ciphers>|<List of Extensions>|<Elliptic Curves>|<Elliptic Curve Formats>
//
// e.g.,
//
//	769,4865-4866-4867-49196-49195-52393-49200-49199-49172...|0-5-10-11-...|23-24-25|0
//
// This string is then MD5-hashed to produce a 32-character representation, which is the JA3 fingerprint.
//
// Any absent field in the client hello will raise an error.
func (s *Session) ApplyJa3WithSpecifications(ja3 string, specifications *TlsSpecifications, navigator string) error {
	_, err := stringToSpec(ja3, specifications, navigator)
	if err != nil {
		return err
	}

	s.GetClientHelloSpec = func() *tls.ClientHelloSpec {
		specs, _ := stringToSpec(ja3, specifications, navigator)
		return specs
	}
	return nil
}

const (
	invalidJA3 = "invalid JA3 fingerprint : %s"
)

// stringToSpec converts a JA3 string to a tls.ClientHelloSpec
// Use DefaultTlsSpecifications() to get the default specifications
func stringToSpec(ja3 string, specifications *TlsSpecifications, navigator string) (*tls.ClientHelloSpec, error) {
	specs := &tls.ClientHelloSpec{}

	information := strings.Split(ja3, ",")

	if len(information) != 5 {
		return nil, fmt.Errorf(invalidJA3, "length is not 5")
	}

	v, err := strconv.Atoi(information[0])
	if err != nil {
		return nil, fmt.Errorf(invalidJA3, "invalid version")
	}

	if information[1] == "" {
		return nil, fmt.Errorf(invalidJA3, "no cipher")
	}

	ciphers := strings.Split(information[1], "-")

	rawExtensions := strings.Split(information[2], "-")

	curves := strings.Split(information[3], "-")

	pointFormats := strings.Split(information[4], "-")

	//ciphers suite
	finalCiphers, convertErr := turnToUint(ciphers, navigator)
	if convertErr != "" {
		return nil, errors.New(convertErr + "cipher")
	}

	specs.CipherSuites = finalCiphers

	var (
		extensions []tls.TLSExtension
		maxVers    uint16
	)
	//extensions
	if information[2] != "" {
		extensions, _, maxVers, err = getExtensions(rawExtensions, specifications, pointFormats, curves, navigator)

		if err != nil {
			return nil, err
		}
	} else {
		extensions, _, maxVers = []tls.TLSExtension{}, 0, tls.VersionTLS13
		if information[3] != "" {
			var (
				c   = make([]tls.CurveID, 0, len(curves))
				val int
			)

			for _, curve := range curves {
				val, err = strconv.Atoi(curve)
				if err != nil {
					return nil, errors.New(curve + " is not a valid curve")
				}
				c = append(c, tls.CurveID(val))
			}

			extensions = append(extensions, &tls.SupportedCurvesExtension{Curves: c})
		}
		if information[4] != "" {
			var (
				pf  = make([]uint8, 0, len(pointFormats))
				val int
			)

			for _, pointFormat := range pointFormats {
				val, err = strconv.Atoi(pointFormat)
				if err != nil {
					return nil, errors.New(pointFormat + " is not a valid point format")
				}
				pf = append(pf, uint8(val))
			}

			extensions = append(extensions, &tls.SupportedPointsExtension{SupportedPoints: pf})

			specs.CompressionMethods = pf
		}
	}

	specs.Extensions = extensions
	specs.TLSVersMin = uint16(v)
	specs.TLSVersMax = maxVers

	return specs, nil
}

func turnToUint(ciphers []string, navigator string) ([]uint16, string) {
	var converted []uint16

	if navigator == Chrome {
		converted = make([]uint16, 1, len(ciphers)+1)
		converted[0] = tls.GREASE_PLACEHOLDER
	} else {
		converted = make([]uint16, 0, len(ciphers))
	}

	//cipher suites
	for _, cipher := range ciphers {
		v, err := strconv.Atoi(cipher)
		if err != nil {
			return nil, cipher + " is not a valid "
		}
		converted = append(converted, uint16(v))
	}

	return converted, ""
}

func isGrease(e uint16) bool {
	i := (e & 0xf0) | 0x0a
	i |= i << 8
	return i == e
}

//gocyclo:ignore
func getExtensions(extensions []string, specifications *TlsSpecifications, defaultPointsFormat []string, defaultCurves []string, navigator string) ([]tls.TLSExtension, uint16, uint16, error) {
	var (
		builtExtensions []tls.TLSExtension
		minVers         uint16 = tls.VersionTLS10
		maxVers         uint16 = tls.VersionTLS13
	)

	switch navigator {
	case Chrome:
		builtExtensions = make([]tls.TLSExtension, 1, len(extensions)+1)
		builtExtensions[0] = &tls.UtlsGREASEExtension{}
	default:
		builtExtensions = make([]tls.TLSExtension, 0, len(extensions))
	}

	for _, extension := range extensions {
		switch extension {
		case "0":
			builtExtensions = append(builtExtensions, &tls.SNIExtension{})
			break

		case "5":
			builtExtensions = append(builtExtensions, &tls.StatusRequestExtension{})
			break

		case "10":
			var finalCurves []tls.CurveID
			switch navigator {
			case Chrome:
				finalCurves = make([]tls.CurveID, 1, len(defaultCurves)+1)
				finalCurves[0] = tls.CurveID(tls.GREASE_PLACEHOLDER)
			default:
				finalCurves = make([]tls.CurveID, 0, len(defaultCurves))
			}
			for j := range defaultCurves {
				value, err := strconv.Atoi(defaultCurves[j])
				if err != nil {
					return nil, 0, 0, errors.New(defaultCurves[j] + " is not a valid curve")
				}
				finalCurves = append(finalCurves, tls.CurveID(value))
			}
			builtExtensions = append(builtExtensions, &tls.SupportedCurvesExtension{Curves: finalCurves})
			break

		case "11":
			var finalPointsFormat []uint8
			finalPointsFormat = make([]uint8, len(defaultPointsFormat))
			for j := range defaultPointsFormat {
				value, err := strconv.Atoi(defaultPointsFormat[j])
				if err != nil {
					return nil, 0, 0, errors.New(defaultPointsFormat[j] + " is not a valid curve")
				}
				finalPointsFormat[j] = uint8(value)
			}
			builtExtensions = append(builtExtensions, &tls.SupportedPointsExtension{SupportedPoints: finalPointsFormat})
			break

		case "13":
			if specifications.SignatureAlgorithms != nil {
				builtExtensions = append(builtExtensions, &tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: specifications.SignatureAlgorithms})
			} else {
				builtExtensions = append(builtExtensions, &tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: getSupportedAlgorithms(navigator)})
			}
			break

		case "16":
			if specifications.AlpnProtocols != nil {
				builtExtensions = append(builtExtensions, &tls.ALPNExtension{AlpnProtocols: specifications.AlpnProtocols})
			} else {
				builtExtensions = append(builtExtensions, &tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}})
			}
			break

		case "17":
			builtExtensions = append(builtExtensions, &tls.StatusRequestV2Extension{})
			break

		case "18":
			builtExtensions = append(builtExtensions, &tls.SCTExtension{})
			break

		case "21":
			builtExtensions = append(builtExtensions, &tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle})
			break

		case "22":
			builtExtensions = append(builtExtensions, &tls.GenericExtension{Id: 22})
			break

		case "23":
			builtExtensions = append(builtExtensions, &tls.ExtendedMasterSecretExtension{})
			break

		case "27":
			if specifications.CertCompressionAlgos != nil {
				builtExtensions = append(builtExtensions, &tls.UtlsCompressCertExtension{Algorithms: specifications.CertCompressionAlgos})
			} else {
				builtExtensions = append(builtExtensions, &tls.UtlsCompressCertExtension{Algorithms: []tls.CertCompressionAlgo{tls.CertCompressionBrotli}})
			}
			break

		case "28":
			builtExtensions = append(builtExtensions, &tls.FakeRecordSizeLimitExtension{
				Limit: specifications.RecordSizeLimit,
			})
			break

		case "35":
			builtExtensions = append(builtExtensions, &tls.SessionTicketExtension{})
			break

		case "34":
			builtExtensions = append(builtExtensions, &tls.FakeDelegatedCredentialsExtension{
				SupportedSignatureAlgorithms: specifications.DelegatedCredentialsAlgorithmSignatures,
			})
			break

		case "41":
			builtExtensions = append(builtExtensions, &tls.GenericExtension{Id: 41})
			break

		case "43":
			var supportedVersions []uint16
			if versions := specifications.SupportedVersions; versions != nil {
				supportedVersions = specifications.SupportedVersions
				for _, specVersion := range versions {
					switch {
					case isGrease(specVersion):
						continue
					case specVersion < tls.VersionTLS10:
						return nil, 0, 0, errors.New("> TLS 1.0 is not supported")
					case specVersion > tls.VersionTLS13:
						return nil, 0, 0, errors.New("> TLS 1.3 is not supported")
					case specVersion < minVers, minVers == 0:
						minVers = specVersion
					case specVersion > maxVers, maxVers == 0:
						maxVers = specVersion
					}
				}
			} else {
				supportedVersions, minVers, maxVers = getSupportedVersion(navigator)
			}

			builtExtensions = append(builtExtensions, &tls.SupportedVersionsExtension{
				Versions: supportedVersions,
			})
			break

		case "44":
			builtExtensions = append(builtExtensions, &tls.CookieExtension{})
			break

		case "45":
			if specifications.PSKKeyExchangeModes != nil {
				builtExtensions = append(builtExtensions, &tls.PSKKeyExchangeModesExtension{Modes: specifications.PSKKeyExchangeModes})
			} else {
				builtExtensions = append(builtExtensions, &tls.PSKKeyExchangeModesExtension{Modes: []uint8{tls.PskModeDHE}})
			}
			break

		case "49":
			builtExtensions = append(builtExtensions, &tls.GenericExtension{Id: 49})
			break

		case "50":
			if specifications.SignatureAlgorithmsCert != nil {
				builtExtensions = append(builtExtensions, &tls.SignatureAlgorithmsCertExtension{SupportedSignatureAlgorithms: specifications.SignatureAlgorithmsCert})
			} else {
				builtExtensions = append(builtExtensions, &tls.SignatureAlgorithmsCertExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{}})
			}
			break

		case "51":
			switch navigator {
			case Chrome:
				builtExtensions = append(builtExtensions, &tls.KeyShareExtension{KeyShares: []tls.KeyShare{
					{Group: tls.GREASE_PLACEHOLDER, Data: []byte{0}},
					{Group: tls.X25519},
				}})

			default: //firefox
				builtExtensions = append(builtExtensions, &tls.KeyShareExtension{KeyShares: []tls.KeyShare{
					{Group: tls.X25519},
					{Group: tls.CurveP256},
				}})
			}
			break

		case "13172":
			builtExtensions = append(builtExtensions, &tls.NPNExtension{})
			break

		case "17513":
			if specifications.ApplicationSettingsProtocols != nil {
				builtExtensions = append(builtExtensions, &tls.OldApplicationSettingsExtension{SupportedProtocols: specifications.ApplicationSettingsProtocols})
			} else {
				builtExtensions = append(builtExtensions, &tls.OldApplicationSettingsExtension{SupportedProtocols: []string{"h2"}})
			}
			break

		case "17613":
			if specifications.ApplicationSettingsProtocols != nil {
				builtExtensions = append(builtExtensions, &tls.ApplicationSettingsExtension{SupportedProtocols: specifications.ApplicationSettingsProtocols})
			} else {
				builtExtensions = append(builtExtensions, &tls.ApplicationSettingsExtension{SupportedProtocols: []string{"h2"}})
			}
			break

		case "65037":
			builtExtensions = append(builtExtensions, tls.BoringGREASEECH())

		case "65281":
			builtExtensions = append(builtExtensions, &tls.RenegotiationInfoExtension{Renegotiation: specifications.RenegotiationSupport})
			break

		default:
			return nil, 0, 0, errors.New("invalid extension : " + extension)
		}
	}

	if navigator == Chrome {
		lastIndex := len(extensions) - 1
		last := extensions[lastIndex]

		switch last {
		case "21":
			lastIndex := len(builtExtensions) - 1
			last := builtExtensions[lastIndex]
			builtExtensions[lastIndex] = &tls.UtlsGREASEExtension{}
			builtExtensions = append(builtExtensions, last)
		default:
			builtExtensions = append(builtExtensions, &tls.UtlsGREASEExtension{})
		}
	}

	return builtExtensions, minVers, maxVers, nil
}

func getSupportedAlgorithms(navigator string) []tls.SignatureScheme {
	switch navigator {
	case Firefox:
		return []tls.SignatureScheme{
			tls.ECDSAWithP256AndSHA256,
			tls.ECDSAWithP384AndSHA384,
			tls.ECDSAWithP521AndSHA512,
			tls.PSSWithSHA256,
			tls.PSSWithSHA384,
			tls.PSSWithSHA512,
			tls.PKCS1WithSHA256,
			tls.PKCS1WithSHA384,
			tls.PKCS1WithSHA512,
			tls.ECDSAWithSHA1,
			tls.PKCS1WithSHA1,
		}
	default: //chrome
		return []tls.SignatureScheme{
			tls.ECDSAWithP256AndSHA256,
			tls.PSSWithSHA256,
			tls.PKCS1WithSHA256,
			tls.ECDSAWithP384AndSHA384,
			tls.PSSWithSHA384,
			tls.PKCS1WithSHA384,
			tls.PSSWithSHA512,
			tls.PKCS1WithSHA512,
		}
	}
}

func getSupportedVersion(navigator string) ([]uint16, uint16, uint16) {
	switch navigator {
	case Chrome:
		return []uint16{
			tls.GREASE_PLACEHOLDER,
			tls.VersionTLS13,
			tls.VersionTLS12,
		}, tls.VersionTLS12, tls.VersionTLS13
	default:
		return []uint16{
			tls.VersionTLS13,
			tls.VersionTLS12,
		}, tls.VersionTLS12, tls.VersionTLS13
	}
}
