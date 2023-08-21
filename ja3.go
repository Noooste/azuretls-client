package azuretls

import (
	"errors"
	"github.com/Noooste/fhttp/http2"
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
}

func DefaultTlsSpecifications() TlsSpecifications {
	signatureAlg := []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256,
		tls.ECDSAWithP256AndSHA256,
		tls.PSSWithSHA256,
		tls.PKCS1WithSHA256,
		tls.ECDSAWithP384AndSHA384,
		tls.PSSWithSHA384,
		tls.PKCS1WithSHA384,
		tls.PSSWithSHA512,
		tls.PKCS1WithSHA512,
	}

	return TlsSpecifications{
		AlpnProtocols:       []string{"h2", "http/1.1"},
		SignatureAlgorithms: signatureAlg,
		SupportedVersions: []uint16{tls.VersionTLS13,
			tls.VersionTLS12,
			tls.VersionTLS11,
		},
		CertCompressionAlgos:                    []tls.CertCompressionAlgo{tls.CertCompressionBrotli},
		DelegatedCredentialsAlgorithmSignatures: signatureAlg,
		PSKKeyExchangeModes:                     []uint8{tls.PskModeDHE},
		SignatureAlgorithmsCert:                 signatureAlg,
		ApplicationSettingsProtocols:            []string{"h2"},
		RenegotiationSupport:                    tls.RenegotiateOnceAsClient,
	}
}

// ApplyJa3 sets the JA3 string for the session using the default TLS specifications.
func (s *Session) ApplyJa3(ja3, navigator string) error {
	return s.ApplyJa3WithSpecifications(ja3, DefaultTlsSpecifications(), navigator)
}

// ApplyJa3WithSpecifications sets the JA3 string for the session using the provided TLS specifications.
func (s *Session) ApplyJa3WithSpecifications(ja3 string, specifications TlsSpecifications, navigator string) error {
	_, err := stringToSpec(ja3, DefaultTlsSpecifications(), navigator)
	if err != nil {
		return err
	}
	s.GetClientHelloSpec = func() *tls.ClientHelloSpec {
		specs, _ := stringToSpec(ja3, specifications, navigator)
		return specs
	}
	return nil
}

// stringToSpec converts a JA3 string to a tls.ClientHelloSpec
// Use DefaultTlsSpecifications() to get the default specifications
func stringToSpec(ja3 string, specifications TlsSpecifications, navigator string) (*tls.ClientHelloSpec, error) {
	specs := &tls.ClientHelloSpec{}

	information := strings.Split(ja3, ",")

	if len(information) != 5 {
		return nil, errors.New("invalid JA3")
	}

	for i := range information {
		if information[i] == "" {
			return nil, errors.New("invalid JA3")
		}
	}

	v, err := strconv.Atoi(information[0])
	if err != nil {
		return nil, errors.New("invalid JA3")
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

	//extensions
	extensions, _, maxVers, err := getExtensions(rawExtensions, &specifications, pointFormats, curves, navigator)

	if err != nil {
		return nil, err
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
			builtExtensions = append(builtExtensions, &tls.UtlsExtendedMasterSecretExtension{})
			break

		case "27":
			if specifications.CertCompressionAlgos != nil {
				builtExtensions = append(builtExtensions, &tls.CompressCertificateExtension{Algorithms: specifications.CertCompressionAlgos})
			} else {
				builtExtensions = append(builtExtensions, &tls.CompressCertificateExtension{Algorithms: []tls.CertCompressionAlgo{tls.CertCompressionBrotli}})
			}
			break

		case "28":
			builtExtensions = append(builtExtensions, &tls.FakeRecordSizeLimitExtension{})
			break

		case "35":
			builtExtensions = append(builtExtensions, &tls.SessionTicketExtension{})
			break

		case "34":
			builtExtensions = append(builtExtensions, &tls.DelegatedCredentialsExtension{})
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
				builtExtensions = append(builtExtensions, &tls.ApplicationSettingsExtension{SupportedProtocols: specifications.ApplicationSettingsProtocols})
			} else {
				builtExtensions = append(builtExtensions, &tls.ApplicationSettingsExtension{SupportedProtocols: []string{"h2"}})
			}
			break

		case "65281":
			builtExtensions = append(builtExtensions, &tls.RenegotiationInfoExtension{Renegotiation: specifications.RenegotiationSupport})
			break

		default:
			return nil, 0, 0, errors.New("invalid extension : " + extension)
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
	case Opera:
		return []tls.SignatureScheme{
			1027,
			1283,
			1539,
			2052,
			2053,
			2054,
			2057,
			2058,
			2059,
			1025,
			1281,
			1537,
			1026,
			771,
			769,
			770,
			515,
			513,
			514,
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

// GetLastChromeVersion apply the latest Chrome version
// Current Chrome version : 114
func GetLastChromeVersion() *tls.ClientHelloSpec {
	extensions := []tls.TLSExtension{
		&tls.UtlsGREASEExtension{},
		&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
			{Group: tls.CurveID(tls.GREASE_PLACEHOLDER), Data: []byte{0}},
			{Group: tls.X25519},
		}},
		&tls.ALPNExtension{AlpnProtocols: []string{
			http2.NextProtoTLS,
			"http/1.1",
		}},
		&tls.SNIExtension{},
		&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
			tls.ECDSAWithP256AndSHA256,
			tls.PSSWithSHA256,
			tls.PKCS1WithSHA256,
			tls.ECDSAWithP384AndSHA384,
			tls.PSSWithSHA384,
			tls.PKCS1WithSHA384,
			tls.PSSWithSHA512,
			tls.PKCS1WithSHA512,
		}},
		&tls.UtlsExtendedMasterSecretExtension{},
		&tls.SessionTicketExtension{},
		&tls.SCTExtension{},
		&tls.RenegotiationInfoExtension{},
		&tls.PSKKeyExchangeModesExtension{Modes: []uint8{
			tls.PskModeDHE,
		}},
		&tls.ApplicationSettingsExtension{SupportedProtocols: []string{http2.NextProtoTLS}},
		&tls.CompressCertificateExtension{Algorithms: []tls.CertCompressionAlgo{
			tls.CertCompressionBrotli,
		}},
		&tls.SupportedVersionsExtension{Versions: []uint16{
			tls.GREASE_PLACEHOLDER,
			tls.VersionTLS13,
			tls.VersionTLS12,
		}},
		&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
			tls.GREASE_PLACEHOLDER,
			tls.X25519,
			tls.CurveP256,
			tls.CurveP384,
		}},
		&tls.StatusRequestExtension{},
		&tls.SupportedPointsExtension{SupportedPoints: []byte{
			0x00, // pointFormatUncompressed
		}},
		&tls.UtlsGREASEExtension{},
		&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
	}

	extensionsLength := len(extensions)
	lastTwo := extensionsLength - 2

	// since version 110, Chrome TLS Client Hello extensions are shuffled
	// https://www.fastly.com/blog/a-first-look-at-chromes-tls-clienthello-permutation-in-the-wild
	random.Shuffle(extensionsLength, func(i, j int) {
		if i >= lastTwo || j >= lastTwo || i == 0 || j == 0 {
			// ignore GREASE extensions and padding
			return
		}
		extensions[i], extensions[j] = extensions[j], extensions[i]
	})

	return &tls.ClientHelloSpec{
		CipherSuites: []uint16{
			tls.GREASE_PLACEHOLDER,
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
		CompressionMethods: []byte{
			0x00, // compressionNone
		},
		Extensions: extensions,
	}
}

func GetLastIosVersion() *tls.ClientHelloSpec {
	return &tls.ClientHelloSpec{
		CipherSuites: []uint16{
			tls.GREASE_PLACEHOLDER,
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		},
		CompressionMethods: []uint8{
			0x00, // compressionNone
		},
		Extensions: []tls.TLSExtension{
			&tls.UtlsGREASEExtension{},
			&tls.SNIExtension{},
			&tls.UtlsExtendedMasterSecretExtension{},
			&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
			&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
				tls.CurveID(tls.GREASE_PLACEHOLDER),
				tls.X25519,
				tls.CurveP256,
				tls.CurveP384,
				tls.CurveP521,
			}},
			&tls.SupportedPointsExtension{SupportedPoints: []byte{
				0x00, // pointFormatUncompressed
			}},
			&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
			&tls.StatusRequestExtension{},
			&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
				tls.ECDSAWithP256AndSHA256,
				tls.PSSWithSHA256,
				tls.PKCS1WithSHA256,
				tls.ECDSAWithP384AndSHA384,
				tls.ECDSAWithSHA1,
				tls.PSSWithSHA384,
				tls.PSSWithSHA384,
				tls.PKCS1WithSHA384,
				tls.PSSWithSHA512,
				tls.PKCS1WithSHA512,
				tls.PKCS1WithSHA1,
			}},
			&tls.SCTExtension{},
			&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
				{Group: tls.CurveID(tls.GREASE_PLACEHOLDER), Data: []byte{0}},
				{Group: tls.X25519},
			}},
			&tls.PSKKeyExchangeModesExtension{Modes: []uint8{
				tls.PskModeDHE,
			}},
			&tls.SupportedVersionsExtension{Versions: []uint16{
				tls.GREASE_PLACEHOLDER,
				tls.VersionTLS13,
				tls.VersionTLS12,
			}},
			&tls.CompressCertificateExtension{Algorithms: []tls.CertCompressionAlgo{
				tls.CertCompressionZlib,
			}},
			&tls.UtlsGREASEExtension{},
			&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
		},
	}
}
