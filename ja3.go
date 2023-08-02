package azuretls

import (
	"errors"
	"github.com/Noooste/fhttp/http2"
	tls "github.com/Noooste/utls"
	"strconv"
	"strings"
)

type TlsVersion uint16

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

func (s *Session) ApplyJa3(ja3, navigator string) error {
	_, err := stringToSpec(ja3, DefaultTlsSpecifications(), navigator)
	if err != nil {
		return err
	}
	s.GetClientHelloSpec = func() *tls.ClientHelloSpec {
		specs, _ := stringToSpec(ja3, DefaultTlsSpecifications(), navigator)
		return specs
	}
	return nil
}

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

	ciphers := strings.Split(information[1], "-")
	rawExtensions := strings.Split(information[2], "-")

	curves := strings.Split(information[3], "-")
	if len(curves) == 1 && curves[0] == "" {
		curves = []string{}
	}

	pointFormats := strings.Split(information[4], "-")
	if len(pointFormats) == 1 && pointFormats[0] == "" {
		pointFormats = []string{}
	}

	//ciphers suite
	finalCiphers, convertErr := TurnToUint(ciphers, navigator, true)
	if convertErr != "" {
		return nil, errors.New(convertErr + "cipher")
	}
	specs.CipherSuites = finalCiphers

	//extensions

	extensions, minVers, maxVers, err := GetExtensions(rawExtensions, specifications, pointFormats, curves, navigator)

	if err != nil {
		return nil, err
	}
	specs.Extensions = extensions
	specs.TLSVersMin = minVers
	specs.TLSVersMax = maxVers

	return specs, nil
}

func TurnToUint(value []string, navigator string, isCipherSuite bool) ([]uint16, string) {
	var converted []uint16
	var nextIndex int

	if isCipherSuite && navigator == Chrome {
		converted = make([]uint16, len(value)+1)
		converted[0] = tls.GREASE_PLACEHOLDER
		nextIndex = 1
	} else {
		converted = make([]uint16, len(value))

	}

	//cipher suites
	for _, cipher := range value {
		value, err := strconv.Atoi(cipher)

		if err != nil {
			return nil, cipher + " is not a valid "
		}

		converted[nextIndex] = uint16(value)

		nextIndex++
	}

	return converted, ""
}

func GetExtensions(extensions []string, specifications TlsSpecifications, defaultPointsFormat []string, defaultCurves []string, navigator string) ([]tls.TLSExtension, uint16, uint16, error) {
	var builtExtensions []tls.TLSExtension
	var nextIndex int
	var minVers uint16 = tls.VersionTLS10
	var maxVers uint16 = tls.VersionTLS13

	switch navigator {
	case Chrome:
		builtExtensions = make([]tls.TLSExtension, len(extensions)+1)
		builtExtensions[0] = &tls.UtlsGREASEExtension{}
		nextIndex = 1
	default:
		builtExtensions = make([]tls.TLSExtension, len(extensions))
	}

	for _, extension := range extensions {
		switch extension {
		case "0":
			builtExtensions[nextIndex] = &tls.SNIExtension{}
			break

		case "5":
			builtExtensions[nextIndex] = &tls.StatusRequestExtension{}
			break

		case "10":
			var finalCurves []tls.CurveID
			var i int
			switch navigator {
			case Chrome:
				finalCurves = make([]tls.CurveID, len(defaultCurves)+1)
				finalCurves[0] = tls.CurveID(tls.GREASE_PLACEHOLDER)
				i = 1
			default:
				finalCurves = make([]tls.CurveID, len(defaultCurves))
			}
			for j := range defaultCurves {
				value, err := strconv.Atoi(defaultCurves[j])
				if err != nil {
					return nil, 0, 0, errors.New(defaultCurves[j] + " is not a valid curve")
				}
				finalCurves[j+i] = tls.CurveID(value)
			}
			builtExtensions[nextIndex] = &tls.SupportedCurvesExtension{Curves: finalCurves}
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
			builtExtensions[nextIndex] = &tls.SupportedPointsExtension{SupportedPoints: finalPointsFormat}
			break

		case "13":
			if specifications.SignatureAlgorithms != nil {
				builtExtensions[nextIndex] = &tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: specifications.SignatureAlgorithms}
			} else {
				builtExtensions[nextIndex] = &tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: GetSupportedAlgorithms(navigator)}
			}
			break

		case "16":
			if specifications.AlpnProtocols != nil {
				builtExtensions[nextIndex] = &tls.ALPNExtension{AlpnProtocols: specifications.AlpnProtocols}
			} else {
				builtExtensions[nextIndex] = &tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}}
			}
			break

		case "17":
			builtExtensions[nextIndex] = &tls.StatusRequestV2Extension{}
			break

		case "18":
			builtExtensions[nextIndex] = &tls.SCTExtension{}
			break

		case "21":
			builtExtensions[nextIndex] = &tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle}
			break

		case "22":
			builtExtensions[nextIndex] = &tls.GenericExtension{Id: 22}
			break

		case "23":
			builtExtensions[nextIndex] = &tls.UtlsExtendedMasterSecretExtension{}
			break

		case "27":
			if specifications.CertCompressionAlgos != nil {
				builtExtensions[nextIndex] = &tls.CompressCertificateExtension{Algorithms: specifications.CertCompressionAlgos}
			} else {
				builtExtensions[nextIndex] = &tls.CompressCertificateExtension{Algorithms: []tls.CertCompressionAlgo{tls.CertCompressionBrotli}}
			}
			break

		case "28":
			builtExtensions[nextIndex] = &tls.FakeRecordSizeLimitExtension{}
			break

		case "35":
			builtExtensions[nextIndex] = &tls.SessionTicketExtension{}
			break

		case "34":
			var supportedAlgorithms []tls.SignatureScheme
			if specifications.DelegatedCredentialsAlgorithmSignatures != nil {
				supportedAlgorithms = make([]tls.SignatureScheme, len(specifications.DelegatedCredentialsAlgorithmSignatures))
			} else {
				supportedAlgorithms = []tls.SignatureScheme{
					tls.ECDSAWithP256AndSHA256,
					tls.ECDSAWithP384AndSHA384,
					tls.ECDSAWithP521AndSHA512,
					tls.ECDSAWithSHA1,
				}
			}
			builtExtensions[nextIndex] = &tls.DelegatedCredentialsExtension{AlgorithmsSignature: supportedAlgorithms}
			break

		case "41":
			builtExtensions[nextIndex] = &tls.GenericExtension{Id: 41}
			break

		case "43":
			var supportedVersions []uint16
			if versions := specifications.SupportedVersions; versions != nil {
				supportedVersions = make([]uint16, len(versions))
				for i, specVersion := range versions {
					supportedVersions[i] = specVersion

					if specVersion == tls.GREASE_PLACEHOLDER {
						continue
					}

					if specVersion < minVers || minVers == 0 {
						minVers = specVersion
					}

					if specVersion > maxVers || minVers == 0 {
						maxVers = specVersion
					}
				}
			} else {
				supportedVersions, minVers, maxVers = GetSupportedVersion(navigator)
			}
			builtExtensions[nextIndex] = &tls.SupportedVersionsExtension{Versions: supportedVersions}
			break

		case "44":
			builtExtensions[nextIndex] = &tls.CookieExtension{}
			break

		case "45":
			if specifications.PSKKeyExchangeModes != nil {
				builtExtensions[nextIndex] = &tls.PSKKeyExchangeModesExtension{Modes: specifications.PSKKeyExchangeModes}
			} else {
				builtExtensions[nextIndex] = &tls.PSKKeyExchangeModesExtension{Modes: []uint8{tls.PskModeDHE}}
			}
			break

		case "49":
			builtExtensions[nextIndex] = &tls.GenericExtension{Id: 49}
			break

		case "50":
			if specifications.SignatureAlgorithmsCert != nil {
				builtExtensions[nextIndex] = &tls.SignatureAlgorithmsCertExtension{SupportedSignatureAlgorithms: specifications.SignatureAlgorithmsCert}
			} else {
				builtExtensions[nextIndex] = &tls.SignatureAlgorithmsCertExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{}}
			}
			break

		case "51":
			switch navigator {
			case Chrome:
				builtExtensions[nextIndex] = &tls.KeyShareExtension{KeyShares: []tls.KeyShare{
					{Group: tls.GREASE_PLACEHOLDER, Data: []byte{0}},
					{Group: tls.X25519},
				}}

			default: //firefox
				builtExtensions[nextIndex] = &tls.KeyShareExtension{KeyShares: []tls.KeyShare{
					{Group: tls.X25519},
					{Group: tls.CurveP256},
				}}
			}
			break

		case "30032":
			builtExtensions[nextIndex] = &tls.GenericExtension{Id: 0x7550, Data: []byte{0}}
			break

		case "13172":
			builtExtensions[nextIndex] = &tls.NPNExtension{}
			break

		case "17513":
			if specifications.ApplicationSettingsProtocols != nil {
				builtExtensions[nextIndex] = &tls.ApplicationSettingsExtension{SupportedALPNList: specifications.ApplicationSettingsProtocols}
			} else {
				builtExtensions[nextIndex] = &tls.ApplicationSettingsExtension{SupportedALPNList: []string{"h2"}}
			}
			break

		case "65281":
			builtExtensions[nextIndex] = &tls.RenegotiationInfoExtension{Renegotiation: specifications.RenegotiationSupport}
			break
		}

		nextIndex++
	}

	length := len(builtExtensions)
	for _, el := range builtExtensions {
		if el == nil {
			length--
		}
	}

	if length != len(builtExtensions) {
		newBuildExtensions := make([]tls.TLSExtension, length)

		index := 0
		for _, el := range builtExtensions {
			if el != nil {
				newBuildExtensions[index] = el
				index++
			}
		}

		return newBuildExtensions, minVers, maxVers, nil
	}

	return builtExtensions, minVers, maxVers, nil
}

func GetSupportedAlgorithms(navigator string) []tls.SignatureScheme {
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

func GetSupportedVersion(navigator string) ([]uint16, uint16, uint16) {
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
		&tls.ApplicationSettingsExtension{SupportedALPNList: []string{http2.NextProtoTLS}},
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
