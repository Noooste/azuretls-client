package azuretls

import (
	"github.com/Noooste/fhttp/http2"
	tls "github.com/Noooste/utls"
)

// GetLastChromeVersion apply the latest Chrome version
// Current Chrome version : 121
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
		&tls.ExtendedMasterSecretExtension{},
		&tls.SessionTicketExtension{},
		&tls.SCTExtension{},
		&tls.RenegotiationInfoExtension{},
		&tls.PSKKeyExchangeModesExtension{Modes: []uint8{
			tls.PskModeDHE,
		}},
		&tls.ApplicationSettingsExtension{SupportedProtocols: []string{http2.NextProtoTLS}},
		&tls.UtlsCompressCertExtension{Algorithms: []tls.CertCompressionAlgo{
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
		tls.BoringGREASEECH(),
		&tls.UtlsGREASEExtension{},
		&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
	}

	extensionsLength := len(extensions)
	lastTwo := extensionsLength - 2

	// since version 110, Chrome TLS Client Hello extensions are shuffled
	// https://www.fastly.com/blog/a-first-look-at-chromes-tls-clienthello-permutation-in-the-wild
	rdn.Shuffle(extensionsLength, func(i, j int) {
		if i >= lastTwo || j >= lastTwo || i == 0 || j == 0 {
			// ignore GREASE extensions and padding extension
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
			&tls.ExtendedMasterSecretExtension{},
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
			&tls.UtlsCompressCertExtension{Algorithms: []tls.CertCompressionAlgo{
				tls.CertCompressionZlib,
			}},
			&tls.UtlsGREASEExtension{},
			&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
		},
	}
}
