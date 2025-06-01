package azuretls

import (
	"context"
	"errors"
	"github.com/Noooste/quic-go"
	tls "github.com/Noooste/utls"
	"net"
)

// dialQUIC establishes a QUIC connection
func (s *Session) dialQUIC(ctx context.Context, addr string, tlsConf *tls.Config, quicConf *quic.Config) (quic.EarlyConnection, error) {
	// Resolve address
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}

	// Apply custom dialer modifications if set
	if s.ModifyDialer != nil {
		// Note: ModifyDialer works with net.Dialer, need adaptation for UDP
		// This is a limitation of the current design
	}

	// Create UDP connection
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, err
	}

	// Handle proxy if configured
	if s.ProxyDialer != nil {
		return s.dialQUICViaProxy(ctx, udpConn, udpAddr, tlsConf, quicConf)
	}

	// Direct QUIC connection
	return quic.DialEarly(ctx, udpConn, udpAddr, tlsConf, quicConf)
}

// dialQUICViaProxy establishes a QUIC connection through a proxy
func (s *Session) dialQUICViaProxy(ctx context.Context, udpConn *net.UDPConn,
	remoteAddr *net.UDPAddr, tlsConf *tls.Config, quicConf *quic.Config) (quic.EarlyConnection, error) {

	switch s.ProxyDialer.ProxyURL.Scheme {
	case "socks5", "socks5h":
		// SOCKS5 UDP ASSOCIATE implementation
		return s.dialQUICViaSocks5(ctx, udpConn, remoteAddr, tlsConf, quicConf)

	case "http", "https":
		// HTTP proxy doesn't support UDP directly
		// Would need CONNECT-UDP or MASQUE protocol
		return nil, errors.New("HTTP proxy not supported for direct QUIC connections")

	default:
		return nil, errors.New("unsupported proxy type for QUIC")
	}
}
