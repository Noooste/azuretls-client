package azuretls

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/Noooste/uquic-go"
	"io"
	"net"
	"sync"
	"time"

	tls "github.com/Noooste/utls"
)

const (
	// SOCKS5 version
	socks5Version = 0x05

	// SOCKS5 commands
	socks5Connect      = 0x01
	socks5Bind         = 0x02
	socks5UDPAssociate = 0x03

	// SOCKS5 address types
	socks5IPv4   = 0x01
	socks5Domain = 0x03
	socks5IPv6   = 0x04

	// SOCKS5 authentication methods
	socks5NoAuth       = 0x00
	socks5UserPass     = 0x02
	socks5NoAcceptable = 0xff

	// SOCKS5 reply codes
	socks5Success          = 0x00
	socks5GeneralFailure   = 0x01
	socks5NotAllowed       = 0x02
	socks5NetworkUnreach   = 0x03
	socks5HostUnreach      = 0x04
	socks5ConnRefused      = 0x05
	socks5TTLExpired       = 0x06
	socks5CmdNotSupported  = 0x07
	socks5AddrNotSupported = 0x08
)

// SOCKS5UDPConn wraps a UDP connection through SOCKS5 proxy
type SOCKS5UDPConn struct {
	// Control connection (TCP)
	controlConn net.Conn

	// UDP connection for data
	udpConn *net.UDPConn

	// Proxy UDP relay address
	proxyUDPAddr *net.UDPAddr

	// Target address
	targetAddr string

	// Mutex for thread safety
	mu sync.RWMutex

	// Context for cancellation
	ctx    context.Context
	cancel context.CancelFunc

	// Buffer pool for efficiency
	bufferPool sync.Pool
}

// SOCKS5UDPDialer handles SOCKS5 UDP ASSOCIATE for QUIC
type SOCKS5UDPDialer struct {
	// SOCKS5 proxy address
	ProxyAddr string

	// Authentication
	Username string
	Password string

	// Dialer for control connection
	Dialer net.Dialer

	// Active connections
	connections sync.Map
}

// NewSOCKS5UDPDialer creates a new SOCKS5 UDP dialer
func NewSOCKS5UDPDialer(proxyAddr, username, password string) *SOCKS5UDPDialer {
	return &SOCKS5UDPDialer{
		ProxyAddr: proxyAddr,
		Username:  username,
		Password:  password,
		Dialer: net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		},
	}
}

// DialUDP establishes a UDP connection through SOCKS5 proxy
func (d *SOCKS5UDPDialer) DialUDP(ctx context.Context, network string, remoteAddr string) (*SOCKS5UDPConn, error) {
	// Parse remote address
	host, port, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid remote address: %w", err)
	}

	// Establish control connection
	controlConn, err := d.Dialer.DialContext(ctx, "tcp", d.ProxyAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to SOCKS5 proxy: %w", err)
	}

	// SOCKS5 handshake
	if err := d.socks5Handshake(controlConn); err != nil {
		controlConn.Close()
		return nil, err
	}

	// Send UDP ASSOCIATE request
	relayAddr, err := d.sendUDPAssociate(controlConn, host, port)
	if err != nil {
		controlConn.Close()
		return nil, err
	}

	// Create local UDP socket
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		controlConn.Close()
		return nil, fmt.Errorf("failed to create UDP socket: %w", err)
	}

	ctx, cancel := context.WithCancel(ctx)

	conn := &SOCKS5UDPConn{
		controlConn:  controlConn,
		udpConn:      udpConn,
		proxyUDPAddr: relayAddr,
		targetAddr:   remoteAddr,
		ctx:          ctx,
		cancel:       cancel,
		bufferPool: sync.Pool{
			New: func() interface{} {
				return make([]byte, 65507) // Max UDP packet size
			},
		},
	}

	// Start control connection monitor
	go conn.monitorControlConnection()

	return conn, nil
}

// socks5Handshake performs SOCKS5 authentication handshake
func (d *SOCKS5UDPDialer) socks5Handshake(conn net.Conn) error {
	// Send greeting
	var methods []byte
	if d.Username != "" && d.Password != "" {
		methods = []byte{socks5Version, 2, socks5NoAuth, socks5UserPass}
	} else {
		methods = []byte{socks5Version, 1, socks5NoAuth}
	}

	if _, err := conn.Write(methods); err != nil {
		return fmt.Errorf("failed to send greeting: %w", err)
	}

	// Read response
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return fmt.Errorf("failed to read greeting response: %w", err)
	}

	if resp[0] != socks5Version {
		return errors.New("invalid SOCKS version")
	}

	// Handle authentication
	switch resp[1] {
	case socks5NoAuth:
		return nil
	case socks5UserPass:
		return d.authenticateUserPass(conn)
	case socks5NoAcceptable:
		return errors.New("no acceptable authentication method")
	default:
		return errors.New("unknown authentication method")
	}
}

// authenticateUserPass performs username/password authentication
func (d *SOCKS5UDPDialer) authenticateUserPass(conn net.Conn) error {
	if d.Username == "" || d.Password == "" {
		return errors.New("username/password required but not provided")
	}

	// Build authentication request
	ulen := len(d.Username)
	plen := len(d.Password)
	req := make([]byte, 3+ulen+plen)
	req[0] = 0x01 // Version
	req[1] = byte(ulen)
	copy(req[2:], d.Username)
	req[2+ulen] = byte(plen)
	copy(req[3+ulen:], d.Password)

	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("failed to send auth request: %w", err)
	}

	// Read response
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return fmt.Errorf("failed to read auth response: %w", err)
	}

	if resp[0] != 0x01 {
		return errors.New("invalid auth version")
	}

	if resp[1] != 0x00 {
		return errors.New("authentication failed")
	}

	return nil
}

// sendUDPAssociate sends UDP ASSOCIATE request and returns relay address
func (d *SOCKS5UDPDialer) sendUDPAssociate(conn net.Conn, host, port string) (*net.UDPAddr, error) {
	// Build request
	// For UDP ASSOCIATE, DST.ADDR and DST.PORT are the address and port
	// that the client expects to use to send UDP datagrams on
	req := []byte{socks5Version, socks5UDPAssociate, 0x00}

	// Add destination address
	ip := net.ParseIP(host)
	if ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			req = append(req, socks5IPv4)
			req = append(req, ip4...)
		} else {
			req = append(req, socks5IPv6)
			req = append(req, ip...)
		}
	} else {
		req = append(req, socks5Domain)
		req = append(req, byte(len(host)))
		req = append(req, []byte(host)...)
	}

	// Add port
	portNum, _ := net.LookupPort("udp", port)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(portNum))
	req = append(req, portBytes...)

	// Send request
	if _, err := conn.Write(req); err != nil {
		return nil, fmt.Errorf("failed to send UDP ASSOCIATE: %w", err)
	}

	// Read response
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, fmt.Errorf("failed to read response header: %w", err)
	}

	if resp[0] != socks5Version {
		return nil, errors.New("invalid SOCKS version in response")
	}

	if resp[1] != socks5Success {
		return nil, fmt.Errorf("UDP ASSOCIATE failed with code: %d", resp[1])
	}

	// Read relay address
	return d.readAddress(conn)
}

// readAddress reads SOCKS5 address from connection
func (d *SOCKS5UDPDialer) readAddress(conn net.Conn) (*net.UDPAddr, error) {
	// Read address type
	addrType := make([]byte, 2)
	if _, err := io.ReadFull(conn, addrType); err != nil {
		return nil, err
	}

	var (
		host         string
		addrTypeByte = addrType[1] // The second byte is the address type
	)

	switch addrTypeByte {
	case socks5IPv4:
		addr := make([]byte, 4)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return nil, err
		}
		host = net.IP(addr).String()

	case socks5IPv6:
		addr := make([]byte, 16)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return nil, err
		}
		host = net.IP(addr).String()

	case socks5Domain:
		lenByte := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenByte); err != nil {
			return nil, err
		}
		domain := make([]byte, lenByte[0])
		if _, err := io.ReadFull(conn, domain); err != nil {
			return nil, err
		}
		host = string(domain)

	default:
		return nil, fmt.Errorf("unsupported address type: %d", addrType[0])
	}

	// Read port
	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBytes); err != nil {
		return nil, err
	}
	port := binary.BigEndian.Uint16(portBytes)

	return net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", host, port))
}

// Write sends data through the SOCKS5 UDP relay
func (c *SOCKS5UDPConn) Write(b []byte) (int, error) {
	return c.WriteTo(b, c.targetAddr)
}

// WriteTo sends data to a specific address through the SOCKS5 UDP relay
func (c *SOCKS5UDPConn) WriteTo(b []byte, addr string) (int, error) {
	// Build SOCKS5 UDP header
	header, err := c.buildUDPHeader(addr)
	if err != nil {
		return 0, err
	}

	// Combine header and data
	packet := append(header, b...)

	// Send to proxy relay
	return c.udpConn.WriteToUDP(packet, c.proxyUDPAddr)
}

// Read receives data from the SOCKS5 UDP relay
func (c *SOCKS5UDPConn) Read(b []byte) (int, error) {
	buffer := c.bufferPool.Get().([]byte)
	defer c.bufferPool.Put(buffer)

	// Read from UDP socket
	n, _, err := c.udpConn.ReadFromUDP(buffer)
	if err != nil {
		return 0, err
	}

	// Parse SOCKS5 UDP header
	data, _, err := c.parseUDPPacket(buffer[:n])
	if err != nil {
		return 0, err
	}

	// Copy data to output buffer
	n = copy(b, data)
	return n, nil
}

// ReadFrom receives data and source address from the SOCKS5 UDP relay
func (c *SOCKS5UDPConn) ReadFrom(b []byte) (int, string, error) {
	buffer := c.bufferPool.Get().([]byte)
	defer c.bufferPool.Put(buffer)

	// Read from UDP socket
	n, _, err := c.udpConn.ReadFromUDP(buffer)
	if err != nil {
		return 0, "", err
	}

	// Parse SOCKS5 UDP header
	data, fromAddr, err := c.parseUDPPacket(buffer[:n])
	if err != nil {
		return 0, "", err
	}

	// Copy data to output buffer
	n = copy(b, data)
	return n, fromAddr, nil
}

// buildUDPHeader builds SOCKS5 UDP request header
func (c *SOCKS5UDPConn) buildUDPHeader(addr string) ([]byte, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}

	// Start with RSV and FRAG
	header := []byte{0x00, 0x00, 0x00}

	// Add address
	ip := net.ParseIP(host)
	if ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			header = append(header, socks5IPv4)
			header = append(header, ip4...)
		} else {
			header = append(header, socks5IPv6)
			header = append(header, ip...)
		}
	} else {
		header = append(header, socks5Domain)
		header = append(header, byte(len(host)))
		header = append(header, []byte(host)...)
	}

	// Add port
	portNum, _ := net.LookupPort("udp", port)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(portNum))
	header = append(header, portBytes...)

	return header, nil
}

// parseUDPPacket parses SOCKS5 UDP packet
func (c *SOCKS5UDPConn) parseUDPPacket(packet []byte) (data []byte, fromAddr string, err error) {
	if len(packet) < 10 {
		return nil, "", errors.New("packet too short")
	}

	// Skip RSV and FRAG
	offset := 3

	// Parse address type
	addrType := packet[offset]
	offset++

	var host string
	switch addrType {
	case socks5IPv4:
		if len(packet) < offset+4 {
			return nil, "", errors.New("invalid IPv4 address")
		}
		host = net.IP(packet[offset : offset+4]).String()
		offset += 4

	case socks5IPv6:
		if len(packet) < offset+16 {
			return nil, "", errors.New("invalid IPv6 address")
		}
		host = net.IP(packet[offset : offset+16]).String()
		offset += 16

	case socks5Domain:
		domainLen := int(packet[offset])
		offset++
		if len(packet) < offset+domainLen {
			return nil, "", errors.New("invalid domain name")
		}
		host = string(packet[offset : offset+domainLen])
		offset += domainLen

	default:
		return nil, "", fmt.Errorf("unsupported address type: %d", addrType)
	}

	// Parse port
	if len(packet) < offset+2 {
		return nil, "", errors.New("invalid port")
	}
	port := binary.BigEndian.Uint16(packet[offset : offset+2])
	offset += 2

	fromAddr = fmt.Sprintf("%s:%d", host, port)
	data = packet[offset:]

	return data, fromAddr, nil
}

// LocalAddr returns the local address
func (c *SOCKS5UDPConn) LocalAddr() net.Addr {
	return c.udpConn.LocalAddr()
}

// RemoteAddr returns the remote address
func (c *SOCKS5UDPConn) RemoteAddr() net.Addr {
	addr, _ := net.ResolveUDPAddr("udp", c.targetAddr)
	return addr
}

// Close closes the SOCKS5 UDP connection
func (c *SOCKS5UDPConn) Close() error {
	// Prevent multiple closes
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.cancel != nil {
		c.cancel()
		c.cancel = nil
	}

	var err error

	// Close UDP connection first (most important for socket exhaustion)
	if c.udpConn != nil {
		if e := c.udpConn.Close(); e != nil {
			err = e
		}
	}

	// Then close control connection
	if c.controlConn != nil {
		if e := c.controlConn.Close(); e != nil && err == nil {
			err = e
		}
	}

	return err
}

// SetDeadline sets read and write deadlines
func (c *SOCKS5UDPConn) SetDeadline(t time.Time) error {
	return c.udpConn.SetDeadline(t)
}

// SetReadDeadline sets read deadline
func (c *SOCKS5UDPConn) SetReadDeadline(t time.Time) error {
	return c.udpConn.SetReadDeadline(t)
}

// SetWriteDeadline sets write deadline
func (c *SOCKS5UDPConn) SetWriteDeadline(t time.Time) error {
	return c.udpConn.SetWriteDeadline(t)
}

// monitorControlConnection monitors the control connection
func (c *SOCKS5UDPConn) monitorControlConnection() {
	// The control connection must remain open for the UDP association
	buf := make([]byte, 1)
	for {
		select {
		case <-c.ctx.Done():
			return
		default:
			c.controlConn.SetReadDeadline(time.Now().Add(time.Second))
			if _, err := c.controlConn.Read(buf); err != nil {
				if nErr, ok := err.(net.Error); ok && nErr.Timeout() {
					continue
				}
				return
			}
		}
	}
}

// dialQUICViaSocks5 establishes a QUIC connection through SOCKS5 proxy
func (s *Session) dialQUICViaSocks5(ctx context.Context, remoteAddr *net.UDPAddr, tlsConf *tls.Config, quicConf *quic.Config) (*quic.Conn, error) {
	if s.IsChainProxy() {
		return nil, errors.New("QUIC over SOCKS5 is not supported with chained proxies")
	}

	proxyURL := s.ProxyDialer.ProxyChain[0]
	username := ""
	password := ""

	if proxyURL.Scheme != "socks5" && proxyURL.Scheme != "socks5h" {
		return nil, fmt.Errorf("unsupported proxy scheme: %s", proxyURL.Scheme)
	}

	if proxyURL.User != nil {
		username = proxyURL.User.Username()
		password, _ = proxyURL.User.Password()
	}

	dialer := NewSOCKS5UDPDialer(proxyURL.Host, username, password)

	// Establish SOCKS5 UDP connection with timeout context
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	socks5Conn, err := dialer.DialUDP(ctx, "udp", remoteAddr.String())
	if err != nil {
		return nil, fmt.Errorf("failed to establish SOCKS5 UDP connection: %w", err)
	}

	// Test the connection first
	_, err = socks5Conn.WriteTo([]byte("probe"), remoteAddr.String())
	if err != nil {
		socks5Conn.Close()
		return nil, fmt.Errorf("SOCKS5 probe packet failed: %w", err)
	}

	// Create a custom net.PacketConn wrapper for QUIC
	packetConn := &socks5PacketConn{
		conn:       socks5Conn,
		remoteAddr: remoteAddr,
	}

	transport := &quic.UTransport{
		Transport: &quic.Transport{
			Conn: packetConn,
		},
		QUICSpec: &quic.QUICSpec{
			ClientHelloSpec:   s.GetBrowserHTTP3ClientHelloFunc(s.Browser)(),
			InitialPacketSpec: getInitialPacket(s.Browser),
		},
	}

	s.HTTP3Config.transport.transportsPoolLock.Lock()
	s.HTTP3Config.transport.transportsPool = append(s.HTTP3Config.transport.transportsPool, transport)
	s.HTTP3Config.transport.transportsPoolLock.Unlock()

	// Dial QUIC using the SOCKS5 connection
	quicConn, err := transport.DialEarly(ctx, remoteAddr, tlsConf, quicConf)

	if err != nil {
		// Ensure cleanup on failure
		_ = packetConn.Close()
		_ = transport.Close()
		return nil, err
	}

	return quicConn, nil
}

// socks5PacketConn wraps SOCKS5UDPConn to implement net.PacketConn for QUIC
type socks5PacketConn struct {
	conn       *SOCKS5UDPConn
	remoteAddr *net.UDPAddr
}

func (c *socks5PacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, fromAddr, err := c.conn.ReadFrom(p)
	if err != nil {
		return 0, nil, err
	}

	// Parse address
	udpAddr, err := net.ResolveUDPAddr("udp", fromAddr)
	if err != nil {
		return 0, nil, err
	}

	return n, udpAddr, nil
}

func (c *socks5PacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, errors.New("invalid address type")
	}

	return c.conn.WriteTo(p, udpAddr.String())
}

func (c *socks5PacketConn) Close() error {
	return c.conn.Close()
}

func (c *socks5PacketConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *socks5PacketConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *socks5PacketConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *socks5PacketConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

func (c *socks5PacketConn) SetReadBuffer(b int) error {
	return c.conn.udpConn.SetReadBuffer(b)
}

func (c *socks5PacketConn) SetWriteBuffer(b int) error {
	return c.conn.udpConn.SetWriteBuffer(b)
}
