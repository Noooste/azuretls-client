package utils

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

// SOCKS4 command codes
const (
	Socks4CmdConnect = 0x01
	Socks4CmdBind    = 0x02
)

// SOCKS4 response codes
const (
	Socks4StatusGranted          = 0x5A
	Socks4StatusRejected         = 0x5B
	Socks4StatusNoIdentd         = 0x5C
	Socks4StatusIdentdAuthFailed = 0x5D
)

// Socks4Request represents a SOCKS4 request
type Socks4Request struct {
	Version byte
	Command byte
	DstPort uint16
	DstIP   net.IP
	UserID  string
}

// Socks4Response represents a SOCKS4 response
type Socks4Response struct {
	Version byte
	Status  byte
	DstPort uint16
	DstIP   net.IP
}

// Socks4ProxyServer implements a simple SOCKS4 proxy server for testing
type Socks4ProxyServer struct {
	listener net.Listener
	address  string
	port     int
}

// NewSocks4ProxyServer creates a new SOCKS4 proxy server
func NewSocks4ProxyServer(host string, port int) *Socks4ProxyServer {
	return &Socks4ProxyServer{
		address: host,
		port:    port,
	}
}

// Start starts the SOCKS4 proxy server
func (s *Socks4ProxyServer) Start() error {
	addr := net.JoinHostPort(s.address, strconv.Itoa(s.port))
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to start SOCKS4 server: %v", err)
	}

	s.listener = listener

	go s.acceptConnections()

	return nil
}

// Stop stops the SOCKS4 proxy server
func (s *Socks4ProxyServer) Stop() error {
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

// GetAddress returns the address the server is listening on
func (s *Socks4ProxyServer) GetAddress() string {
	if s.listener != nil {
		return s.listener.Addr().String()
	}
	return net.JoinHostPort(s.address, strconv.Itoa(s.port))
}

// acceptConnections handles incoming connections
func (s *Socks4ProxyServer) acceptConnections() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			// Server is likely shutting down
			return
		}

		go s.handleConnection(conn)
	}
}

// handleConnection handles a single SOCKS4 connection
func (s *Socks4ProxyServer) handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	// Set connection timeout
	clientConn.SetDeadline(time.Now().Add(30 * time.Second))

	// Read SOCKS4 request
	req, err := s.readSocks4Request(clientConn)
	if err != nil {
		s.sendSocks4Response(clientConn, Socks4StatusRejected, net.IPv4zero, 0)
		return
	}

	// Handle CONNECT command
	if req.Command == Socks4CmdConnect {
		s.handleConnect(clientConn, req)
	} else {
		s.sendSocks4Response(clientConn, Socks4StatusRejected, net.IPv4zero, 0)
	}
}

// readSocks4Request reads and parses a SOCKS4 request
func (s *Socks4ProxyServer) readSocks4Request(conn net.Conn) (*Socks4Request, error) {
	// Read fixed-size header (8 bytes minimum)
	header := make([]byte, 8)
	_, err := io.ReadFull(conn, header)
	if err != nil {
		return nil, fmt.Errorf("failed to read SOCKS4 header: %v", err)
	}

	req := &Socks4Request{
		Version: header[0],
		Command: header[1],
		DstPort: binary.BigEndian.Uint16(header[2:4]),
		DstIP:   net.IPv4(header[4], header[5], header[6], header[7]),
	}

	// Validate version
	if req.Version != 0x04 {
		return nil, fmt.Errorf("unsupported SOCKS version: %d", req.Version)
	}

	// Read UserID (null-terminated string)
	var userID []byte
	for {
		b := make([]byte, 1)
		_, err := conn.Read(b)
		if err != nil {
			return nil, fmt.Errorf("failed to read UserID: %v", err)
		}

		if b[0] == 0x00 {
			break
		}

		userID = append(userID, b[0])
	}

	req.UserID = string(userID)

	return req, nil
}

// sendSocks4Response sends a SOCKS4 response
func (s *Socks4ProxyServer) sendSocks4Response(conn net.Conn, status byte, ip net.IP, port uint16) error {
	response := Socks4Response{
		Version: 0x00, // SOCKS4 response version is 0
		Status:  status,
		DstPort: port,
		DstIP:   ip.To4(),
	}

	if response.DstIP == nil {
		response.DstIP = net.IPv4zero
	}

	buf := make([]byte, 8)
	buf[0] = response.Version
	buf[1] = response.Status
	binary.BigEndian.PutUint16(buf[2:4], response.DstPort)
	copy(buf[4:8], response.DstIP)

	_, err := conn.Write(buf)
	return err
}

// handleConnect handles a SOCKS4 CONNECT request
func (s *Socks4ProxyServer) handleConnect(clientConn net.Conn, req *Socks4Request) {
	// Connect to target server
	targetAddr := net.JoinHostPort(req.DstIP.String(), strconv.Itoa(int(req.DstPort)))
	targetConn, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
	if err != nil {
		s.sendSocks4Response(clientConn, Socks4StatusRejected, net.IPv4zero, 0)
		return
	}
	defer targetConn.Close()

	// Send success response
	err = s.sendSocks4Response(clientConn, Socks4StatusGranted, req.DstIP, req.DstPort)
	if err != nil {
		return
	}

	// Remove connection deadline for data forwarding
	clientConn.SetDeadline(time.Time{})
	targetConn.SetDeadline(time.Time{})

	// Start bidirectional forwarding
	done := make(chan struct{}, 2)

	// Forward client -> target
	go func() {
		defer func() { done <- struct{}{} }()
		io.Copy(targetConn, clientConn)
		targetConn.(*net.TCPConn).CloseWrite()
	}()

	// Forward target -> client
	go func() {
		defer func() { done <- struct{}{} }()
		io.Copy(clientConn, targetConn)
		clientConn.(*net.TCPConn).CloseWrite()
	}()

	// Wait for one direction to finish
	<-done
}

// StartSocks4ProxyServer is a convenience function to start a SOCKS4 proxy server
// Returns the server instance and the actual address it's listening on
func StartSocks4ProxyServer(host string, port int) (*Socks4ProxyServer, string, error) {
	server := NewSocks4ProxyServer(host, port)
	err := server.Start()
	if err != nil {
		return nil, "", err
	}

	return server, server.GetAddress(), nil
}

// StartSocks4ProxyServerOnRandomPort starts a SOCKS4 proxy server on a random available port
// Returns the server instance and the actual address it's listening on
func StartSocks4ProxyServerOnRandomPort() (*Socks4ProxyServer, string, error) {
	return StartSocks4ProxyServer("127.0.0.1", 0)
}

// GetPort returns the port number the server is listening on
func (s *Socks4ProxyServer) GetPort() int {
	if s.listener != nil {
		addr := s.listener.Addr().(*net.TCPAddr)
		return addr.Port
	}
	return s.port
}
