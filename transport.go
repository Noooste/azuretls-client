package azuretls

import (
	"context"
	http "github.com/Noooste/fhttp"
	"github.com/Noooste/fhttp/http2"
	"net"
)

func (s *Session) initTransport(browser string) (err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.Transport == nil {
		s.initHTTP1()
	}

	if s.HTTP2Transport == nil {
		if err = s.initHTTP2(browser); err != nil {
			return
		}
	}

	s.HTTP2Transport.PushHandler = &http2.DefaultPushHandler{}

	return
}

func (s *Session) initHTTP1() {
	s.Transport = &http.Transport{
		TLSHandshakeTimeout:   s.TimeOut,
		ResponseHeaderTimeout: s.TimeOut,
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			s.Connections.mu.RLock()
			defer s.Connections.mu.RUnlock()
			rc := s.Connections.hosts[addr]
			return rc.TLS, nil
		},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			s.Connections.mu.RLock()
			defer s.Connections.mu.RUnlock()
			rc := s.Connections.hosts[addr]
			return rc.Conn, nil
		},
	}
}

func (s *Session) initHTTP2(browser string) error {
	tr, err := http2.ConfigureTransports(s.Transport) // upgrade to HTTP2, while keeping http.Transport

	if err != nil {
		return err
	}

	tr.StreamPriorities = defaultStreamPriorities(browser)
	tr.Settings = defaultHeaderSettings(browser)
	tr.WindowsUpdateSize = defaultWindowsUpdate(browser)
	tr.HeaderPriorities = defaultHeaderPriorities(browser)

	for _, setting := range tr.Settings {
		switch setting.ID {
		case http2.SettingInitialWindowSize:
			tr.InitialWindowSize = setting.Val

		case http2.SettingHeaderTableSize:
			tr.HeaderTableSize = setting.Val
		}
	}

	s.HTTP2Transport = tr

	return nil
}
