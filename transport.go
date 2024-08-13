package azuretls

import (
	"context"
	http "github.com/Noooste/fhttp"
	"github.com/Noooste/fhttp/http2"
	"net"
	"net/url"
	"time"
)

func (s *Session) InitTransport(browser string) (err error) {
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
			dialer := &net.Dialer{
				Timeout:   s.TimeOut,
				KeepAlive: 30 * time.Second,
			}

			if s.ModifyDialer != nil {
				if err := s.ModifyDialer(dialer); err != nil {
					return nil, err
				}
			}

			return dialer.DialContext(s.ctx, network, addr)
		},
		Proxy: func(*http.Request) (*url.URL, error) {
			if s.Proxy == "" {
				return nil, nil
			}

			return url.Parse(s.Proxy)
		},
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          1e3,
		IdleConnTimeout:       90 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
}

func (s *Session) initHTTP2(browser string) error {
	tr, err := http2.ConfigureTransports(s.Transport) // upgrade to HTTP2, while keeping http.Transport

	if err != nil {
		return err
	}

	tr.Priorities = defaultStreamPriorities(browser)
	tr.Settings, tr.SettingsOrder = defaultHeaderSettings(browser)
	tr.ConnectionFlow = defaultWindowsUpdate(browser)

	if s.HeaderPriority != nil {
		tr.HeaderPriority = s.HeaderPriority
	} else {
		tr.HeaderPriority = defaultHeaderPriorities(browser)
	}

	tr.StrictMaxConcurrentStreams = true

	tr.PushHandler = &http2.DefaultPushHandler{}

	for k, v := range tr.Settings {
		switch k {
		case http2.SettingInitialWindowSize:
			tr.InitialWindowSize = v

		case http2.SettingHeaderTableSize:
			tr.HeaderTableSize = v
		}
	}

	s.HTTP2Transport = tr

	return nil
}
