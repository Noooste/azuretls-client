package azuretls

import (
	http "github.com/Noooste/fhttp"
	"github.com/Noooste/fhttp/http2"
	"net/url"
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

	return
}

func (s *Session) initHTTP1() {
	s.Transport = &http.Transport{
		TLSHandshakeTimeout:   s.TimeOut,
		ResponseHeaderTimeout: s.TimeOut,
		Proxy: func(req *http.Request) (*url.URL, error) {
			if s.ProxyDialer == nil {
				return nil, nil
			}
			return s.ProxyDialer.ProxyURL, nil
		},
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
	tr.HeaderPriority = defaultHeaderPriorities(browser)
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
