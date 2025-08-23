package azuretls

import (
	"time"

	http "github.com/Noooste/fhttp"
	"github.com/Noooste/fhttp/http2"
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
		DialTLSContext:        s.dialTLS,
		DialContext:           s.dial,
		MaxIdleConns:          1e3,
		IdleConnTimeout:       90 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DisableCompression:    true,
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
