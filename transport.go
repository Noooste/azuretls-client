package azuretls

import (
	http "github.com/Noooste/fhttp"
	"github.com/Noooste/fhttp/http2"
	"sync"
	"time"
)

func (s *Session) initTransport(browser string) (err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.tr == nil {
		s.initHTTP1()
	}

	if s.tr2 == nil {
		if err = s.initHTTP2(browser); err != nil {
			return
		}
		var serverPushEnabled bool
		for _, v := range s.tr2.Settings {
			if v.ID == http2.SettingEnablePush {
				serverPushEnabled = v.Val == 1
				break
			}
		}
		if serverPushEnabled {
			s.tr2.PushHandler = &DefaultPushHandler{
				mu:     &sync.Mutex{},
				listen: false,
			}
		}
	}
	return
}

func (s *Session) initHTTP1() {
	s.tr = &http.Transport{
		TLSHandshakeTimeout:   time.Duration(30) * time.Second,
		ResponseHeaderTimeout: time.Duration(30) * time.Second,
	}
}

func (s *Session) initHTTP2(browser string) error {
	tr, err := http2.ConfigureTransports(s.tr) // upgrade to HTTP2, while keeping http.Transport

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

	s.tr2 = tr

	return nil
}
