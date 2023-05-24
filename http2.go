package azuretls

import (
	"errors"
	http "github.com/Noooste/fhttp"
	"github.com/Noooste/fhttp/http2"
	"strconv"
	"strings"
	"time"
)

func (s *Session) ApplyHTTP2(fp string) error {
	tr2, err := http2.ConfigureTransports(&http.Transport{
		TLSHandshakeTimeout:   time.Duration(30) * time.Second,
		ResponseHeaderTimeout: time.Duration(30) * time.Second,
	}) // upgrade to HTTP2, while keeping http.Transport

	if err != nil {
		return errors.New("failed to configure transport: " + err.Error())
	}

	split := strings.Split(fp, "|")

	if len(split) < 4 {
		return errors.New("invalid fingerprint")
	}

	settings := split[0]
	if settings != "0" {
		for _, setting := range strings.Split(settings, ",") {
			s2 := strings.Split(setting, ":")
			if len(s2) != 2 {
				return errors.New("invalid SETTING : " + setting)
			}

			id, err := strconv.Atoi(s2[0])
			if err != nil {
				return errors.New("invalid SETTING : " + setting)
			}

			val, err := strconv.Atoi(s2[1])
			if err != nil {
				return errors.New("invalid SETTING : " + setting)
			}

			tr2.Settings = append(tr2.Settings, http2.Setting{
				ID:  http2.SettingID(id),
				Val: uint32(val),
			})
		}
	} else {
		tr2.Settings = []http2.Setting{}
	}

	windowUpdate := split[1]
	if windowUpdate == "0" {
		windowUpdate = "65535"
	}

	ws, err := strconv.Atoi(windowUpdate)

	if err != nil {
		return errors.New("invalid WINDOW_UPDATE : " + windowUpdate)
	}

	tr2.WindowsUpdateSize = uint32(ws)

	priorities := split[2]
	if priorities != "0" {
		for _, priority := range strings.Split(priorities, ",") {
			s2 := strings.Split(priority, ":")
			if len(s2) != 4 {
				return errors.New("invalid PRIORITY : " + priority)
			}

			id, err := strconv.Atoi(s2[0])
			if err != nil {
				return errors.New("invalid PRIORITY : " + priority)
			}

			exclusive := s2[1] == "1"

			deps, err := strconv.Atoi(s2[2])
			if err != nil {
				return errors.New("invalid PRIORITY : " + priority)
			}

			weight, err := strconv.Atoi(s2[3])
			if err != nil {
				return errors.New("invalid PRIORITY : " + priority)
			}

			tr2.StreamPriorities = append(tr2.StreamPriorities, http2.StreamPriority{
				StreamId: uint32(id),
				PriorityParam: http2.PriorityParam{
					Weight:    uint8(weight - 1),
					Exclusive: exclusive,
					StreamDep: uint32(deps),
				},
			})
		}
	} else {
		tr2.StreamPriorities = []http2.StreamPriority{}
	}

	preHeader := split[3]

	for i, header := range strings.Split(preHeader, ",") {
		switch header {
		case "m":
			s.PHeader[i] = Method
			break
		case "p":
			s.PHeader[i] = Path
			break
		case "s":
			s.PHeader[i] = Scheme
			break
		case "a":
			s.PHeader[i] = Authority
			break
		default:
			return errors.New("invalid PRIORITY : " + header)

		}
	}

	tr2.HeaderPriorities = defaultHeaderPriorities(s.Browser)

	for _, setting := range tr2.Settings {
		switch setting.ID {
		case http2.SettingInitialWindowSize:
			tr2.InitialWindowSize = setting.Val

		case http2.SettingHeaderTableSize:
			tr2.HeaderTableSize = setting.Val
		}
	}

	s.tr2 = tr2

	return nil
}
