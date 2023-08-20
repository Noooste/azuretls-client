package azuretls

import (
	"fmt"
	"github.com/Noooste/fhttp/http2"
	"strconv"
	"strings"
)

const (
	invalidSettings      = "invalid SETTINGS : "
	invalidSettingsIndex = invalidSettings + "index %d (invalid %s)"
	invalidWindow        = "invalid WINDOW_UPDATE : %s"
	invalidPriority      = "invalid PRIORITY : %s"
	invalidPre           = "invalid PRE_HEADER : %s"
)

// ApplyHTTP2 applies HTTP2 settings to the session from a fingerprint.
// The fingerprint is in the format:
//
//	<SETTINGS>|<WINDOW_UPDATE>|<PRIORITY>|<PRE_HEADER>
//
// egs :
//
//	1:65536,2:0,3:1000,4:6291456,6:262144|15663105|0|m,s,a,p
//
// Any 0 value will be ignored.
func (s *Session) ApplyHTTP2(fp string) error {
	// check if HTTP2 is already initialized
	// if not initialize it
	if s.tr2 == nil {
		if s.tr == nil {
			s.initHTTP1()
		}

		var err error
		s.tr2, err = http2.ConfigureTransports(s.tr)
		if err != nil {
			return err
		}
	}

	split := strings.Split(fp, "|")

	// fingerprint should have 4 parts
	if len(split) != 4 {
		return fmt.Errorf("%s%s, invalid length : expected 4, got %d", invalidSettings, fp, len(split))
	}

	var (
		settings     = split[0]
		windowUpdate = split[1]
		priorities   = split[2]
		preHeader    = split[3]
	)

	if err := applySettings(settings, s.tr2); err != nil {
		return err
	}

	if err := applyWindowUpdate(windowUpdate, s.tr2); err != nil {
		return err
	}

	if err := applyPriorities(priorities, s.tr2); err != nil {
		return err
	}

	if err := applyPreHeader(preHeader, &s.PHeader, s.tr2); err != nil {
		return err
	}

	return nil
}

func applySettings(settings string, tr *http2.Transport) error {
	if settings != "0" {
		values := strings.Split(settings, ",")

		settingsFrame := make([]http2.Setting, 0, len(values))

		var (
			id, val uint64
			err     error
		)

		for i, setting := range values {
			s2 := strings.Split(setting, ":")
			if len(s2) != 2 {
				return fmt.Errorf(invalidSettingsIndex, i, "length")
			}

			id, err = strconv.ParseUint(s2[0], 10, 16)
			if err != nil {
				return fmt.Errorf(invalidSettingsIndex, i, "id")
			}

			val, err = strconv.ParseUint(s2[1], 10, 32)
			if err != nil {
				return fmt.Errorf(invalidSettingsIndex, i, "value")
			}

			settingsFrame = append(settingsFrame, http2.Setting{
				ID:  http2.SettingID(id),
				Val: uint32(val),
			})

			tr.Settings = settingsFrame
		}
	} else {
		tr.Settings = make([]http2.Setting, 0)
	}

	return nil
}

func applyWindowUpdate(windowUpdate string, tr *http2.Transport) error {
	if windowUpdate == "0" {
		tr.WindowsUpdateSize = (2 << 15) - 1
	} else {
		if ws, err := strconv.Atoi(windowUpdate); err != nil {
			return fmt.Errorf(invalidWindow, windowUpdate)
		} else if ws == 0 {
			return fmt.Errorf(invalidWindow, windowUpdate)
		} else {
			tr.WindowsUpdateSize = uint32(ws)
		}
	}

	return nil
}

func applyPriorities(priorities string, tr *http2.Transport) error {
	if priorities != "0" {
		rawPriorities := strings.Split(priorities, ",")
		streamPriorities := make([]http2.StreamPriority, 0, len(rawPriorities))

		var (
			id, deps, weight int
			exclusive        bool
			err              error
		)

		for _, priority := range rawPriorities {
			s2 := strings.Split(priority, ":")
			if len(s2) != 4 {
				return fmt.Errorf(invalidPriority, priority)
			}

			id, err = strconv.Atoi(s2[0])
			if err != nil {
				return fmt.Errorf(invalidPriority, priority)
			}

			exclusive = s2[1] == "1"

			deps, err = strconv.Atoi(s2[2])
			if err != nil {
				return fmt.Errorf(invalidPriority, priority)
			}

			weight, err = strconv.Atoi(s2[3])
			if err != nil {
				return fmt.Errorf(invalidPriority, priority)
			}

			streamPriorities = append(streamPriorities, http2.StreamPriority{
				StreamId: uint32(id),
				PriorityParam: http2.PriorityParam{
					Weight:    uint8(weight - 1),
					Exclusive: exclusive,
					StreamDep: uint32(deps),
				},
			})
		}

		tr.StreamPriorities = streamPriorities

	} else {
		tr.StreamPriorities = make([]http2.StreamPriority, 0)
	}

	return nil
}

func applyPreHeader(preHeader string, h *PHeader, tr *http2.Transport) error {
	if preHeader != "0" {
		headers := strings.Split(preHeader, ",")
		if len(headers) != 4 {
			return fmt.Errorf(invalidPre, preHeader)
		}

		for i, header := range headers {
			switch header {
			case "m":
				h[i] = Method
			case "p":
				h[i] = Path
			case "s":
				h[i] = Scheme
			case "a":
				h[i] = Authority
			default:
				return fmt.Errorf(invalidPre, header)
			}
		}
	}

	tr.HeaderPriorities = defaultHeaderPriorities("")

	for _, setting := range tr.Settings {
		switch setting.ID {
		case http2.SettingInitialWindowSize:
			tr.InitialWindowSize = setting.Val

		case http2.SettingHeaderTableSize:
			tr.HeaderTableSize = setting.Val
		}
	}

	return nil
}
