package azuretls

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/Noooste/fhttp/http2"
)

const (
	invalidSettings      = "invalid SETTINGS : "
	invalidSettingsIndex = invalidSettings + "index %d (invalid %s)"
	invalidWindow        = "invalid WINDOW_UPDATE : %s"
	invalidPriority      = "invalid PRIORITY : %s"
	invalidPseudo        = "invalid PSEUDO_HEADER : %s"
)

// ApplyHTTP2 applies HTTP2 settings to the session from a fingerprint.
// The fingerprint is in the format:
//
//	<SETTINGS>|<WINDOW_UPDATE>|<PRIORITY>|<PSEUDO_HEADER>
//
// egs :
//
//	1:65536,2:0,3:1000,4:6291456,6:262144|15663105|0|m,s,a,p
//
// Any 0 value will be ignored.
func (s *Session) ApplyHTTP2(fp string) error {
	// check if HTTP2 is already initialized
	// if not initialize it
	if s.HTTP2Transport == nil {
		if s.Transport == nil {
			s.initHTTP1()
		}

		var err error
		s.HTTP2Transport, err = s.getDefaultHTTP2Transport()

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
		settings      = split[0]
		windowUpdate  = split[1]
		priorities    = split[2]
		pseudoHeaders = split[3]
	)

	if err := applySettings(settings, s.HTTP2Transport); err != nil {
		return err
	}

	if err := applyWindowUpdate(windowUpdate, s.HTTP2Transport); err != nil {
		return err
	}

	if err := applyPriorities(priorities, s.HTTP2Transport); err != nil {
		return err
	}

	s.PHeader = make(PHeader, 4)
	if err := applyPseudoHeaders(pseudoHeaders, s.PHeader, s.HTTP2Transport); err != nil {
		return err
	}

	return nil
}

func splitSettings(settings string) []string {
	if strings.Contains(settings, ",") {
		return strings.Split(settings, ",")
	}

	return strings.Split(settings, ";")
}

func applySettings(settings string, tr *http2.Transport) error {
	if settings != "0" {
		values := splitSettings(settings)

		settingsFrame := make(map[http2.SettingID]uint32, len(values))

		var (
			id, val uint64
			err     error
		)

		for i, setting := range values {
			split := strings.Split(setting, ":")
			if len(split) != 2 {
				return fmt.Errorf(invalidSettingsIndex, i, "length")
			}

			id, err = strconv.ParseUint(split[0], 10, 16)
			if err != nil {
				return fmt.Errorf(invalidSettingsIndex, i, "id")
			}

			val, err = strconv.ParseUint(split[1], 10, 32)
			if err != nil {
				return fmt.Errorf(invalidSettingsIndex, i, "value")
			}

			settingsFrame[http2.SettingID(id)] = uint32(val)

			tr.Settings = settingsFrame
			tr.SettingsOrder = append(tr.SettingsOrder, http2.SettingID(id))
		}
	} else {
		tr.Settings = make(map[http2.SettingID]uint32)
	}

	return nil
}

func applyWindowUpdate(windowUpdate string, tr *http2.Transport) error {
	if windowUpdate == "0" {
		tr.ConnectionFlow = (2 << 15) - 1
	} else {
		if ws, err := strconv.Atoi(windowUpdate); err != nil {
			return fmt.Errorf(invalidWindow, windowUpdate)
		} else {
			tr.ConnectionFlow = uint32(ws)
		}
	}

	return nil
}

func applyPriorities(priorities string, tr *http2.Transport) error {
	if priorities != "0" {
		rawPriorities := strings.Split(priorities, ",")
		streamPriorities := make([]http2.Priority, 0, len(rawPriorities))

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

			if s2[1] != "0" && s2[1] != "1" {
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

			streamPriorities = append(streamPriorities, http2.Priority{
				StreamID: uint32(id),
				PriorityParam: http2.PriorityParam{
					Weight:    uint8(weight - 1),
					Exclusive: exclusive,
					StreamDep: uint32(deps),
				},
			})
		}

		tr.Priorities = streamPriorities

	} else {
		tr.Priorities = make([]http2.Priority, 0)
	}

	return nil
}

func applyPseudoHeaders(pseudoHeaders string, h PHeader, tr *http2.Transport) error {
	if pseudoHeaders != "0" {
		headers := strings.Split(pseudoHeaders, ",")
		if len(headers) != 4 {
			return fmt.Errorf(invalidPseudo, pseudoHeaders)
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
				return fmt.Errorf(invalidPseudo, header)
			}
		}
	}

	tr.HeaderPriority = defaultHeaderPriorities("")

	for k, v := range tr.Settings {
		switch k {
		case http2.SettingInitialWindowSize:
			tr.InitialWindowSize = v

		case http2.SettingHeaderTableSize:
			tr.HeaderTableSize = v
		}
	}

	return nil
}
