package azuretls

import (
	"github.com/Noooste/fhttp/http2"
	"math"
)

const (
	Chrome  = "chrome"
	Firefox = "firefox"
	Opera   = "opera"
	Safari  = "safari"
	Edge    = "edge"
	Ios     = "ios"
	Android = "android" //deprecated
)

func defaultHeaderSettings(navigator string) (map[http2.SettingID]uint32, []http2.SettingID) {
	switch navigator {
	case Firefox:
		return map[http2.SettingID]uint32{
				http2.SettingHeaderTableSize:   65536,
				http2.SettingEnablePush:        0,
				http2.SettingInitialWindowSize: 131072,
				http2.SettingMaxFrameSize:      16384,
			}, []http2.SettingID{
				http2.SettingHeaderTableSize,
				http2.SettingEnablePush,
				http2.SettingInitialWindowSize,
				http2.SettingMaxFrameSize,
			}

	case Ios:
		return map[http2.SettingID]uint32{
				http2.SettingHeaderTableSize:      4096,
				http2.SettingMaxConcurrentStreams: 100,
				http2.SettingInitialWindowSize:    2097152,
				http2.SettingMaxFrameSize:         16384,
				http2.SettingMaxHeaderListSize:    math.MaxUint32,
			}, []http2.SettingID{
				http2.SettingHeaderTableSize,
				http2.SettingMaxConcurrentStreams,
				http2.SettingInitialWindowSize,
				http2.SettingMaxFrameSize,
				http2.SettingMaxHeaderListSize,
			}

	case Safari:
		return map[http2.SettingID]uint32{
				http2.SettingEnablePush:           0,
				http2.SettingMaxConcurrentStreams: 100,
				http2.SettingInitialWindowSize:    2097152,
				0x8:                               1,
				0x9:                               1,
			}, []http2.SettingID{
				http2.SettingEnablePush,
				http2.SettingMaxConcurrentStreams,
				http2.SettingInitialWindowSize,
				0x8,
				0x9,
			}

	default: //chrome
		return map[http2.SettingID]uint32{
				http2.SettingHeaderTableSize:   65536,
				http2.SettingEnablePush:        0,
				http2.SettingInitialWindowSize: 6291456,
				http2.SettingMaxHeaderListSize: 262144,
			}, []http2.SettingID{
				http2.SettingHeaderTableSize,
				http2.SettingEnablePush,
				http2.SettingInitialWindowSize,
				http2.SettingMaxHeaderListSize,
			}
	}
}

func defaultWindowsUpdate(navigator string) uint32 {
	switch navigator {
	case Firefox:
		return 12517377
	case Ios:
		return 15663105
	case Safari:
		return 10420225
	default:
		return 15663105
	}
}

func defaultStreamPriorities(navigator string) []http2.Priority {
	switch navigator {
	default:
		return []http2.Priority{}
	}
}

func defaultHeaderPriorities(navigator string) *http2.PriorityParam {
	switch navigator {
	case Firefox:
		return &http2.PriorityParam{
			Weight:    41,
			StreamDep: 0,
			Exclusive: false,
		}

	case Ios:
		return &http2.PriorityParam{
			Weight:    254,
			StreamDep: 0,
			Exclusive: false,
		}

	default: // chrome
		return &http2.PriorityParam{
			Weight:    255,
			StreamDep: 0,
			Exclusive: true,
		}
	}
}
