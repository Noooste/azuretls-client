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

func defaultHeaderSettings(navigator string) []http2.Setting {
	switch navigator {
	case Firefox:
		return []http2.Setting{
			{ID: http2.SettingHeaderTableSize, Val: 65536},
			{ID: http2.SettingInitialWindowSize, Val: 131072},
			{ID: http2.SettingMaxFrameSize, Val: 16384},
		}
	case Ios:
		return []http2.Setting{
			{ID: http2.SettingHeaderTableSize, Val: 4096},
			{ID: http2.SettingMaxConcurrentStreams, Val: 100},
			{ID: http2.SettingInitialWindowSize, Val: 2097152},
			{ID: http2.SettingMaxFrameSize, Val: 16384},
			{ID: http2.SettingMaxHeaderListSize, Val: math.MaxUint32},
		}
	default: //chrome
		return []http2.Setting{
			{ID: http2.SettingHeaderTableSize, Val: 65536},
			{ID: http2.SettingEnablePush, Val: 0},
			{ID: http2.SettingMaxConcurrentStreams, Val: 1e3},
			{ID: http2.SettingInitialWindowSize, Val: 6291456},
			{ID: http2.SettingMaxHeaderListSize, Val: 262144},
		}
	}
}

func defaultWindowsUpdate(navigator string) uint32 {
	switch navigator {
	case Firefox:
		return 12517377
	case Ios:
		return 15663105
	default:
		return 15663105
	}
}

func defaultStreamPriorities(navigator string) []http2.StreamPriority {
	switch navigator {
	case Firefox:
		return []http2.StreamPriority{
			{
				StreamId: 3,
				PriorityParam: http2.PriorityParam{
					Weight: 200,
				},
			},
			{
				StreamId: 5,
				PriorityParam: http2.PriorityParam{
					Weight: 100,
				},
			},
			{
				StreamId: 7,
				PriorityParam: http2.PriorityParam{
					Weight: 0,
				},
			},
			{
				StreamId: 9,
				PriorityParam: http2.PriorityParam{
					Weight:    0,
					StreamDep: 7,
				},
			},
			{
				StreamId: 11,
				PriorityParam: http2.PriorityParam{
					Weight:    0,
					StreamDep: 3,
				},
			},
			{
				StreamId: 13,
				PriorityParam: http2.PriorityParam{
					Weight: 240,
				},
			},
		}

	default:
		return []http2.StreamPriority{}
	}
}

func defaultHeaderPriorities(navigator string) http2.PriorityParam {
	switch navigator {
	case Firefox:
		return http2.PriorityParam{
			Weight:    41,
			StreamDep: 13,
			Exclusive: false,
		}

	default:
		return http2.PriorityParam{
			Weight:    255,
			StreamDep: 0,
			Exclusive: true,
		}
	}
}
