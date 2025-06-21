package utils

type PeetResponse struct {
	Donate      string `json:"donate"`
	Ip          string `json:"ip"`
	HttpVersion string `json:"http_version"`
	Method      string `json:"method"`
	UserAgent   string `json:"user_agent,omitempty"`
	Tls         struct {
		Ciphers              []string `json:"ciphers"`
		Extensions           []any    `json:"extensions"`
		TlsVersionRecord     string   `json:"tls_version_record"`
		TlsVersionNegotiated string   `json:"tls_version_negotiated"`
		Ja3                  string   `json:"ja3"`
		Ja3Hash              string   `json:"ja3_hash"`
		Ja4                  string   `json:"ja4"`
		Ja4R                 string   `json:"ja4_r"`
		Peetprint            string   `json:"peetprint"`
		PeetprintHash        string   `json:"peetprint_hash"`
		ClientRandom         string   `json:"client_random"`
		SessionId            string   `json:"session_id"`
	} `json:"tls"`
	Http2 struct {
		AkamaiFingerprint     string `json:"akamai_fingerprint"`
		AkamaiFingerprintHash string `json:"akamai_fingerprint_hash"`
		SentFrames            []struct {
			FrameType string   `json:"frame_type"`
			Length    int      `json:"length"`
			Settings  []string `json:"settings,omitempty"`
			Increment int      `json:"increment,omitempty"`
			StreamId  int      `json:"stream_id,omitempty"`
			Headers   []string `json:"headers,omitempty"`
			Flags     []string `json:"flags,omitempty"`
			Priority  struct {
				Weight    int `json:"weight"`
				DependsOn int `json:"depends_on"`
				Exclusive int `json:"exclusive"`
			} `json:"priority,omitempty"`
		} `json:"sent_frames"`
	} `json:"http2,omitempty"`
	Tcpip struct {
		Ip struct {
		} `json:"ip"`
		Tcp struct {
		} `json:"tcp"`
	} `json:"tcpip"`
	Http1 struct {
		Headers []string `json:"headers"`
	} `json:"http1,omitempty"`
}
