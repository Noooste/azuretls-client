package azuretls

import (
	"bytes"
	"encoding/json"
	"io"
	"math/rand"
	"regexp"
	"strings"
	"time"
)

const (
	SchemeHttp  = "http"
	SchemeHttps = "https"
	SchemeWs    = "ws"
	SchemeWss   = "wss"
)

var random = rand.New(rand.NewSource(time.Now().UnixNano()))

func (r *Response) toString() string {
	returnElement, _ := json.Marshal(r)
	return string(returnElement)
}

func getRandomId() uint64 {
	return random.Uint64()
}

var numberReg = regexp.MustCompile(`\d+`)

func formatProxy(proxy string) string {
	var split = strings.Split(strings.Trim(proxy, "\n\r"), ":")
	if len(split) == 4 {
		if numberReg.MatchString(split[1]) {
			// proxy = ip:port:username:password
			return "http://" + split[2] + ":" + split[3] + "@" + split[0] + ":" + split[1]
		}

		// proxy = ip:port:username:password
		return "http://" + split[0] + ":" + split[1] + "@" + split[2] + ":" + split[3]

	} else if len(split) == 2 {
		// proxy = ip:port
		return "http://" + split[0] + ":" + split[1]

	} else if len(split) == 3 {
		// proxy = username:password@ip:port
		return "http://" + proxy
	}

	return proxy
}

func toBytes(b any) []byte {
	switch b.(type) {
	case string:
		return []byte(b.(string))
	case []byte:
		return b.([]byte)
	case io.Reader:
		var buf = new(bytes.Buffer)
		_, _ = io.Copy(buf, b.(io.Reader))
		return buf.Bytes()
	default:
		var dumped []byte
		dumped, _ = json.Marshal(b)
		return dumped
	}
}
