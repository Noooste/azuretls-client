package azuretls

import (
	"bytes"
	"encoding/json"
	"golang.org/x/net/idna"
	"io"
	"math/rand"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	SchemeHttp  = "http"
	SchemeHttps = "https"
	SchemeWs    = "ws"
	SchemeWss   = "wss"
)

var (
	random    = rand.New(rand.NewSource(time.Now().UnixNano()))
	numberReg = regexp.MustCompile(`\d+`)
)

func formatProxy(proxy string) string {
	var split = strings.Split(strings.Trim(proxy, "\n\r"), ":")
	if len(split) == 4 {
		if numberReg.MatchString(split[1]) {
			// proxy = ip:port:username:password
			return "http://" + split[2] + ":" + split[3] + "@" + split[0] + ":" + split[1]
		}

		// proxy = username:password:ip:port
		return "http://" + split[0] + ":" + split[1] + "@" + split[2] + ":" + split[3]

	} else if len(split) == 2 {
		// proxy = ip:port
		return "http://" + split[0] + ":" + split[1]

	} else if len(split) == 3 {
		// proxy = username:password@ip:port
		return "http://" + proxy
	}

	return ""
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

	case bytes.Buffer:
		buf := b.(bytes.Buffer)
		return buf.Bytes()

	case strings.Builder:
		buf := b.(strings.Builder)
		return []byte(buf.String())

	case *strings.Builder:
		buf := b.(*strings.Builder)
		return []byte(buf.String())

	default:
		var dumped []byte
		dumped, _ = json.Marshal(b)
		return dumped
	}
}

var portMap = map[string]string{
	"http":   "80",
	"https":  "443",
	"socks5": "1080",
}

func idnaASCII(v string) (string, error) {
	if isASCII(v) {
		return v, nil
	}
	return idna.Lookup.ToASCII(v)
}
func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

func isDomainOrSubdomain(sub, parent string) bool {
	if sub == parent {
		return true
	}
	// If sub is "foo.example.com" and parent is "example.com",
	// that means sub must end in "."+parent.
	// Do it without allocating.
	if !strings.HasSuffix(sub, parent) {
		return false
	}
	return sub[len(sub)-len(parent)-1] == '.'
}
