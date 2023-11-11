package azuretls

import (
	"bytes"
	"encoding/json"
	"fmt"
	"golang.org/x/net/idna"
	"io"
	"math/rand"
	"net/url"
	"reflect"
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
	Socks5      = "socks5"
	Socks5H     = "socks5h"
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
	SchemeHttp:  "80",
	SchemeHttps: "443",
	SchemeWs:    "80",
	SchemeWss:   "443",
	"socks5":    "1080",
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

// UrlEncode encodes a map[string]string to url encoded string
// Example:
//
//	UrlEncodeMap(map[string]string{"bar": "foo", "foo": "bar"})
//	returns "bar=foo&foo=bar"
//
// If you want to encode a struct, you can use the `url` tag
// Example:
//
//	type Foo struct {
//		Bar string `url:"bar"`
//		Baz string `url:"baz"`
//	}
//
//	UrlEncode({
//		Bar: "bar",
//		Baz: "baz baz baz",
//	})
//	returns "bar=bar&baz=baz+baz+baz"
func UrlEncode(obj any) string {
	r := reflect.ValueOf(obj)

	if r.Kind() == reflect.Ptr {
		r = r.Elem()
	}

	switch r.Kind() {
	case reflect.Map:
		keys := r.MapKeys()
		var result []string
		for _, key := range keys {
			result = append(result, fmt.Sprintf("%s=%v", key, r.MapIndex(key)))
		}
		return strings.Join(result, "&")

	case reflect.Struct:
		var result []string
		for i := 0; i < r.NumField(); i++ {
			if name, ok := r.Type().Field(i).Tag.Lookup("url"); ok {
				//detect if omitempty is set
				split := strings.Split(name, ",")
				if len(split) > 1 && split[1] == "omitempty" {
					if r.Field(i).IsZero() {
						continue
					}
				}
				result = append(result, fmt.Sprintf("%s=%s", split[0], url.QueryEscape(fmt.Sprintf("%v", r.Field(i)))))
			}

		}
		return strings.Join(result, "&")

	case reflect.String:
		return url.QueryEscape(r.String())

	default:
		return ""
	}
}
