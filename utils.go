package azuretls

import (
	"bytes"
	"encoding/json"
	"errors"
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

	defaultUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36"
)

var (
	rdn       = rand.New(rand.NewSource(time.Now().UnixNano()))
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

// ToBytes converts any type to []byte, it supports string, []byte, io.Reader,
// strings.Builder and any other type that can be marshaled to json
func ToBytes(b any) []byte {
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

func toReader(b any) (io.Reader, error) {
	switch b.(type) {
	case string:
		return strings.NewReader(b.(string)), nil

	case []byte:
		return bytes.NewReader(b.([]byte)), nil

	case io.Reader:
		return b.(io.Reader), nil

	case bytes.Buffer:
		buf := b.(bytes.Buffer)
		return bytes.NewReader(buf.Bytes()), nil

	case strings.Builder:
		buf := b.(strings.Builder)
		return strings.NewReader(buf.String()), nil

	case *strings.Builder:
		buf := b.(*strings.Builder)
		return strings.NewReader(buf.String()), nil

	default:
		value := reflect.ValueOf(b)

		if value.Kind() == reflect.Ptr {
			value = value.Elem()
		}

		switch value.Kind() {
		case reflect.Struct, reflect.Map, reflect.Slice, reflect.Array:
			var (
				dumped []byte
				err    error
			)

			if dumped, err = json.Marshal(b); err != nil {
				return nil, err
			}

			return bytes.NewReader(dumped), nil

		default:
			return nil, errors.New("unsupported body type : " + value.Kind().String())
		}
	}
}

var portMap = map[string]string{
	SchemeHttp:  "80",
	SchemeHttps: "443",
	SchemeWs:    "80",
	SchemeWss:   "443",
	Socks5:      "1080",
	Socks5H:     "1080",
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
// If you want to encode a struct, you will use the `url` tag
func UrlEncode(obj any) string {
	r := reflect.ValueOf(obj)

	if r.Kind() == reflect.Ptr {
		r = r.Elem()
	}

	switch r.Kind() {
	case reflect.Map:
		keys := r.MapKeys()
		var result = make([]string, 0, len(keys))
		for _, key := range keys {
			result = append(result, fmt.Sprintf("%s=%v", key, url.QueryEscape(fmt.Sprintf("%v", r.MapIndex(key)))))
		}
		return strings.Join(result, "&")

	case reflect.Struct:
		var result = make([]string, 0, r.NumField())
		for i := 0; i < r.NumField(); i++ {
			if name, ok := r.Type().Field(i).Tag.Lookup("url"); ok {
				if name == "-" {
					continue
				}
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

func (s *Session) urlMatch(host *url.URL, urls []*regexp.Regexp) bool {
	if urls == nil {
		return false
	}

	for _, h := range urls {
		if h.MatchString(host.String()) {
			return true
		}
	}

	return false
}
