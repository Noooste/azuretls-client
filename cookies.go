package azuretls

import (
	"bytes"
	http "github.com/Noooste/fhttp"
	"strings"
)

var cookieNameSanitizer = strings.NewReplacer("\n", "-", "\r", "-")

func CookiesToString(cookies []*http.Cookie) string {
	var buf bytes.Buffer

	var length = 0
	for _, el := range cookies {
		length += len(el.Name) + len(el.Value) + 3
	}

	buf.Grow(length)
	for _, el := range cookies {
		buf.WriteString(cookieNameSanitizer.Replace(el.Name))
		buf.WriteByte('=')
		buf.WriteString(cookieNameSanitizer.Replace(el.Value))
		buf.WriteString("; ")
	}

	buf.Truncate(buf.Len() - 2)
	return buf.String()
}

func getCookiesMap(cookies []*http.Cookie) map[string]string {
	var result = make(map[string]string, len(cookies))

	for _, cookie := range cookies {
		result[cookie.Name] = cookie.Value
	}

	return result
}
