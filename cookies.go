package azuretls

import (
	http "github.com/Noooste/fhttp"
	"strings"
)

var cookieNameSanitizer = strings.NewReplacer("\n", "-", "\r", "-")

func cookiesToString(cookies []*http.Cookie) string {
	var f = make([]string, 0, len(cookies))
	for _, el := range cookies {
		f = append(f, cookieNameSanitizer.Replace(el.Name)+"="+cookieNameSanitizer.Replace(el.Value))
	}
	return strings.Join(f, "; ")
}

func getCookiesMap(cookies []*http.Cookie) map[string]string {
	var result = make(map[string]string)

	for _, cookie := range cookies {
		result[cookie.Name] = cookie.Value
	}

	return result
}
