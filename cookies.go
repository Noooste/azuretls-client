package azuretls

import (
	http "github.com/Noooste/fhttp"
	"net/url"
	"strings"
)

func cookiesToString(cookies []*http.Cookie) string {
	finalString := ""
	for _, el := range cookies {
		finalString += el.Name + "=" + el.Value + "; "
	}

	if finalString != "" {
		return finalString[:len(finalString)-2]
	}

	return finalString
}

func getCookiesMap(cookies []*http.Cookie) map[string]string {
	var result = make(map[string]string)

	for _, cookie := range cookies {
		result[cookie.Name] = cookie.Value
	}

	return result
}

func (s *Session) LoadCookie(cookies string) []*http.Cookie {
	if cookies == "" {
		return nil
	}

	var cookiesList []*http.Cookie

	for _, el := range strings.Split(cookies, ";") {
		cookie := strings.Split(el, "=")
		if len(cookie) == 2 {
			cookiesList = append(cookiesList, &http.Cookie{
				Name:  strings.TrimSpace(cookie[0]),
				Value: strings.TrimSpace(cookie[1]),
			})
		}
	}

	return cookiesList
}

func (s *Session) GetCookies(u string) map[string]string {
	parsed, err := url.Parse(u)
	if err != nil {
		return nil
	}
	return getCookiesMap(s.CookieJar.Cookies(parsed))
}
