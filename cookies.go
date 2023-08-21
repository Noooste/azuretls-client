package azuretls

import (
	http "github.com/Noooste/fhttp"
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
