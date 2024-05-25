package azuretls_test

import (
	"github.com/Noooste/azuretls-client"
	http "github.com/Noooste/fhttp"
	"regexp"
	"testing"
)

var userAgentReg = regexp.MustCompile(`user-agent`)
var contentTypeReg = regexp.MustCompile(`content-type`)
var acceptReg = regexp.MustCompile(`accept`)

func TestHeader(t *testing.T) {
	session := azuretls.NewSession()
	defer session.Close()

	session.OrderedHeaders = azuretls.OrderedHeaders{
		{"user-agent", "test"},
		{"accept", "application/json"},
	}

	response, err := session.Get("https://tls.peet.ws/api/all")

	if err != nil {
		t.Fatal(err)
	}

	if response.StatusCode != 200 {
		t.Fatal("TestHeader failed, expected: 200, got: ", response.StatusCode)
	}

	uaIndex := userAgentReg.FindIndex(response.Body)
	if uaIndex == nil {
		t.Fatal("TestHeader failed, User-Agent should be present")
	}

	acceptIndex := acceptReg.FindIndex(response.Body)
	if acceptIndex == nil {
		t.Fatal("TestHeader failed, Accept should be present")
	}

	if uaIndex[0] > acceptIndex[0] {
		t.Fatal("TestHeader failed, User-Agent should be before Accept")
	}

	session = azuretls.NewSession()

	session.OrderedHeaders = azuretls.OrderedHeaders{
		{"accept", "application/json"},
		{"user-agent", "test"},
	}

	response, err = session.Get("https://tls.peet.ws/api/all")

	if err != nil {
		t.Fatal(err)
	}

	if response.StatusCode != 200 {
		t.Fatal("TestHeader failed, expected: 200, got: ", response.StatusCode)
	}

	uaIndex = userAgentReg.FindIndex(response.Body)
	if uaIndex == nil {
		t.Fatal("TestHeader failed, User-Agent should be present")
	}

	acceptIndex = acceptReg.FindIndex(response.Body)
	if acceptIndex == nil {
		t.Fatal("TestHeader failed, Accept should be present")
	}

	if uaIndex[0] < acceptIndex[0] {
		t.Fatal("TestHeader failed, User-Agent should be before Accept")
	}
}

func TestHeader2(t *testing.T) {
	session := azuretls.NewSession()

	session.Header = http.Header{
		"accept":     {"application/json"},
		"user-agent": {"test"},
	}

	session.HeaderOrder = []string{"user-agent", "content-type", "accept"}

	response, err := session.Get("https://tls.peet.ws/api/all")

	if err != nil {
		t.Fatal(err)
	}

	if response.StatusCode != 200 {
		t.Fatal("TestHeader failed, expected: 200, got: ", response.StatusCode)
	}
}

type scrapeResponse struct {
	HttpProtocolVersion string `json:"http_protocol_version"`
	Http2               struct {
		Fingerprint string `json:"fingerprint"`
		Digest      string `json:"digest"`
		Http2Frames []struct {
			Type        int    `json:"type"`
			Name        string `json:"name"`
			SettingsMap struct {
				Field1 int `json:"1"`
				Field2 int `json:"2"`
				Field3 int `json:"4"`
				Field4 int `json:"6"`
			} `json:"settings_map,omitempty"`
			SettingsOrder     []int `json:"settings_order,omitempty"`
			Increment         int   `json:"increment,omitempty"`
			Stream            int   `json:"stream,omitempty"`
			Headers           http.Header
			OrderedHeadersKey []string `json:"ordered_headers_key,omitempty"`
		} `json:"http2_frames"`
	} `json:"http2"`
	Headers struct {
		Fingerprint string `json:"fingerprint"`
		Digest      string `json:"digest"`
		Headers     map[string]string
		Tls         struct {
			Ja3              string `json:"ja3"`
			Ja3Digest        string `json:"ja3_digest"`
			Ja3N             string `json:"ja3n"`
			Ja3NDigest       string `json:"ja3n_digest"`
			ScrapflyFp       string `json:"scrapfly_fp"`
			ScrapflyFpDigest string `json:"scrapfly_fp_digest"`
		} `json:"tls"`
	}
}

func checkOrder(response scrapeResponse, expectedOrder []string) bool {
	for _, frame := range response.Http2.Http2Frames {
		if frame.Name == "HEADERS" {
			for i, order := range frame.OrderedHeadersKey[4:] {
				if expectedOrder[i] != order {
					return false
				}
			}
		}
	}

	return true
}

func TestHeaderAndOrderInParamWithRedirect(t *testing.T) {
	session := azuretls.NewSession()
	defer session.Close()

	session.Log()

	orders := azuretls.HeaderOrder{"cache-control", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "upgrade-insecure-requests", "user-agent", "accept", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-user", "sec-fetch-dest", "accept-encoding", "accept-language"}
	headers := http.Header{
		"accept":                    {"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
		"accept-encoding":           {"gzip, deflate, br"},
		"accept-language":           {"zh-HK,zh-TW;q=0.9,zh;q=0.8"},
		"cache-control":             {"max-age=0"},
		"sec-ch-ua":                 {`"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"`},
		"sec-ch-ua-mobile":          {"?0"},
		"sec-ch-ua-platform":        {`"Windows"`},
		"sec-fetch-site":            {"none"},
		"sec-fetch-mode":            {"navigate"},
		"sec-fetch-user":            {"?1"},
		"sec-fetch-dest":            {"document"},
		"user-agent":                {"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"},
		"upgrade-insecure-requests": {"1"},
	}

	response, err := session.Get("https://jigsaw.w3.org/HTTP/300/302.html", headers, orders)

	if err != nil {
		t.Fatal(err)
	}

	if response.StatusCode != 200 {
		t.Fatal("TestHeader failed, expected: 200, got: ", response.StatusCode)
	}
}

func TestOrderedHeaders_Get(t *testing.T) {
	headers := azuretls.OrderedHeaders{
		{"user-agent", "test"},
		{"content-type", "application/json"},
		{"accept", "application/json"},
	}

	if headers.Get("accept") != "application/json" {
		t.Fatal("TestOrderedHeaders_Get failed, expected: application/json, got: ", headers.Get("accept"))
	}
}

func TestOrderedHeaders_Add(t *testing.T) {
	headers := azuretls.OrderedHeaders{
		{"user-agent", "test"},
		{"content-type", "application/json"},
		{"accept", "application/json"},
	}

	headers.Add("accept", "application/xml")

	if len(headers) != 3 {
		t.Fatal("TestOrderedHeaders_Add failed, expected: 3, got: ", len(headers))
	}

	if headers.Get("accept") != "application/json; application/xml" {
		t.Fatal("TestOrderedHeaders_Add failed, expected: application/xml, got: ", headers.Get("accept"))
	}
}

func TestOrderedHeaders_Del(t *testing.T) {

	headers := azuretls.OrderedHeaders{
		{"user-agent", "test"},
		{"content-type", "application/json"},
		{"accept", "application/json"},
	}

	headers = headers.Remove("accept")

	if len(headers) != 2 {
		t.Fatal("TestOrderedHeaders_Del failed, expected: 2, got: ", len(headers))
	}

	if headers.Get("accept") != "" {
		t.Fatal("TestOrderedHeaders_Del failed, expected: , got: ", headers.Get("accept"))
	}
}

func TestOrderedHeaders_Set(t *testing.T) {

	headers := azuretls.OrderedHeaders{
		{"user-agent", "test"},
		{"content-type", "application/json"},
		{"accept", "application/json"},
	}

	headers.Set("accept", "application/xml")

	if len(headers) != 3 {
		t.Fatal("TestOrderedHeaders_Set failed, expected: 3, got: ", len(headers))
	}

	if headers.Get("accept") != "application/xml" {
		t.Fatal("TestOrderedHeaders_Set failed, expected: application/xml, got: ", headers.Get("accept"))
	}
}

func TestOrderedHeaders_Set2(t *testing.T) {

	headers := azuretls.OrderedHeaders{
		{"user-agent", "test"},
		{"content-type", "application/json"},
		{"accept", "application/json"},
	}

	headers.Set("accept2", "application/xml")

	if len(headers) != 4 {
		t.Fatal("TestOrderedHeaders_Set failed, expected: 3, got: ", len(headers))
	}

	if headers.Get("accept2") != "application/xml" {
		t.Fatal("TestOrderedHeaders_Set failed, expected: application/xml, got: ", headers.Get("accept2"))
	}
}

func TestContentTypeInGetRequest(t *testing.T) {
	session := azuretls.NewSession()

	response, err := session.Get("https://tls.peet.ws/api/all", azuretls.OrderedHeaders{
		{"content-type", "application/json"},
	})

	if err != nil {
		t.Fatal(err)
	}

	if contentTypeReg.FindIndex(response.Body) == nil {
		t.Fatal("TestContentTypeInGetRequest failed, Content-Type should be present")
	}
}
