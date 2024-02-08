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

	session.OrderedHeaders = azuretls.OrderedHeaders{
		{"user-agent", "test"},
		{"content-type", "application/json"},
		{"accept", "application/json"},
	}

	response, err := session.Get("https://tls.peet.ws/api/all")

	if err != nil {
		t.Fatal(err)
	}

	if response.StatusCode != 200 {
		t.Fatal("TestHeader failed, expected: 200, got: ", response.StatusCode)
	}

	if contentTypeReg.FindIndex(response.Body) != nil {
		t.Fatal("TestHeader failed, Content-Type should not be present")
	}

	uaIndex := userAgentReg.FindIndex(response.Body)[0]
	aIndex := acceptReg.FindIndex(response.Body)[0]

	if uaIndex > aIndex {
		t.Fatal("TestHeader failed, User-Agent should be before Content-Type")
	}
}

func TestHeader2(t *testing.T) {
	session := azuretls.NewSession()

	session.Header = http.Header{
		"user-agent":   {"test"},
		"content-type": {"application/json"},
		"accept":       {"application/json"},
	}

	session.HeaderOrder = []string{"user-agent", "content-type", "accept"}

	response, err := session.Get("https://tls.peet.ws/api/all")

	if err != nil {
		t.Fatal(err)
	}

	if response.StatusCode != 200 {
		t.Fatal("TestHeader failed, expected: 200, got: ", response.StatusCode)
	}

	if contentTypeReg.FindIndex(response.Body) != nil {
		t.Fatal("TestHeader failed, Content-Type should not be present")
	}

	uaIndex := userAgentReg.FindIndex(response.Body)[0]
	aIndex := acceptReg.FindIndex(response.Body)[0]

	if uaIndex > aIndex {
		t.Fatal("TestHeader failed, User-Agent should be before Content-Type")
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
