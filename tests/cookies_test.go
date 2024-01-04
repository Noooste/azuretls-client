package azuretls_test

import (
	"github.com/Noooste/azuretls-client"
	http "github.com/Noooste/fhttp"
	"testing"
)

func TestCookiesToString(t *testing.T) {
	cookies := []*http.Cookie{
		{
			Name:  "test",
			Value: "test",
		},
	}

	if azuretls.CookiesToString(cookies) != "test=test" {
		t.Fatal("TestCookiesToString failed, expected: test=test, got: ", azuretls.CookiesToString(cookies))
	}
}

func TestGetCookiesMap(t *testing.T) {
	cookies := []*http.Cookie{
		{
			Name:  "test",
			Value: "test",
		},
	}

	if azuretls.GetCookiesMap(cookies)["test"] != "test" {
		t.Fatal("TestGetCookiesMap failed, expected: test=test, got: ", azuretls.GetCookiesMap(cookies)["test"])
	}
}
