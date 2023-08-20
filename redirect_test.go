package azuretls

import "testing"

func TestRedirect(t *testing.T) {
	session := NewSession()

	response, err := session.Get("https://httpbin.org/status/302")

	if err != nil {
		t.Fatal(err)
	}

	if response.StatusCode != 200 {
		t.Fatal("TestRedirect failed, expected: 200, got: ", response.StatusCode)
	}

	if response.Url != "https://httpbin.org/get" {
		t.Fatal("TestRedirect failed, expected: https://httpbin.org/get, got: ", response.Url)
	}
}

func TestRedirect2_307(t *testing.T) {
	session := NewSession()

	response, err := session.Get("https://httpbin.org/status/307")

	if err != nil {
		t.Fatal(err)
	}

	if response.StatusCode != 200 {
		t.Fatal("TestRedirect2_307 failed, expected: 200, got: ", response.StatusCode)
	}

	if response.Url != "https://httpbin.org/get" {
		t.Fatal("TestRedirect2_307 failed, expected: https://httpbin.org/get, got: ", response.Url)
	}
}
