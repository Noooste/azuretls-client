package azuretls

import "testing"

func TestRedirect(t *testing.T) {

	session := NewSession()

	response, err := session.Get("https://www.nike.com/")

	if err != nil {
		t.Fatal(err)
	}

	if response.StatusCode != 200 {
		t.Fatal("TestRedirect failed, expected: 200, got: ", response.StatusCode)
	}

	if response.Url == "https://www.nike.com/" {
		t.Fatal("TestRedirect failed, still on", response.Url)
	}
}
