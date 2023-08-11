package azuretls

import "testing"

func TestProxy(t *testing.T) {
	session := NewSession()

	response, err := session.Get("https://api.ipify.org/")

	if err != nil {
		t.Fatal(err)
	}

	oldIP := string(response.Body)

	session.InsecureSkipVerify = true

	session.SetProxy("http://localhost:8888")

	response, err = session.Get("https://api.ipify.org/")

	if err != nil {
		t.Fatal(err)
	}

	newIP := string(response.Body)

	if oldIP == newIP {
		t.Fatal("TestProxy failed, IP is not changed")
	}
}
