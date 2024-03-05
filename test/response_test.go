package azuretls_test

import (
	"github.com/Noooste/azuretls-client"
	http "github.com/Noooste/fhttp"
	"io"
	"testing"
)

func TestResponse_CloseBody(t *testing.T) {
	session := azuretls.NewSession()

	response, err := session.Do(&azuretls.Request{
		Method:     "GET",
		Url:        "https://tls.peet.ws/api/all",
		IgnoreBody: true,
	})

	if err != nil {
		t.Fatal(err)
	}

	if _, err = io.ReadAll(response.RawBody); err != nil {
		t.Fatal("TestResponse_CloseBody failed, expected: nil, got: ", err)
	}

	if err = response.CloseBody(); err != nil {
		t.Fatal("TestResponse_CloseBody failed, expected: nil, got: ", err)
	}
}

func TestResponse_Load(t *testing.T) {
	session := azuretls.NewSession()
	defer session.Close()

	var response, err = session.Do(&azuretls.Request{
		Method:     http.MethodGet,
		Url:        "https://tls.peet.ws/api/all",
		IgnoreBody: true,
	})

	if err != nil {
		t.Fatal(err)
	}

	var loaded map[string]any

	session = azuretls.NewSession()
	defer session.Close()

	if err = response.JSON(&loaded); err == nil {
		t.Fatal("TestResponse_Load failed, expected: err, got: ", nil)
	}

	response, err = session.Get("https://tls.peet.ws/api/all")

	if err != nil {
		t.Fatal(err)
	}

	if err = response.JSON(&loaded); err != nil {
		t.Fatal("TestResponse_Load failed, expected: nil, got: ", err)
	}
}
