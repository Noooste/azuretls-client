package azuretls

import (
	"testing"
	"time"
)

func TestServerPush(t *testing.T) {
	t.Parallel()

	s := NewSession()

	response, err := s.Get("https://http2-push.appspot.com/")

	if err != nil {
		t.Fatal(err)
	}

	if response.StatusCode != 200 {
		t.Fatal("Status code is not 200")
	}

	select {
	case <-s.ServerPush:
		t.Log("Server push received")
		break

	case <-time.After(5 * time.Second):
		t.Fatal("Server push not received")
	}
}
