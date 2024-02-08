package azuretls_test

import (
	"github.com/Noooste/azuretls-client"
	"testing"
)

func TestSession_Websocket(t *testing.T) {
	s := azuretls.NewSession()

	_, err := s.NewWebsocket(nil)

	if err == nil {
		t.Fatal("TestSession_Websocket failed, expected: error, got: nil")
	}

	ws, err := s.NewWebsocket(&azuretls.Request{
		Url: "wss://demo.piesocket.com/v3/channel_123?api_key=VCXCEuvhGcBDP7XhiJJUDvR1e1D3eiVjgZ9VRiaV&notify_self",
		OrderedHeaders: azuretls.OrderedHeaders{
			{"User-Agent", "fhttp"},
		},
	})

	if err != nil {
		t.Fatal(err)
	}

	if ws == nil {
		t.Fatal("TestSession_Websocket failed, expected: *Websocket, got: nil")
	}

	if err = ws.WriteJSON(map[string]string{
		"event": "new_message",
	}); err != nil {
		t.Fatal(err)
	}
}
