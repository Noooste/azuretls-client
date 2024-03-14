package azuretls_test

import (
	"github.com/Noooste/azuretls-client"
	"testing"
)

func TestSession_Websocket(t *testing.T) {
	s := azuretls.NewSession()

	_, err := s.NewWebsocket("", 0, 0)

	if err == nil {
		t.Fatal("TestSession_Websocket failed, expected: error, got: nil")
	}

	ws, err := s.NewWebsocket(
		"wss://demo.piesocket.com/v3/channel_123?api_key=VCXCEuvhGcBDP7XhiJJUDvR1e1D3eiVjgZ9VRiaV&notify_self",
		1024, 1024,
		azuretls.OrderedHeaders{
			{"User-Agent", "fhttp"},
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

func TestSession_WebsocketDiscord(t *testing.T) {
	session := azuretls.NewSession()
	defer session.Close()

	ws, err := session.NewWebsocket("wss://gateway.discord.gg/?encoding=etf&v=9&compress=zlib-stream", 1024, 1024, azuretls.OrderedHeaders{
		{"Host"},
		{"Connection"},
		{"Pragma", "no-cache"},
		{"Cache-Control", "no-cache"},
		{"User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"},
		{"Upgrade"},
		{"Origin", "https://discord.com"},
		{"Sec-WebSocket-Version"},
		{"Accept-Encoding", "gzip, deflate, br"},
		{"Accept-Language", "en-US,en;q=0.9"},
		{"Sec-WebSocket-Key"},
		{"Sec-WebSocket-Extensions"},
	})

	if err != nil {
		t.Fatal(err)
		return
	}

	_, _, err = ws.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
}
