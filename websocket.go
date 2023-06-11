package azuretls

import (
	"github.com/Noooste/websocket"
	"net"
)

type Websocket struct {
	*websocket.Dialer
}

func (s *Session) Upgrade(resp *Response) (*Websocket, error) {
	ws := new(Websocket)
	ws.Dialer = &websocket.Dialer{
		NetDial: func(network, addr string) (net.Conn, error) {
			if resp.Request.conn.tlsConn == nil {
				return resp.Request.conn.conn, nil
			}
			return resp.Request.conn.tlsConn, nil
		},
	}
	return ws, nil
}

func (s *Session) newDialer() (*Websocket, error) {
	return nil, nil
}
