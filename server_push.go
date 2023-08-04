package azuretls

import (
	"github.com/Noooste/fhttp/http2"
	"time"
)

// DefaultPushHandler default push handler
type DefaultPushHandler struct {
	session *Session
}

func (ph *DefaultPushHandler) HandlePush(r *http2.PushedRequest) {
	select {
	case <-time.After(5 * time.Second):
		r.Cancel()
		return

	default:
		push, err := r.ReadResponse(r.Promise.Context())
		if err != nil {
			return
		}
		var response = new(Response)
		ph.session.buildResponse(response, push)
		if response.Body == nil {
			return
		}
		ph.session.ServerPush <- response
	}
}
