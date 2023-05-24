package azuretls

import (
	"github.com/Noooste/fhttp/http2"
	"sync"
	"time"
)

// DefaultPushHandler default push handler
type DefaultPushHandler struct {
	request  *Request
	response *Response
	mu       *sync.Mutex

	listen bool
}

func (ph *DefaultPushHandler) HandlePush(r *http2.PushedRequest) {
	go func() {
		if !ph.listen {
			return
		}
		push, err := r.ReadResponse(r.Promise.Context())

		if err != nil {
			return
		}

		response := buildServerPushResponse(push)

		ph.mu.Lock()
		ph.response.ServerPush = append(ph.response.ServerPush, response)
		ph.mu.Unlock()
	}()

	select {
	case <-time.After(5 * time.Second):
		r.Cancel()
	}
}
