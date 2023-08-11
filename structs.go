package azuretls

import (
	"context"
	http "github.com/Noooste/fhttp"
	"github.com/Noooste/fhttp/cookiejar"
	"github.com/Noooste/fhttp/http2"
	tls "github.com/Noooste/utls"
	"io"
	"net/url"
	"sync"
	"time"
)

const (
	Path      = ":path"
	Method    = ":method"
	Authority = ":authority"
	Scheme    = ":scheme"
)

type Session struct {
	Headers      http.Header //deprecated, use OrderedHeaders instead
	HeadersOrder HeaderOrder //deprecated

	PHeader PHeader

	OrderedHeaders OrderedHeaders

	CookieJar *cookiejar.Jar
	Browser   string

	Connections *ConnPool

	tr2 *http2.Transport
	tr  *http.Transport

	GetClientHelloSpec func() *tls.ClientHelloSpec

	mu *sync.Mutex

	Proxy       string
	RotateProxy bool

	Verbose           bool
	VerbosePath       string
	VerboseIgnoreHost []string

	VerboseFunc func(request *Request, response *Response, err error)

	TimeOut time.Duration

	PreHook  func(request *Request) error
	Callback func(request *Request, response *Response, err error)

	VerifyPins         bool // deprecated, this parameter is ignored as verify pins is always true. To disable pin verification, use the InsecureSkipVerify parameter instead
	InsecureSkipVerify bool

	ctx context.Context

	UserAgent, SecChUa string

	ServerPush chan *Response
}

type Request struct {
	HttpRequest *http.Request

	Method string

	Url       string
	parsedUrl *url.URL

	Body any
	body []byte

	PHeader PHeader

	Header      http.Header //deprecated, use OrderedHeaders instead
	HeaderOrder HeaderOrder //deprecated, use OrderedHeaders instead

	OrderedHeaders OrderedHeaders
	conn           *Conn

	Proxy   string
	Browser string

	DisableRedirects bool
	NoCookie         bool

	TimeOut time.Duration

	IsRedirected bool

	FetchServerPush    bool
	InsecureSkipVerify bool

	IgnoreBody bool

	Proto            string
	listenServerPush bool

	contentLength int64

	retries uint8
	ctx     context.Context
}

type Response struct {
	Id         uint64
	StatusCode int
	Body       []byte
	RawBody    io.ReadCloser
	Header     http.Header
	Cookies    map[string]string
	Url        string
	IgnoreBody bool

	HttpResponse *http.Response

	Request *Request

	TLS *tls.ConnectionState

	ContentLength int64
}

type ServerPush struct {
	StatusCode int               `json:"status_code"`
	Body       string            `json:"body"`
	Headers    map[string]string `json:"headers"`
	Cookies    map[string]string `json:"cookies"`
	Url        string            `json:"url"`
}
