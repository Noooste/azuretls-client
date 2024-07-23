package azuretls

import (
	"context"
	"errors"
	http "github.com/Noooste/fhttp"
	"github.com/Noooste/fhttp/cookiejar"
	"github.com/Noooste/fhttp/http2"
	tls "github.com/Noooste/utls"
	"io"
	"net/url"
	"regexp"
	"sync"
	"time"
)

const (
	Path      = ":path"
	Method    = ":method"
	Authority = ":authority"
	Scheme    = ":scheme"
)

var ErrUseLastResponse = errors.New("azuretls: use last response")

// Session represents the core structure for managing and conducting HTTP(S)
// sessions. It holds configuration settings, headers, cookie storage,
// connection pool, and other attributes necessary to perform and customize
// requests.
type Session struct {
	PHeader        PHeader
	OrderedHeaders OrderedHeaders

	// Default headers for all requests. Deprecated: Use OrderedHeaders instead.
	Header http.Header
	// Order of headers for all requests.
	HeaderOrder HeaderOrder

	// Stores cookies across session requests.
	CookieJar *cookiejar.Jar

	// Name or identifier of the browser used in the session.
	Browser string

	// Pool of persistent connections to manage concurrent requests.
	Connections *ConnPool

	HTTP2Transport *http2.Transport
	Transport      *http.Transport

	// Function to provide custom TLS handshake details.
	GetClientHelloSpec func() *tls.ClientHelloSpec

	mu *sync.Mutex

	// Proxy address.
	Proxy string
	// If true, use HTTP2 for proxy connections.
	H2Proxy        bool
	ProxyDialer    *proxyDialer
	proxyConnected bool

	dump       bool
	dumpDir    string
	dumpIgnore []*regexp.Regexp

	logging       bool
	loggingIgnore []*regexp.Regexp

	// If true, print detailed logs or debugging information. Deprecated: Use Dump instead.
	Verbose bool
	// Path for logging verbose information. Deprecated: Use Log instead.
	VerbosePath string
	// List of hosts to ignore when logging verbose info. Deprecated: Use Log instead.
	VerboseIgnoreHost []string
	// Custom function to handle verbose logging. Deprecated: Use Log instead.
	VerboseFunc func(request *Request, response *Response, err error)

	// Maximum number of redirects to follow.
	MaxRedirects uint
	// Maximum time to wait for request to complete.
	TimeOut time.Duration

	// Deprecated, use PreHookWithContext instead.
	PreHook func(request *Request) error
	// Function called before sending a request.
	PreHookWithContext func(ctx *Context) error

	// Deprecated, use CallbackWithContext instead.
	Callback func(request *Request, response *Response, err error)
	// Function called after receiving a response.
	CallbackWithContext func(ctx *Context)

	// CheckRedirect specifies the policy for handling redirects.
	// If CheckRedirect is not nil, the client calls it before
	// following an HTTP redirect. The arguments req and via are
	// the upcoming request and the requests made already, oldest
	// first. If CheckRedirect returns an error, the Session's Get
	// method returns both the previous Response (with its Body
	// closed) and CheckRedirect's error (wrapped in an url.Error)
	// instead of issuing the Request req.
	// As a special case, if CheckRedirect returns ErrUseLastResponse,
	// then the most recent response is returned, along with a nil error.
	//
	// If CheckRedirect is nil, the Session uses its default policy,
	// which is to stop after 10 consecutive requests.
	CheckRedirect func(req *Request, reqs []*Request) error

	// Deprecated: This field is ignored as pin verification is always true.
	// To disable pin verification, use InsecureSkipVerify.
	VerifyPins bool
	// If true, server's certificate is not verified (insecure: this may facilitate attack from middleman).
	InsecureSkipVerify bool
	// Context for cancellable and timeout operations.
	ctx context.Context
	// Headers for User-Agent and Sec-Ch-Ua, respectively.
	UserAgent string

	closed bool
}

// Request represents the details and configuration for an individual HTTP(S)
// request. It encompasses URL, headers, method, body, proxy settings,
// timeouts, and other configurations necessary for customizing the request
// and its execution.
type Request struct {
	HttpRequest *http.Request
	Response    *Response

	// HTTP method, e.g., GET, POST.
	Method string

	Url string
	// Parsed version of Url.
	parsedUrl *url.URL

	Body any
	body []byte

	PHeader        PHeader
	OrderedHeaders OrderedHeaders

	// Headers for the request. Deprecated: Use OrderedHeaders instead.
	Header http.Header
	// Order of headers for the request.
	HeaderOrder HeaderOrder

	// Connection associated with the request.
	conn *Conn

	proxy   string
	ua      string
	browser string

	// If true, redirects won't be followed.
	DisableRedirects bool
	// Maximum number of redirects to follow.
	MaxRedirects uint
	// If true, cookies won't be included in the request.
	NoCookie bool
	// Maximum time to wait for request to complete.
	TimeOut time.Duration
	// Indicates if the current request is a result of a redirection.
	IsRedirected bool
	// If true, server's certificate is not verified.
	InsecureSkipVerify bool

	// If true, the body of the response is not read.
	// The response body can be read from Response.RawBody and
	// you will have to close using Response.CloseBody manually.
	IgnoreBody bool
	Proto      string
	ForceHTTP1 bool

	// Length of content in the request.
	ContentLength int64
	// Context for cancellable and timeout operations.
	ctx context.Context

	startTime time.Time

	deadline time.Time
}

// Response encapsulates the received data and metadata from an HTTP(S)
// request. This includes status code, body, headers, cookies, associated
// request details, TLS connection state, etc.
type Response struct {
	// HTTP status code, e.g., 200, 404.
	StatusCode int

	// HTTP status message, e.g., "OK", "Not Found".
	Status string

	// Byte representation of the response body.
	Body []byte
	// Raw body stream.
	RawBody io.ReadCloser
	// Response headers.
	Header http.Header
	// Parsed cookies from the response.
	Cookies map[string]string
	// URL from which the response was received.
	Url string
	// Indicates if the body of the response was ignored.
	IgnoreBody bool

	// The underlying HTTP response.
	HttpResponse *http.Response
	// Reference to the associated request.
	Request *Request
	// Length of content in the response.
	ContentLength int64

	Session *Session
}

// Context represents the context of a request. It holds the session, request,
// response, error, and other details associated with the request.
type Context struct {
	// Session is the session associated with the request.
	Session *Session

	// Request is the request being made.
	Request *Request

	// Response is the response received.
	// It can be modified to change the response returned by the request.
	Response *Response

	// Err is the error, if any, that occurred during the request.
	// It can be modified to change the error returned by the request.
	Err error

	// Ctx is the context associated with the request.
	ctx context.Context

	// RequestStartTime is the time when the request was started.
	RequestStartTime time.Time
}
