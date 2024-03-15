package azuretls

import (
	"context"
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
	loggingIgnore []string

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

	Method string // HTTP method, e.g., GET, POST.

	Url       string
	parsedUrl *url.URL // Parsed version of Url.

	Body any
	body []byte

	PHeader        PHeader
	OrderedHeaders OrderedHeaders

	Header      http.Header // Headers for the request. Deprecated: Use OrderedHeaders instead.
	HeaderOrder HeaderOrder // Order of headers for the request.

	conn *Conn // Connection associated with the request.

	proxy   string
	ua      string
	browser string

	DisableRedirects bool // If true, redirects won't be followed.
	MaxRedirects     uint // Maximum number of redirects to follow.

	NoCookie bool // If true, cookies won't be included in the request.

	TimeOut time.Duration // Maximum time to wait for request to complete.

	IsRedirected bool // Indicates if the current request is a result of a redirection.

	InsecureSkipVerify bool // If true, server's certificate is not verified.

	IgnoreBody bool // If true, the body of the response is not read.

	Proto string

	ForceHTTP1 bool

	ContentLength int64 // Length of content in the request.

	ctx context.Context // Context for cancellable and timeout operations.

	startTime time.Time

	deadline time.Time
}

// Response encapsulates the received data and metadata from an HTTP(S)
// request. This includes status code, body, headers, cookies, associated
// request details, TLS connection state, etc.
type Response struct {
	StatusCode int // HTTP status code, e.g., 200, 404.

	Body       []byte            // Byte representation of the response body.
	RawBody    io.ReadCloser     // Raw body stream.
	Header     http.Header       // Response headers.
	Cookies    map[string]string // Parsed cookies from the response.
	Url        string            // URL from which the response was received.
	IgnoreBody bool              // Indicates if the body of the response was ignored.

	HttpResponse *http.Response // The underlying HTTP response.

	Request *Request // Reference to the associated request.

	ContentLength int64 // Length of content in the response.
}

type Context struct {
	Session  *Session
	Request  *Request
	Response *Response

	Err error

	RequestStartTime time.Time
}
