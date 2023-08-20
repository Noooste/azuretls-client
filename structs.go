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

// Session represents the core structure for managing and conducting HTTP(S)
// sessions. It holds configuration settings, headers, cookie storage,
// connection pool, and other attributes necessary to perform and customize
// requests.
type Session struct {
	Headers      http.Header // Deprecated: OrderedHeaders should be used instead.
	HeadersOrder HeaderOrder // Deprecated.

	PHeader        PHeader
	OrderedHeaders OrderedHeaders

	CookieJar *cookiejar.Jar // Stores cookies across session requests.
	Browser   string         // Name or identifier of the browser used in the session.

	Connections *ConnPool // Pool of persistent connections to manage concurrent requests.

	tr2 *http2.Transport
	tr  *http.Transport

	GetClientHelloSpec func() *tls.ClientHelloSpec // Function to provide custom TLS handshake details.

	mu *sync.Mutex

	Proxy string // Proxy address.

	Verbose           bool                                                  // If true, print detailed logs or debugging information.
	VerbosePath       string                                                // Path for logging verbose information.
	VerboseIgnoreHost []string                                              // List of hosts to ignore when logging verbose info.
	VerboseFunc       func(request *Request, response *Response, err error) // Custom function to handle verbose logging.

	TimeOut time.Duration // Maximum time to wait for request to complete.

	PreHook  func(request *Request) error                          // Function called before sending request.
	Callback func(request *Request, response *Response, err error) // Function called after receiving a response.

	// Deprecated: This field is ignored as pin verification is always true.
	// To disable pin verification, use InsecureSkipVerify.
	VerifyPins         bool
	InsecureSkipVerify bool // If true, server's certificate is not verified.

	ctx context.Context // Context for cancellable and timeout operations.

	UserAgent, SecChUa string // Headers for User-Agent and Sec-Ch-Ua, respectively.

	ServerPush chan *Response // Channel to receive server push notifications.
}

// Request represents the details and configuration for an individual HTTP(S)
// request. It encompasses URL, headers, method, body, proxy settings,
// timeouts, and other configurations necessary for customizing the request
// and its execution.
type Request struct {
	HttpRequest *http.Request

	Method string // HTTP method, e.g., GET, POST.

	Url       string
	parsedUrl *url.URL // Parsed version of Url.

	Body any
	body []byte

	PHeader     PHeader
	Header      http.Header // Deprecated: OrderedHeaders should be used instead.
	HeaderOrder HeaderOrder // Deprecated.

	OrderedHeaders OrderedHeaders
	conn           *Conn // Connection associated with the request.

	Proxy   string
	Browser string

	DisableRedirects bool // If true, redirects won't be followed.
	NoCookie         bool // If true, cookies won't be included in the request.

	TimeOut time.Duration // Maximum time to wait for request to complete.

	IsRedirected bool // Indicates if the current request is a result of a redirection.

	FetchServerPush    bool // If true, the request will fetch server pushes.
	InsecureSkipVerify bool // If true, server's certificate is not verified.

	IgnoreBody bool // If true, the body of the response is not read.

	Proto            string
	listenServerPush bool // Indicates whether to listen for server pushes.

	contentLength int64 // Length of content in the request.

	retries uint8           // Number of retries for the request.
	ctx     context.Context // Context for cancellable and timeout operations.
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

	TLS *tls.ConnectionState // TLS connection details if the request was over HTTPS.

	ContentLength int64 // Length of content in the response.
}
