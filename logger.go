package azuretls

import (
	"fmt"
	http "github.com/Noooste/fhttp"
	"github.com/fatih/color"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Log will print the request and response to the console
//
// uris (optional) is a list of uris to ignore,
// if ignore is empty, all uris will be logged
func (s *Session) Log(uris ...string) {
	s.logging = true

	s.loggingIgnore = make([]*regexp.Regexp, 0, len(uris))

	for _, v := range uris {
		s.loggingIgnore = append(s.loggingIgnore, regexp.MustCompile(
			fmt.Sprintf(".*%s.*",
				strings.ReplaceAll(
					replaceNonAlphaNumeric(v), "*\\.", ".*\\.?",
				),
			),
		))
	}
}

// DisableLog will disable request and response logging
func (s *Session) DisableLog() {
	s.logging = false
}

// EnableLog will enable request and response logging
func (s *Session) EnableLog() {
	s.logging = true
}

// LogIgnore will check if the given uri is ignored from dumping
func (s *Session) LogIgnore(uri string) bool {
	parsed, err := url.Parse(uri)

	if err != nil {
		return false
	}

	return s.urlMatch(parsed, s.loggingIgnore)
}

var colorMethodMap = map[string]*color.Color{
	http.MethodGet:     color.New(color.BgBlue, color.FgHiWhite),
	http.MethodPost:    color.New(color.BgHiBlue, color.FgHiWhite),
	http.MethodPut:     color.New(color.BgHiYellow, color.FgBlack),
	http.MethodPatch:   color.New(color.BgHiMagenta, color.FgHiWhite),
	http.MethodDelete:  color.New(color.BgHiRed, color.FgHiWhite),
	http.MethodOptions: color.New(color.BgHiCyan, color.FgHiWhite),
	http.MethodConnect: color.New(color.BgHiWhite, color.FgBlack),
}

func centerString(s string, width int) string {
	if len(s) >= width {
		return s
	}
	leftPadding := (width - len(s)) / 2
	rightPadding := width - len(s) - leftPadding
	return strings.Repeat(" ", leftPadding) + s + strings.Repeat(" ", rightPadding)
}

func (s *Session) logRequest(request *Request) {
	if !s.logging || s.urlMatch(request.parsedUrl, s.loggingIgnore) {
		return
	}

	fmt.Printf("[%s] %v |%s | %s | %25s | %#v\n",
		color.CyanString("AZURETLS"),
		request.startTime.Format("01/02/2006 - 15:04:05"),
		colorMethodMap[request.Method].Sprintf(" %-8s", request.Method),
		centerString(request.Proto, 8),
		request.parsedUrl.Host,
		request.parsedUrl.Path,
	)
}

func getColorStatus(status int) *color.Color {
	switch {
	case status < 200:
		return color.New(color.BgHiCyan, color.FgHiWhite)
	case status < 300:
		return color.New(color.BgHiGreen, color.FgHiWhite)
	case status < 400:
		return color.New(color.BgHiYellow, color.FgHiWhite)
	default:
		return color.New(color.BgHiRed, color.FgHiWhite)
	}
}

func (s *Session) logResponse(response *Response, err error) {
	if !s.logging || s.urlMatch(response.Request.parsedUrl, s.loggingIgnore) {
		return
	}

	now := time.Now()

	if err != nil {
		fmt.Printf("[%s] %v | %s | %13v | %25s | %#v\n",
			color.CyanString("AZURETLS"),
			now.Format("01/02/2006 - 15:04:05"),
			color.New(color.BgRed, color.FgBlack).Sprint(err),
			now.Sub(response.Request.startTime),
			response.Request.parsedUrl.Host,
			response.Request.parsedUrl.Path,
		)
		return
	}

	fmt.Printf("[%s] %v |%s| %13v | %25s | %#v\n",
		color.CyanString("AZURETLS"),
		now.Format("01/02/2006 - 15:04:05"),
		getColorStatus(response.StatusCode).Sprintf(" %3d ", response.StatusCode),
		now.Sub(response.Request.startTime),
		response.Request.parsedUrl.Host,
		response.Request.parsedUrl.Path,
	)
}

// EnableVerbose enables verbose logging
//
// Deprecated: use Dump instead
func (s *Session) EnableVerbose(path string, ignoreHost []string) error {
	return s.Dump(path, ignoreHost...)
}
