package azuretls

import (
	"bytes"
	"fmt"
	http "github.com/Noooste/fhttp"
	"net/url"
	"os"
	"path"
	"regexp"
	"strings"
)

var nonAlphaNumeric = regexp.MustCompile(`([^a-zA-Z0-9*])`)

func replaceNonAlphaNumeric(s string) string {
	return nonAlphaNumeric.ReplaceAllString(s, "\\$1")
}

// Dump will activate requests and responses dumping to the specified directory
//
// dir is the directory to save the logs
//
// ignore (optional) is a list of uri to ignore,
// if ignore is empty, all uri will be logged
func (s *Session) Dump(dir string, uris ...string) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	s.dump = true
	s.dumpDir = dir

	if len(uris) == 0 {
		s.dumpIgnore = []*regexp.Regexp{}
		return nil
	}

	s.dumpIgnore = make([]*regexp.Regexp, 0, len(uris))

	for _, v := range uris {
		s.dumpIgnore = append(s.dumpIgnore, regexp.MustCompile(
			fmt.Sprintf(".*%s.*",
				strings.ReplaceAll(
					replaceNonAlphaNumeric(v), "*\\.", ".*\\.?",
				),
			),
		))
	}

	return nil
}

// DisableDump will disable requests and responses dumping
func (s *Session) DisableDump() {
	s.dump = false
}

// EnableDump will enable requests and responses dumping
func (s *Session) EnableDump() {
	s.dump = true
}

// DumpIgnore will check if the given uri is ignored from dumping
func (s *Session) DumpIgnore(uri string) bool {
	parsed, err := url.Parse(uri)

	if err != nil {
		return false
	}

	return s.urlMatch(parsed, s.dumpIgnore)
}

// DumpAndLog will activate requests and responses dumping to the specified directory
// and log the requests and responses
func (s *Session) DumpAndLog(dir string, uris ...string) error {
	if err := s.Dump(dir, uris...); err != nil {
		return err
	}

	s.Log(uris...)

	return nil
}

func (s *Session) dumpRequest(request *Request, response *Response, err error) {
	if !s.dump {
		return
	}

	if s.VerboseFunc != nil {
		s.VerboseFunc(request, response, err)
		return
	}

	if !s.urlMatch(request.parsedUrl, s.dumpIgnore) {
		reqUrl := request.parsedUrl.Path
		if reqUrl == "" {
			reqUrl = "/"
		}

		if reqUrl[len(reqUrl)-1] == '/' {
			reqUrl += "index.html"
		}

		pathSplit := strings.Split(reqUrl, "/")
		length := len(pathSplit)

		for i := 0; i < length; i++ {
			pathSplit[i] = url.PathEscape(pathSplit[i])
		}

		folderPath := path.Join(s.dumpDir, request.parsedUrl.Hostname(), strings.Join(pathSplit[:length-1], "/"))

		_ = os.MkdirAll(folderPath, 0755)

		fileName := path.Join(folderPath, pathSplit[length-1])

		iter := 1
		for _, err2 := os.ReadFile(fileName); err2 == nil; _, err2 = os.ReadFile(fileName) {
			fileName = path.Join(folderPath, pathSplit[length-1]+fmt.Sprintf(" (%d)", iter))
			iter++
		}

		request.proxy = s.Proxy
		requestPart := request.toString()

		var responsePart string
		if response != nil {
			responsePart = response.toString()
		} else {
			responsePart = "error : " + err.Error()
		}

		if err2 := os.WriteFile(fileName, []byte(fmt.Sprintf(
			"%s\n\n%s\n\n\n%s", requestPart, strings.Repeat("=", 80), responsePart,
		)), 0755); err2 != nil {
			return
		}
	}
}

const newPart = "\n\n"

func (r *Request) toString() string {
	var buffer bytes.Buffer
	buffer.Grow(1024)

	if r.proxy != "" {
		buffer.WriteString(fmt.Sprintf("Proxy : %s", r.proxy))
	} else {
		buffer.WriteString("Proxy : none")
	}
	buffer.WriteString(newPart)

	buffer.WriteString(fmt.Sprintf("%s %s %s", r.Method, r.Url, r.Proto))
	buffer.WriteString(newPart)

	if h, ok := r.HttpRequest.Header[http.PHeaderOrderKey]; ok {
		mapping := map[string]string{
			Authority: r.parsedUrl.Host,
			Method:    r.Method,
			Path:      r.parsedUrl.Path,
			Scheme:    r.parsedUrl.Scheme,
		}

		for _, v := range h {
			buffer.WriteString(fmt.Sprintf("%s: %s\n", v, mapping[v]))
		}
	}

	writeHeaders(r.HttpRequest.Header, &buffer)

	if r.Body != nil {
		buffer.WriteByte('\n')
		buffer.Write(r.body)
	}

	return buffer.String()
}

func (r *Response) toString() string {
	var buffer bytes.Buffer
	buffer.Grow(1024)

	buffer.WriteString(fmt.Sprintf("Status : %d %s", r.StatusCode, http.StatusText(r.StatusCode)))
	buffer.WriteString(newPart)

	writeHeaders(r.Header, &buffer)

	buffer.WriteString("\n")
	buffer.Write(r.Body)

	return buffer.String()
}

type orderedHeaders struct {
	key    string
	values []string
}

func writeHeaders(headers http.Header, buf *bytes.Buffer) {
	var kvs []orderedHeaders

	if headerOrder, ok := headers[http.HeaderOrderKey]; ok && len(headerOrder) > 0 {
		order := make(map[string]int, len(headerOrder))
		for i, v := range headerOrder {
			order[v] = i
		}

		kvs = make([]orderedHeaders, 0, len(headers))

		for _, vv := range headerOrder {
			header := headers[vv]

			if len(header) <= 1 {
				continue
			}

			kvs = append(kvs, orderedHeaders{vv, header})
		}

	} else {
		kvs = make([]orderedHeaders, 0, len(headers))

		for k, vv := range headers {
			if len(vv) > 0 {
				kvs = append(kvs, orderedHeaders{k, vv})
			}
		}
	}

	for _, kv := range kvs {
		if kv.key != http.HeaderOrderKey && kv.key != http.PHeaderOrderKey {
			for _, v := range kv.values {
				if strings.ToLower(kv.key) == "cookie" {
					for _, cookie := range strings.Split(v, "; ") {
						buf.WriteString("cookie: " + cookie + "\n")
					}
				} else {
					buf.WriteString(kv.key + ": " + v + "\n")
				}
			}
		}
	}
}
