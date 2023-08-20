package azuretls

import (
	"bytes"
	"fmt"
	http "github.com/Noooste/fhttp"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
)

func (s *Session) isIgnored(host string) bool {
	if s.VerboseIgnoreHost == nil {
		return false
	}

	for _, h := range s.VerboseIgnoreHost {
		if h == host {
			return true
		}

		if h[0] == '*' && strings.HasSuffix(host, h[2:]) {
			return true
		}
	}
	return false
}

func (s *Session) EnableVerbose(path string, ignoreHost []string) {
	if err := os.MkdirAll(path, 0755); err != nil {
		panic(err)
	}

	s.Verbose = true
	s.VerbosePath = path

	if ignoreHost == nil {
		ignoreHost = []string{}
	}

	s.VerboseIgnoreHost = append(ignoreHost, "ipinfo.org")
}

func (s *Session) saveVerbose(request *Request, response *Response, err error) {
	defer func() {
		if r := recover(); r != nil {
			return
		}
	}()

	if s.VerboseFunc != nil {
		s.VerboseFunc(request, response, err)
		return
	}

	if s.Verbose && !s.isIgnored(request.parsedUrl.Hostname()) {
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

		folderPath := path.Join(s.VerbosePath, request.parsedUrl.Hostname(), strings.Join(pathSplit[:length-1], "/"))

		_ = os.MkdirAll(folderPath, 0755)

		fileName := path.Join(folderPath, pathSplit[length-1])

		iter := 1
		for _, err2 := os.ReadFile(fileName); err2 == nil; _, err2 = os.ReadFile(fileName) {
			fileName = path.Join(folderPath, pathSplit[length-1]+fmt.Sprintf(" (%d)", iter))
			iter++
		}

		request.proxy = s.Proxy
		requestPart := request.String()

		var responsePart string
		if response != nil {
			responsePart = response.String()
		} else {
			responsePart = "error : " + err.Error()
		}

		if err2 := os.WriteFile(fileName, []byte(
			requestPart+"\n\n====================================\n\n"+responsePart+"\n"), 0755); err2 != nil {
		}
	}
}

func (r *Request) String() string {
	var buffer bytes.Buffer
	buffer.WriteString(r.Method + " " + r.Url + "\n\n")

	if r.proxy != "" {
		buffer.WriteString("Proxy : " + r.proxy + "\n\n")
	}

	if h, ok := r.HttpRequest.Header[http.PHeaderOrderKey]; ok {
		for _, v := range h {
			switch v {
			case Authority:
				buffer.WriteString(Authority + ": " + r.parsedUrl.Host + "\n")
			case Method:
				buffer.WriteString(Method + ": " + r.Method + "\n")
			case Path:
				buffer.WriteString(Path + ": " + r.parsedUrl.Path + "\n")
			case Scheme:
				buffer.WriteString(Scheme + ": " + r.parsedUrl.Scheme + "\n")
			}
		}
	}

	writeHeaders(r.HttpRequest.Header, &buffer)

	if r.Body != nil {
		buffer.WriteByte('\n')
		buffer.Write(r.body)
	}

	return buffer.String()
}

func (r *Response) String() string {
	var buffer bytes.Buffer

	buffer.WriteString(strconv.Itoa(r.StatusCode) + "\n\n")

	writeHeaders(r.HttpResponse.Header, &buffer)

	buffer.WriteString("\n")
	buffer.Write(r.Body)

	return buffer.String()
}

func writeHeaders(header http.Header, buf *bytes.Buffer) {
	var kvs []http.HeaderKeyValues

	if headerOrder, ok := header[http.HeaderOrderKey]; ok && len(headerOrder) > 0 {
		order := make(map[string]int)
		for i, v := range headerOrder {
			order[v] = i
		}
		kvs, _ = header.SortedKeyValuesBy(order, make(map[string]bool))
	} else {
		kvs, _ = header.SortedKeyValues(make(map[string]bool))
	}

	for _, kv := range kvs {
		if kv.Key != http.HeaderOrderKey && kv.Key != http.PHeaderOrderKey {
			for _, v := range kv.Values {
				if strings.ToLower(kv.Key) == "cookie" {
					for _, cookie := range strings.Split(v, "; ") {
						buf.WriteString("cookie : " + cookie + "\n")
					}
				} else if strings.ToLower(kv.Key) == "set-cookie" {
					for _, val := range kv.Values {
						buf.WriteString("set-cookie : " + val + "\n")
					}
				} else {
					buf.WriteString(kv.Key + ": " + v + "\n")
				}
			}
		}
	}
}
