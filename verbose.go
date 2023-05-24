package azuretls

import (
	http "github.com/Noooste/fhttp"
	"net/url"
	"os"
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
		path := request.parsedUrl.Path
		if path == "" {
			path = "/"
		}

		if path[len(path)-1] == '/' {
			path += "$no_name$"
		}

		pathSplit := strings.Split(path, "/")
		length := len(pathSplit)

		for i := 0; i < length; i++ {
			pathSplit[i] = url.PathEscape(pathSplit[i])
		}

		folderPath := s.VerbosePath + "/" + request.parsedUrl.Host + "/" + strings.Join(pathSplit[:length-1], "/")

		_ = os.MkdirAll(folderPath, 0755)

		fileName := folderPath + "/" + "$" + pathSplit[length-1]

		iter := 1
		for _, err = os.ReadFile(fileName); err == nil; _, err = os.ReadFile(fileName) {
			fileName = folderPath + "/" + pathSplit[length-1] + " (" + strconv.Itoa(iter) + ")"
			iter++
		}

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
	buffer := strings.Builder{}
	buffer.WriteString(r.Method + " " + r.Url + "\n\n")

	if r.Proxy != "" {
		buffer.WriteString("Proxy : " + r.Proxy + "\n\n")
	}

	var kvs []http.HeaderKeyValues

	if headerOrder := r.HttpRequest.Header[http.HeaderOrderKey]; len(headerOrder) > 0 {
		order := make(map[string]int)
		for i, v := range headerOrder {
			order[v] = i
		}
		kvs, _ = r.HttpRequest.Header.SortedKeyValuesBy(order, make(map[string]bool))

	} else {
		kvs, _ = r.HttpRequest.Header.SortedKeyValues(make(map[string]bool))
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

	for _, kv := range kvs {
		if kv.Key != http.HeaderOrderKey && kv.Key != http.PHeaderOrderKey {
			for _, v := range kv.Values {
				if strings.ToLower(kv.Key) == "cookie" {
					for _, cookie := range strings.Split(v, "; ") {
						buffer.WriteString("cookie : " + cookie + "\n")
					}
				} else {
					buffer.WriteString(kv.Key + ": " + v + "\n")
				}
			}
		}
	}

	if r.Body != nil {
		buffer.WriteString("\n")
		buffer.Write(r.Body)
	}

	return buffer.String()
}

func (r *Response) String() string {
	buffer := strings.Builder{}

	buffer.WriteString(strconv.Itoa(r.StatusCode) + "\n\n")

	for key, value := range r.Header {
		if key != http.HeaderOrderKey && key != http.PHeaderOrderKey {
			if strings.ToLower(key) == "set-cookie" {
				for _, v := range value {
					buffer.WriteString("set-cookie : " + v + "\n")
				}
			} else {
				for _, v := range value {
					buffer.WriteString(key + ": " + v + "\n")
				}
			}
		}
	}

	buffer.WriteString("\n")
	buffer.Write(r.Body)

	return buffer.String()
}
