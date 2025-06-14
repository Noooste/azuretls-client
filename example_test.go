package azuretls_test

import (
	"bytes"
	"fmt"
	"github.com/Noooste/azuretls-client"
	http "github.com/Noooste/fhttp"
	"os"
	"strings"
	"time"
)

func ExampleNewSession() {
	session := azuretls.NewSession()

	resp, err := session.Get("https://www.google.com")

	if err != nil {
		panic(err)
	}

	fmt.Println(resp.StatusCode)

	// Output:
	// 200
}

func ExampleSession_Get() {
	session := azuretls.NewSession()

	resp, err := session.Get("https://www.google.com")

	if err != nil {
		panic(err)
	}

	fmt.Println(resp.StatusCode)

	// Output:
	// 200
}

func ExampleSession_Post() {
	session := azuretls.NewSession()

	resp, err := session.Post("https://httpbin.org/post", `post me`)

	if err != nil {
		panic(err)
	}

	fmt.Println(resp.StatusCode)
	fmt.Println(bytes.Contains(resp.Body, []byte("post me")))

	// Output:
	// 200
	// true
}

func ExampleSession_DumpIgnore() {
	session := azuretls.NewSession()

	if err := session.Dump("./logs", "*.google.com"); err != nil {
		panic(err)
	}

	fmt.Println(session.DumpIgnore("https://www.google.com"))
	fmt.Println(session.DumpIgnore("https://google.com/search"))
	fmt.Println(session.DumpIgnore("https://www.google.com/search"))

	if err := session.Dump("./logs", "/get"); err != nil {
		panic(err)
	}

	fmt.Println(session.DumpIgnore("https://www.google.com"))
	fmt.Println(session.DumpIgnore("https://google.com/search"))
	fmt.Println(session.DumpIgnore("https://www.google.com/get/the/thing"))

	// Output:
	// true
	// true
	// true
	// false
	// false
	// true
}

func ExampleSession_Dump() {
	session := azuretls.NewSession()

	_ = session.Dump("./logs", "*.httpbin.org")

	_, _ = session.Get("https://www.google.com", azuretls.OrderedHeaders{
		{"User-Agent", "Mozilla/5.0"},
		{"Accept", "text/html"},
	})

	_, _ = session.Get("https://httpbin.org/get")

	time.Sleep(1 * time.Second)

	f, _ := os.ReadDir("./logs")

	fmt.Println(len(f))

	// Output:
	// 1
}

func ExampleSession_Log() {
	session := azuretls.NewSession()

	session.Log("/any/path/to/ignore", "can.ignore.this", "*.all.subdomains")

	_, _ = session.Get("https://www.google.com")
	_, _ = session.Get("https://www.google.com/any/path/to/ignore")
}

func ExampleSession_SetProxy() {
	session := azuretls.NewSession()

	err := session.SetProxy("http://username:password@proxy:8080")

	if err != nil {
		panic(err)
	}

	fmt.Println(session.Proxy)

	// Output:
	// http://username:password@proxy:8080
}

func ExampleSession_ApplyJa3() {
	session := azuretls.NewSession()

	ja3 := "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,45-13-43-0-16-65281-51-18-11-27-35-23-10-5-17613-21,29-23-24,0"

	if err := session.ApplyJa3(ja3, azuretls.Chrome); err != nil {
		panic(err)
	}

	resp, err := session.Get("https://tls.peet.ws/api/all")

	if err != nil {
		panic(err)
	}

	fmt.Println(strings.Contains(resp.String(), ja3))

	// Output:
	// true
}

func ExampleSession_ApplyHTTP2() {
	session := azuretls.NewSession()

	preset := "1:65536;2:0;3:1000;4:6291456;6:262144|15663105|0|m,s,a,p"

	if err := session.ApplyHTTP2(preset); err != nil {
		panic(err)
	}

	resp, err := session.Get("https://tls.peet.ws/api/all")

	if err != nil {
		panic(err)
	}

	fmt.Println(strings.Contains(resp.String(), preset))

	// Output:
	// true
}

func ExampleSession_ApplyHTTP3() {
	session := azuretls.NewSession()

	http3 := "1:16383;7:100;GREASE|m,s,a,p"

	if err := session.ApplyHTTP3(http3); err != nil {
		panic(err)
	}

	resp, err := session.Do(&azuretls.Request{
		Method:     http.MethodGet,
		Url:        "https://tls.peet.ws/api/all",
		ForceHTTP3: true,
	})

	if err != nil {
		panic(err)
	}

	fmt.Println(strings.Contains(resp.String(), http3))

	// Output:
	// true
}

func ExampleUrlEncode() {
	type Foo struct {
		Bar       string `url:"bar"`
		Baz       string `url:"baz"`
		Omit      string `url:"-"`
		OmitEmpty string `url:"no,omitempty"`
	}

	fmt.Println(azuretls.UrlEncode(Foo{
		Bar:       "bar",
		Baz:       "baz baz baz",
		Omit:      "omit",
		OmitEmpty: "",
	}))

	// Output:
	// bar=bar&baz=baz+baz+baz
}

func ExampleToBytes() {
	fmt.Println(string(azuretls.ToBytes("test1")))

	fmt.Println(string(azuretls.ToBytes([]byte("test2"))))

	buf := bytes.NewBufferString("test3")
	fmt.Println(string(azuretls.ToBytes(buf)))

	type s struct {
		A string
		B int
	}
	fmt.Println(string(azuretls.ToBytes(s{"test4", 4})))

	// Output:
	// test1
	// test2
	// test3
	// {"A":"test4","B":4}
}
