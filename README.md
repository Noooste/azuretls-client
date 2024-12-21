# AzureTLS Client 
[![GoDoc](https://godoc.org/github.com/Noooste/azuretls-client?status.svg)](https://godoc.org/github.com/Noooste/azuretls-client)
![Coverage](https://img.shields.io/badge/Coverage-76.5%25-brightgreen)
[![build](https://github.com/Noooste/azuretls-client/actions/workflows/push.yml/badge.svg)](https://github.com/Noooste/azuretls-client/actions/workflows/push.yml)
[![Go Report Card](https://goreportcard.com/badge/Noooste/azuretls-client)](https://goreportcard.com/report/Noooste/azuretls-client)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/Noooste/azuretls-client/blob/master/LICENSE)

# 📖 Introduction 

Welcome to AzureTLS Client, a robust and flexible HTTP client library for Golang designed with security and customization in mind. Whether you're building a web scraper, an API client, or any application that requires HTTP requests, AzureTLS Client provides a suite of features to meet your needs.

## Why AzureTLS Client?

- **Security**: With built-in SSL pinning and proxy support, AzureTLS Client takes security seriously, ensuring your connections are secure and reliable.
  
- **Customization**: Modify TLS ClientHello fingerprints, configure HTTP/2 settings, and even set ordered headers. AzureTLS Client is built to be as flexible as your project requires.
  
- **Performance**: Built on top of Golang's native packages, AzureTLS Client is designed for speed and efficiency, making it suitable for both small and large-scale applications.

Whether you're a seasoned developer looking for a feature-rich HTTP client or you're just getting started with Golang, AzureTLS Client offers a blend of performance, customization, and security to help you build better applications.


# 🌟 Features 

- Latest Chrome ClientHello Support
- HTTP/1.1 and HTTP/2 Compatibility
- Customizable ClientHello TLS (JA3 strings and extensions)
- Configurable HTTP/2 Frames (SETTINGS, PRIORITY, WINDOW_UPDATE)
- Built-in Proxy Support
- SSL Pinning
- PreHook and Callback Functions
- Integrated Cookie Jar
- Websocket with JA3



📑 Table of Contents
=================

* [Table of Contents](#-table-of-contents)
* [Dependencies](#dependencies)
* [Installation](#installation)
* [Usage](#usage)
   * [Create a Session](#create-a-session)
   * [Make Requests](#make-requests)
      * [GET](#get)
      * [POST](#post)
      * [PUT](#put)
      * [PATCH](#patch)
      * [DELETE](#delete)
      * [OPTIONS](#options)
      * [HEAD](#head)
      * [CONNECT](#connect)
   * [Modify TLS Client Hello (JA3)](#modify-tls-client-hello-ja3)
   * [Modify HTTP2](#modify-http2)
   * [Headers](#headers)
   * [Proxy](#proxy)
   * [SSL Pinning](#ssl-pinning)
   * [Timeout](#timeout)
   * [PreHook and CallBack](#prehook-and-callback)
   * [Cookies](#cookies)
   * [Websocket](#websocket)
   * [Utils](#utils)
      * [Response to JSON](#response-to-json)
      * [Url encode](#url-encode)
   * [Dump](#dump)
   * [Log](#log)


## Dependencies

```
golang ^1.22
```

## Installation

```bash
$ go get github.com/Noooste/azuretls-client
````

## Usage

```go
import (
    "github.com/Noooste/azuretls-client"
)
```

### Create a Session
```go
// without context
session := azuretls.NewSession()
// don't forget to close the session when you no longer need it, to free up resources
defer session.Close() 

// or with context
session := azuretls.NewSessionWithContext(context.Background())
defer session.Close()
```
### Predefined browsers/devices

Some browsers/devices are already defined in the module:
- Chrome 
- Firefox
- Opera  
- Safari 
- Edge   
- Ios

In order to use them, you can simply do:

```go
// without context
session := azuretls.NewSession()
// don't forget to close the session when you no longer need it, to free up resources
defer session.Close() 

session.Browser = azuretls.Firefox // JA3 and HTTP2 specifications will be automatically set
```

### Make Requests

#### REQUEST ARGUMENTS

You can pass arguments to the request methods.
Valid arguments are:
- `azuretls.OrderedHeaders`: for ordered headers (of type `[][]string`)
- `http.Header`: for headers (of type `map[string]string`)
- `azuretls.HeaderOrder`: for `http.Header` order  (of type `[]string`)
- `time.Duration`: for the request timeout

#### REQUEST REDIRECTS

By default, the azuretls client follows redirects. If you want to disable it, you can do `request.DisableRedirects = true`.
Otherwise, it will follow redirects until the `MaxRedirects` limit is reached (default: 10).
You can modify the maximum number of redirects with `session.MaxRedirects` or `request.MaxRedirects`.

#### GET
```go
session := azuretls.NewSession()
defer session.Close()

response, err := session.Get("https://tls.peet.ws/api/all")

if err != nil {
    panic(err)
}

fmt.Println(response.StatusCode, string(response.Body))
```

To do a POST, PUT or PATCH requests, you can use as body:
  - `string` 
  - `[]byte`
  - `io.Reader` 
  - anything that can be marshalled to JSON
    
#### POST

```go
session := azuretls.NewSession()
defer session.Close()

response, err := session.Post("https://tls.peet.ws/api/all", `{"test": "test"}`)
// or
response, err := session.Post("https://tls.peet.ws/api/all", map[string]string{"test": "test"})
// or
response, err := session.Post("https://tls.peet.ws/api/all", []byte(`{"test": "test"}`))
```

#### PUT
```go
session := azuretls.NewSession()
defer session.Close()

// the body follows the same semantics as the POST request.
response, err := session.Put("https://tls.peet.ws/api/all", `{"test": "test"}`)
```

#### PATCH
```go
session := azuretls.NewSession()
defer session.Close()

// the body follows the same semantics as the POST request.
response, err := session.Patch("https://tls.peet.ws/api/all", `{"test": "test"}`)
```

#### DELETE
```go
session := azuretls.NewSession()
defer session.Close()

response, err := session.Delete("https://tls.peet.ws/api/all")
```

#### OPTIONS
```go
session := azuretls.NewSession()
defer session.Close()

response, err := session.Options("https://tls.peet.ws/api/all")
```

#### HEAD
```go
session := azuretls.NewSession()
defer session.Close()

response, err := session.Head("https://tls.peet.ws/api/all")
```

#### CONNECT

`session.Connect` is a method that allows you to connect to a website without sending any HTTP request.
It initiates the TLS handshake and the HTTP connection.
This ensures that the server connection is made first, to avoid having to make these connections during the next requests.

```go
session := azuretls.NewSession()
defer session.Close()

response, err := session.Connect("https://tls.peet.ws/api/all")
```

#
### Modify TLS Client Hello (JA3)

To modify your ClientHello, you have two options:
- The first one is to use the `session.ApplyJA3` method, which takes a JA3 fingerprint and the target browser (chrome, firefox, safari, ...).
- The second one is to assign a method to `session.GetClientHelloSpec` that returns TLS configuration.

You can retrieve your JA3 fingerprint there : [tls.peet.ws](https://tls.peet.ws/)

```go
session := azuretls.NewSession()
defer session.Close()

// First method
if err := session.ApplyJa3("771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,45-13-43-0-16-65281-51-18-11-27-35-23-10-5-17513-21,29-23-24-25-26,0", azuretls.Chrome); err != nil {
    panic(err)
}

// Second method
session.GetClientHelloSpec = azuretls.GetLastChromeVersion //func() *tls.ClientHelloSpec

response, err := session.Get("https://tls.peet.ws/api/all")

if err != nil {
    panic(err)
}

// response *azuretls.Response
fmt.Println(response.StatusCode, string(response.Body))
```

#
### Modify HTTP2

To modify HTTP2, you have to apply the HTTP2 fingerprint to the session. 
You can retrieve your HTTP/2 fingerprint there : [tls.peet.ws](https://tls.peet.ws/)
```go
session := azuretls.NewSession()
defer session.Close()

if err := session.ApplyHTTP2("1:65536,2:0,3:1000,4:6291456,6:262144|15663105|0|m,s,a,p"); err != nil {
    panic(err)
}

response, err := session.Get("https://tls.peet.ws/api/all")

if err != nil {
    panic(err)
}

fmt.Println(response.StatusCode, string(response.Body))
```
#
### Headers

You can define headers for the session with the `session.Header` attribute, or use the `session.OrderedHeaders` attribute to maintain header order.

```go
session := azuretls.NewSession()
defer session.Close()

// it will keep the order
session.OrderedHeaders = azuretls.OrderedHeaders{
    {"user-agent", "test"},
    {"content-type", "application/json"},
    {"accept", "application/json"},
}

response, err = session.Get("https://tls.peet.ws/api/all")

if err != nil {
    panic(err)
}

fmt.Println(response.StatusCode, string(response.Body))
```

This also works if you pass `azuretls.Header` (or `azuretls.OrderedHeaders`) as arguments to the request methods.

```go
session := azuretls.NewSession()
defer session.Close()

headers := azuretls.OrderedHeaders{
    {"user-agent", "test"},
    {"content-type", "application/json"},
    {"accept", "application/json"},
}

response, err = session.Get("https://tls.peet.ws/api/all", headers)

if err != nil {
    panic(err)
}
```

**NOTE**: For `azuretls.OrderedHeaders`, if you specify only the key, the order will be applied.

```go
session := azuretls.NewSession()
defer session.Close()

headers := azuretls.OrderedHeaders{
    {"Host"}, // it will only apply the order of the Host header
    {"user-agent", "test"},
    {"content-type", "application/json"},
    {"accept", "application/json"},
}

response, err = session.Get("https://tls.peet.ws/api/all", headers)

if err != nil {
    panic(err)
}
```

#
### Proxy

You can set a proxy to the session with the `session.SetProxy` method.

If the proxy needs to be cleared, you can do `session.ClearProxy`.

Supported proxy formats include:
- `http(s)://ip`
- `http(s)://ip:port`
- `http(s)://username:password@ip:port`
- `socks5(h)://ip`
- `socks5(h)://ip:port`
- `socks5(h)://username:password@ip:port`
- `ip:port`
- `ip:port:username:password`
- `username:password:ip:port`
- `username:password@ip:port`
  
*If a scheme is not provided, `http` will be used by default.*

**If you need to use IPV6 proxies, please format it correctly with the appropriate scheme, for example:** `http://user:pass@[2001:0db8:85a3:0000:0000:8a2e:0370:7334]:8080`

```go
session := azuretls.NewSession()
defer session.Close()

if err := session.SetProxy("http://username:password@ip:port"); err != nil {
    panic(err)
}

response, err := session.Get("https://api.ipify.org")

if err != nil {
    panic(err)
}

fmt.Println(response.StatusCode, string(response.Body))
```
#
### SSL Pinning

SSL pinning is enabled by default.

*SSL pinning ensures that you are connecting to the intended server and mitigates the risk of man-in-the-middle attacks, such as those potentially executed using tools like Charles Proxy.*

```go
session := azuretls.NewSession()
defer session.Close()

// secured request
response, err := session.Get("https://tls.peet.ws/api/all")

if err != nil {
    panic(err)
}

fmt.Println(response.StatusCode, string(response.Body))
```

If you're concerned about the reliability of a server, you can improve security by manually setting pins prior to initiating any requests within the session, using the `session.AddPins` method. 
The pins are generated through the following series of steps:

1. SubjectPublicKeyInfo is first DER-encoded.
2. The DER-encoded data is then hashed using the SHA-256 algorithm.
3. Finally, the hashed output is base64 encoded to generate the pin.

*It's not necessary for every certificate in the chain to match a pin. If even a single certificate in the chain matches one of the pre-defined pins, the entire chain is considered valid : this approach allows for flexibility in the certificate chain while still providing an additional layer of security.* 

```go
session := azuretls.NewSession()
defer session.Close()

session.AddPins(&url.URL{
        Scheme: "https",
        Host:   "httpbin.org",
    }, []string{
        "j5bzD/UjYVE+0feXsngcrVs3i1vSaoOOtPgpLBb9Db8=",
        "18tkPyr2nckv4fgo0dhAkaUtJ2hu2831xlO2SKhq8dg=",
        "++MBgDH5WGvL9Bcn5Be30cRcL0f5O+NyoXuWtQdX1aI=",
        "KwccWaCgrnaw6tsrrSO61FgLacNgG2MMLq8GE6+oP5I=",
})

_, err := session.Get("https://httpbin.org/get")

if err != nil {
    panic(err)
}
```

You can also call `session.ClearPins` beforehand to remove any saved pins in the session for the given URL

To disable SSL Pinning, you can do `session.InsecureSkipVerify = true`

```go
session := azuretls.NewSession()
defer session.Close()

session.InsecureSkipVerify = true

// do it at your own risk
response, err := session.Get("https://tls.peet.ws/api/all")

if err != nil {
    panic(err)
}

fmt.Println(response.StatusCode, string(response.Body))
```

#
### Timeout

You can set a timeout to the session with the `session.SetTimeout` method.

```go
session := azuretls.NewSession()
defer session.Close()

session.SetTimeout(5 * time.Second)

response, err := session.Get("https://tls.peet.ws/api/all")

if err != nil {
    panic(err)
}

fmt.Println(response.StatusCode, string(response.Body))
```
#
### PreHook and CallBack

You can use the `session.PreHook` method to modify all outgoing requests in the session before they are executed.
You can also set a callback for the session using the `session.CallBack` method which will be called just after the response received.

```go
session := azuretls.NewSession()
defer session.Close()

session.PreHook = func(request *azuretls.Request) error {
    request.Header.Set("user-agent", "test")
    return nil
}

session.CallBack = func(request *azuretls.Request, response *azuretls.Response, err error) error {
    fmt.Println(response.StatusCode, string(response.Body))
    return nil
}

response, err := session.Get("https://tls.peet.ws/api/all")

if err != nil {
    panic(err)
}
```

### Cookies

You can manage cookies with the jar of the session. Note that azuretls automatically manage cookies when doing requests.
```go
session := azuretls.NewSession()
defer session.Close()

parsed, err := url.Parse("https://tls.peet.ws/api/all")

session.CookieJar.SetCookies(parsed, []*http.Cookie{
    {
        Name:  "test",
        Value: "test",
    },
})

response, err := session.Get("https://tls.peet.ws/api/all")

if err != nil {
    panic(err)
}
```

### Websocket

You can use websocket with `session.NewWebsocket` method.
```go
session := azuretls.NewSession()
defer session.Close()

ws, err := session.NewWebsocket("wss://demo.piesocket.com/v3/channel_123?api_key=VCXCEuvhGcBDP7XhiJJUDvR1e1D3eiVjgZ9VRiaV&notify_self", 1024, 1024,
		azuretls.OrderedHeaders{
			{"User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36"},
		},
})
if err = ws.WriteJSON(map[string]string{
  "event": "new_message",
}); err != nil {
  panic(err)
}
```

### Utils

#### Response to JSON

You can unmarshal the response body (JSON format) into a struct with the `response.JSON` or `response.MustJSON` methods.
```go
session := azuretls.NewSession()
defer session.Close()

response, err := session.Get("https://tls.peet.ws/api/all")

if err != nil {
    panic(err)
}

var data map[string]any

if err := response.JSON(&data); err != nil {
    panic(err)
}

fmt.Println(data)
```

#### Url encode

You can convert a struct into an url encoded string (used for urls or `application/x-www-form-urlencoded`) with the `azuretls.UrlEncode` method.
```go
session := azuretls.NewSession()
defer session.Close()

type Foo struct {
	Bar string `url:"bar"`
	Baz string `url:"baz"`
}

body := azuretls.UrlEncode(Foo{
	Bar: "bar",
	Baz: "baz baz baz",
})

response, err := session.Post("https://tls.peet.ws/api/all", body)

if err != nil {
    panic(err)
}

fmt.Println(response.StatusCode, string(response.Body))
```

### Dump

You can dump the request and response with the `session.Dump` method.
```go
session := azuretls.NewSession()

session.Dump("./my_dump_dir", 
    "/any/path/to/ignore", 
    "can.ignore.this", 
    "*.all.subdomains",
)

session.Get("https://www.google.com")
// the request and response dump will be in the "my_dump_dir" directory.
```

### Log

You can log the request and response with the `session.Log` method.
This will display the request and response in the console.

```go
session := azuretls.NewSession()

session.Log( 
    "/any/path/to/ignore", 
    "can.ignore.this", 
    "*.all.subdomains",
)

session.Get("https://www.google.com")
```

