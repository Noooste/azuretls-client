# AzureTLS Client
[![GoDoc](https://godoc.org/github.com/Noooste/azuretls-client?status.svg)](https://godoc.org/github.com/Noooste/azuretls-client)
![Coverage](https://img.shields.io/badge/Coverage-84.3%25-brightgreen)
[![build](https://github.com/Noooste/azuretls-client/actions/workflows/push.yml/badge.svg?branch=improvement)](https://github.com/Noooste/azuretls-client/actions/workflows/push.yml)
[![Go Report Card](https://goreportcard.com/badge/Noooste/azuretls-client)](https://goreportcard.com/report/Noooste/azuretls-client)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/Noooste/azuretls-client/blob/master/LICENSE)

This golang package aims to personate JA3 fingerprint and HTTP/2 specifications.

# Features

- Latest Chrome ClientHello
- Fully customizable ClientHello TLS (JA3 string + extension specifications)
- Proxy and SSL Pinning support
- HTTP/1.1 and HTTP/2 support
- HTTP/2 Frames configuration (SETTINGS, PRIORITY, WINDOW_UPDATE)



Table of Contents
=================



* [Table of Contents](#table-of-contents)
* [Installation](#installation)
* [Usage](#usage)
    * [Create a Session](#create-a-session)
    * [Modify TLS](#modify-tls)
    * [Modify HTTP2](#modify-http2)
    * [Headers](#headers)
    * [Proxy](#proxy)
    * [SSL Pinning](#ssl-pinning)
    * [Timeout](#timeout)
    * [PreHook and CallBack](#prehook-and-callback)
    * [Cookies](#cookies)


## Dependencies

```
golang ^1.18
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

// or with context
session := azuretls.NewSessionWithContext(context.Background())
```

#
### Modify TLS Client Hello (JA3)

To modify your client hello, you have 2 ways :
- The first one is to use the `session.ApplyJA3` method, which takes the ja3 fingerprint and the target navigator (chrome, firefox, safari, ...).
- The second one is to assign a method to `session.GetClientHelloSpec` that returns TLS configuration.

```go
session := azuretls.NewSession()

// First way
if err := session.ApplyJa3("771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,45-13-43-0-16-65281-51-18-11-27-35-23-10-5-17513-21,29-23-24-25-26,0", azuretls.Chrome); err != nil {
    panic(err)
}

// Second way
session.GetClientHelloSpec = azuretls.GetLastChromeVersion //func() *tls.ClientHelloSpec

resp, err := session.Get("https://tls.peet.ws/api/all")

if err != nil {
    panic(err)
}

fmt.Println(resp.StatusCode, string(resp.Body))
```

#
### Modify HTTP2

To modify HTTP2, you have to apply the HTTP2 fingerprint to the session. You can get your HTTP/2 fingerprint there : [https://tls.peet.ws/api/all](https://tls.peet.ws/api/all)
```go
session := azuretls.NewSession()

if err := session.ApplyHTTP2("1:65536,2:0,3:1000,4:6291456,6:262144|15663105|0|m,s,a,p"); err != nil {
    panic(err)
}

resp, err := session.Get("https://tls.peet.ws/api/all")

if err != nil {
    panic(err)
}

fmt.Println(resp.StatusCode, string(resp.Body))
```
#
### Headers

Use `session.OrderedHeaders` method, which is `[][]string`

```go
session := azuretls.NewSession()

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

#
### Proxy

You can set a proxy to the session with the `session.SetProxy` method.
Proxy format supported :
- `http(s)://ip:port`
- `http(s)://username:password@ip:port`
- `ip:port`
- `ip:port:username:password`
- `username:password:ip:port`
- `username:password@ip:port`

```go
session := azuretls.NewSession()

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

```go
session := azuretls.NewSession()

// secured request
response, err := session.Get("https://tls.peet.ws/api/all")

if err != nil {
    panic(err)
}

fmt.Println(response.StatusCode)
fmt.Println(string(response.Body))
```

If you can't trust the machine, you can still set manual pins before doing any requests with the session with method `session.AddPins`.
The pins are generated from DER encoded SubjectPublicKeyInfo sha256 hashed and base64 encoded

```go
session := azuretls.NewSession()

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

You can also call `session.ClearPins` before to remove any pins saved in the session for the given url.

To disable SSL Pinning, you can do `session.InsecureSkipVerify = true`

```go
session := azuretls.NewSession()

session.InsecureSkipVerify = true

// do it at your own risk !
_, err := session.Get("https://tls.peet.ws/api/all")

if err != nil {
    panic(err)
}
```
#
### Timeout

You can set a timeout to the session with the `session.SetTimeout` method.

```go
session := azuretls.NewSession()

session.SetTimeout(5 * time.Second)

response, err := session.Get("https://tls.peet.ws/api/all")

if err != nil {
    panic(err)
}

fmt.Println(response.StatusCode, string(response.Body))
```
#
### PreHook and CallBack

You can modify all the requests done with the session before it does it by using prehook to the session with the `session.PreHook` method.
You can also set callback to the session with the `session.CallBack` method.

```go
session := azuretls.NewSession()

session.PreHook = func(request *azuretls.Request) error {
    req.Header.Set("user-agent", "test")
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

You can manage cookies in the cookie jar of the session.

```go
session := azuretls.NewSession()

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
