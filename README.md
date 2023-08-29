# AzureTLS Client 
[![GoDoc](https://godoc.org/github.com/Noooste/azuretls-client?status.svg)](https://godoc.org/github.com/Noooste/azuretls-client)
![Coverage](https://img.shields.io/badge/Coverage-84.3%25-brightgreen)
[![build](https://github.com/Noooste/azuretls-client/actions/workflows/push.yml/badge.svg?branch=improvement)](https://github.com/Noooste/azuretls-client/actions/workflows/push.yml)
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



📑 Table of Contents
=================

* [Table of Contents](#-table-of-contents)
* [Dependencies](#dependencies)
* [Installation](#installation)
* [Usage](#usage)
   * [Create a Session](#create-a-session)
   * [Modify TLS Client Hello (JA3)](#modify-tls-client-hello-ja3)
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

To modify your ClientHello, you have two options:
- The first one is to use the `session.ApplyJA3` method, which takes the ja3 fingerprint and the target browser (chrome, firefox, safari, ...).
- The second one is to assign a method to `session.GetClientHelloSpec` that returns TLS configuration.

```go
session := azuretls.NewSession()

// First way
if err := session.ApplyJa3("771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,45-13-43-0-16-65281-51-18-11-27-35-23-10-5-17513-21,29-23-24-25-26,0", azuretls.Chrome); err != nil {
    panic(err)
}

// Second way
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

To modify HTTP2, you have to apply the HTTP2 fingerprint to the session. You can get your HTTP/2 fingerprint there : [https://tls.peet.ws/api/all](https://tls.peet.ws/api/all)
```go
session := azuretls.NewSession()

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

Use `session.OrderedHeaders` method, which is `[][]string`

```go
session := azuretls.NewSession()

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

#
### Proxy

You can set a proxy to the session with the `session.SetProxy` method.
Supported proxy formats include:
- `http(s)://ip:port`
- `http(s)://username:password@ip:port`
- `ip:port`
- `ip:port:username:password`
- `username:password:ip:port`
- `username:password@ip:port`
  
*If a scheme is not provided, `http` will be used by default.*

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

*SSL pinning ensures that you are connecting to the intended server and mitigates the risk of man-in-the-middle attacks, such as those potentially executed using tools like Charles Proxy.*

```go
session := azuretls.NewSession()

// secured request
response, err := session.Get("https://tls.peet.ws/api/all")

if err != nil {
    panic(err)
}

fmt.Println(response.StatusCode, string(response.Body))
```

If you're concerned about the reliability of a machine, you can improve security by manually setting pins prior to initiating any requests within the session, using the `session.AddPins` method. 
The pins are generated through the following series of steps:

1. SubjectPublicKeyInfo is first DER-encoded.
2. The DER-encoded data is then hashed using the SHA-256 algorithm.
3. Finally, the hashed output is base64 encoded to generate the pin.

*It's not necessary for every certificate in the chain to match a pin. If even a single certificate in the chain matches one of the pre-defined pins, the entire chain is considered valid : this approach allows for flexibility in the certificate chain while still providing an additional layer of security.* 

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

You can also call `session.ClearPins` beforehand to remove any saved pins in the session for the given URL

To disable SSL Pinning, you can do `session.InsecureSkipVerify = true`

```go
session := azuretls.NewSession()

session.InsecureSkipVerify = true

// do it at your own risk !
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

session.SetTimeout(5 * time.Second)

response, err := session.Get("https://tls.peet.ws/api/all")

if err != nil {
    panic(err)
}

fmt.Println(response.StatusCode, string(response.Body))
```
#
### PreHook and CallBack

You can modify all outgoing requests in the session using the `session.PreHook` method before they are executed.
You can also set a callback for the session using the `session.CallBack` method.

```go
session := azuretls.NewSession()

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
