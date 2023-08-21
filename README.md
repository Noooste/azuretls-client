# AzureTLS Client
![Coverage](https://img.shields.io/badge/Coverage-75.8%25-brightgreen)

The project aims to provide a simple way to modify and spoof TLS and HTTP2 information in Go.

## Usage

### Import
```go
import (
    "github.com/Noooste/azuretls-client"
)
```

### Create a Session
```go
session := azuretls.NewSession()
```

### Modify TLS

To modify TLS, you have 2 ways :
- The first one is to use the `session.ApplyJA3` method, which takes a (`string`, `string`) as parameter. The first one is the ja3 fingerprint and the second one is the target navigator (chrome, firefox, safari, ...).
- The second one is to assign a method to `session.GetClientHelloSpec` that returns TLS configuration.
```go
session := azuretls.NewSession()

// First way
ja3 := "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,45-13-43-0-16-65281-51-18-11-27-35-23-10-5-17513-21,29-23-24-25-26,0"
if err := session.ApplyJa3(ja3, azuretls.Chrome); err != nil {
    panic(err)
}

// Second way
session.GetClientHelloSpec = azuretls.GetLastChromeVersion

resp, err := session.Get("https://tls.peet.ws/api/all")

if err != nil {
    panic(err)
}

fmt.Println(resp.StatusCode)
fmt.Println(string(resp.Body))
```

### Modify HTTP2

To modify HTTP2, you have to apply the HTTP2 fingerprint to the session.
```go
session := azuretls.NewSession()

http2 := "1:65536,2:0,3:1000,4:6291456,6:262144|15663105|0|m,s,a,p"

if err := session.ApplyHTTP2(http2); err != nil {
    panic(err)
}

resp, err := session.Get("https://tls.peet.ws/api/all")

if err != nil {
    panic(err)
}

fmt.Println(resp.StatusCode)
fmt.Println(string(resp.Body))
```

### Headers

Use `session.OrderedHeaders` method, which is `[][]string`..

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

fmt.Println(response.StatusCode)
fmt.Println(string(response.Body))

session.Close()
```

### Proxy

You can set a proxy to the session with the `session.SetProxy` method. It takes a `string` as parameter, which is the proxy address.
Proxy format supported :
- `http://ip:port`
- `http://username:password@ip:port`
- `ip:port`
- `ip:port:username:password`
- `username:password:ip:port`
- `username:password@ip:port`

```go
session := azuretls.NewSession()

session.SetProxy("http://username:password@ip:port")

response, err := session.Get("https://api.ipify.org")

if err != nil {
    panic(err)
}

fmt.Println(response.StatusCode)
fmt.Println(string(response.Body))

session.Close()
```

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

session.Close()
```

You can set manual SSL Pinning to the session with method `session.AddPins`.

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


To diable SSL Pinning, you can do `session.InsecureSkipVerify = true`

```go
session := azuretls.NewSession()

session.InsecureSkipVerify = true

// do it at your own risk !
_, err := session.Get("https://httpbin.org/get")

if err != nil {
    panic(err)
}
```

### Timeout

You can set a timeout to the session with the `session.SetTimeout` method. It takes a `time.Duration` as parameter, which is the timeout duration.

```go
session := azuretls.NewSession()

session.SetTimeout(10 * time.Second)

response, err := session.Get("https://tls.peet.ws/api/all")

if err != nil {
    panic(err)
}

fmt.Println(response.StatusCode)
fmt.Println(string(response.Body))

session.Close()
```

### PreHook and CallBack

You can set pre hooks to the session with the `session.PreHook` method. It takes a `func(*http.Request) error` as parameter, which is the pre hook function.

```go
session := azuretls.NewSession()

session.PreHook = func(req *http.Request) error {
    req.Header.Set("user-agent", "test")
    return nil
}

response, err := session.Get("https://tls.peet.ws/api/all")

if err != nil {
    panic(err)
}
```

You can set call backs to the session with the `session.CallBack` method. It takes a `func(*http.Response) error` as parameter, which is the call back function.

```go
session := azuretls.NewSession()

session.CallBack = func(request *Request, response *Response, err error) {
    fmt.Println(response.StatusCode)
    return nil
}

response, err := session.Get("https://tls.peet.ws/api/all")

if err != nil {
    panic(err)
}
```

### Cookies

You can set cookies to the session with the `session.SetCookies` method. It takes a `[]*http.Cookie` as parameter, which is the cookies.

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
