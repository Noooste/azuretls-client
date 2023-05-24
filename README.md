# AzureTLS Client

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

You can set headers to the session in 2 different ways :
- The first one would be to add the headers to the session with the `session.Headers`. However, you will need to apply the order of the headers with the `session.HeadersOrder`.

```go
session := azuretls.NewSession()

session.Headers = http.Header{
    "user-agent": {"test"},
    "content-type": {"application/json"},
    "accept": {"application/json"},
}

session.HeadersOrder = azuretls.HeaderOrder{
    "user-agent",
    "content-type",
    "accept",
}

response, err := session.Get("https://tls.peet.ws/api/all")

if err != nil {
    panic(err)
}

fmt.Println(response.StatusCode)
fmt.Println(string(response.Body))

session.Close()
```

- The second one, which is the easiest one, is to use the `session.OrderedHeaders` method, which is `[][]string`. No need to apply the order of the headers, it's already done.

```go
// Second way
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

You can set SSL Pinning to the session with the `session.VerifyPins = true`.

```go
session := azuretls.NewSession()

session.VerifyPins = true

response, err := session.Get("https://tls.peet.ws/api/all")

if err != nil {
    panic(err)
}

fmt.Println(response.StatusCode)
fmt.Println(string(response.Body))

session.Close()
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
