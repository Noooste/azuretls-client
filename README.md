# AzureTLS Client
[![GoDoc](https://godoc.org/github.com/Noooste/azuretls-client?status.svg)](https://godoc.org/github.com/Noooste/azuretls-client)
[![codecov](https://codecov.io/gh/Noooste/azuretls-client/graph/badge.svg?token=XGHX707RK6)](https://codecov.io/gh/Noooste/azuretls-client)
[![build](https://github.com/Noooste/azuretls-client/actions/workflows/push.yml/badge.svg)](https://github.com/Noooste/azuretls-client/actions/workflows/push.yml)
[![Go Report Card](https://goreportcard.com/badge/Noooste/azuretls-client)](https://goreportcard.com/report/Noooste/azuretls-client)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/Noooste/azuretls-client/blob/master/LICENSE)

A powerful HTTP client for Go that's **simple to use** but gives you **full control** when you need it.

Perfect for API clients, web scraping, testing, and any situation where you need more than the standard library offers, without the complexity.

## Installation

```bash
go get github.com/Noooste/azuretls-client
```

## Quick Start - 30 Seconds

```go
package main

import (
    "fmt"
    "log"
    "github.com/Noooste/azuretls-client"
)

func main() {
    session := azuretls.NewSession()
    defer session.Close()

    response, err := session.Get("https://api.github.com")
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Status: %d\n", response.StatusCode)
    fmt.Println(response.String())
}
```

**That's it!** Just create a session and make requests. This automatically uses Chrome's TLS (JA3) and HTTP/2 fingerprint, making it look like a real browser to servers.

> 💡 **New to Go?** AzureTLS uses a session-based API (similar to creating an `http.Client`). Each session automatically mimics Chrome by default, no fingerprint configuration needed. Advanced customization is completely optional.

## Common Tasks

### POST Request with JSON

```go
session := azuretls.NewSession()
defer session.Close()

data := map[string]string{
    "name": "AzureTLS",
    "type": "HTTP Client",
}

response, err := session.Post("https://api.example.com/data", data)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Status: %d\n", response.StatusCode)
```

### Using a Proxy

```go
session := azuretls.NewSession()
defer session.Close()

// One line proxy setup: supports HTTP, HTTPS, SOCKS4, SOCKS5
err := session.SetProxy("http://username:password@proxy.example.com:8080")
if err != nil {
    log.Fatal(err)
}

response, err := session.Get("https://api.ipify.org")
```

### Browser Emulation

```go
session := azuretls.NewSession()
defer session.Close()

// Default: Chrome fingerprint (already active, no configuration needed!)

// Want to mimic a different browser? Just change it:
session.Browser = azuretls.Firefox  // or Safari, Edge, etc.

response, err := session.Get("https://example.com")
```

### Custom Header Ordering

```go
session := azuretls.NewSession()
defer session.Close()

// Precise control over header order
session.OrderedHeaders = azuretls.OrderedHeaders{
    {"User-Agent", "MyApp/1.0"},
    {"Accept", "application/json"},
    {"Authorization", "Bearer token123"},
}

response, err := session.Get("https://api.example.com")
```

## Why AzureTLS vs Standard Library?

| Feature | net/http | AzureTLS                     |
|---------|----------|------------------------------|
| API Style | Package or Client-based | Session-based                |
| Browser Fingerprint | ❌ Looks like Go | ✅ **Chrome by default**      |
| Cookie Management | Manual setup | ✅ Automatic jar              |
| Ordered Headers | ❌ | ✅ Built-in                   |
| Proxy Support | Manual dialer setup | ✅ `session.SetProxy()`       |
| Multiple Proxy Types | Manual | ✅ HTTP/SOCKS4/SOCKS5         |
| Custom TLS (JA3/JA4) | ❌ | ✅ Easy                       |
| HTTP/2 Customization | ❌ | ✅ Easy                   |
| HTTP/3 Support | ❌ | ✅ Easy                   |
| Browser Presets | ❌ | ✅ Chrome/Firefox/Safari/Edge |


## 🌟 Key Features

- **🌐 Modern Protocols**: HTTP/1.1, HTTP/2, and HTTP/3 support
- **🔧 TLS Fingerprinting**: Full control over ClientHello (JA3/JA4)
- **🎭 Browser Emulation**: Chrome, Firefox, Safari, Edge presets
- **🔗 Advanced Proxy Support**: HTTP, HTTPS, SOCKS4, SOCKS5 with authentication.
- **⛓️ Proxy Chaining**: Multi-hop proxy connections for enhanced anonymity
- **📋 Header Control**: Precise ordering and custom headers
- **🍪 Cookie Management**: Automatic handling with persistent jar
- **🔒 SSL Pinning**: Enhanced security with certificate validation
- **🐛 Debug Tools**: Request logging and dumping capabilities

## Documentation

- 📖 **[Complete API Reference](./examples/README.md)**: Every feature, method, and option
- 💬 **[Examples Directory](./examples/)**: Working code samples
- 🌍 **[CFFI Documentation](./cffi/README.md)**: Use AzureTLS from other languages

### Learn More

- **Making Requests**: GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS ([examples/README.md](./examples/README.md#make-requests))
- **TLS Fingerprinting**: JA3/JA4 customization ([examples/README.md](./examples/README.md#modify-tls-client-hello-ja3))
- **HTTP/2 & HTTP/3**: Protocol customization ([examples/README.md](./examples/README.md#modify-http2))
- **Proxy Management**: Advanced proxy features ([examples/README.md](./examples/README.md#proxy))
- **Websockets**: WebSocket support ([examples/README.md](./examples/README.md#websocket))
- **SSL Pinning**: Certificate validation ([examples/README.md](./examples/README.md#ssl-pinning))

## Use Cases

**Perfect for:**
- 🔌 **API Integration**: REST clients that look like real browsers by default
- 🌐 **Web Scraping**: Automatic browser fingerprinting without configuration
- 🛡️ **Testing antibot systems**: Avoid bot detection with authentic browser signatures
- 🔄 **Proxy Rotation**: Built-in support for multiple proxy types
- 🧪 **Security Testing**: Custom TLS configurations for advanced testing
- 📊 **Load Testing**: High-performance concurrent requests

## Multi-Language Support via CFFI

AzureTLS can be used from **any programming language** that supports C Foreign Function Interface.
Read the [CFFI documentation](./cffi/README.md) for full details.

## Community & Support

- 💬 **[GitHub Discussions](https://github.com/Noooste/azuretls-client/discussions)**: Ask questions, share ideas
- 🐛 **[GitHub Issues](https://github.com/Noooste/azuretls-client/issues)**: Report bugs, request features
- 📖 **[Examples](./examples/)**: Code samples and tutorials

## Show Your Support

If AzureTLS helps you build something awesome:

- ⭐ **Star this repository**
- 🐛 **Report bugs** or suggest features
- 💡 **Share your use cases** in discussions
- 🤝 **Contribute** code or documentation
- 🌍 **Create bindings** for your favorite programming language

[!["Buy Me A Coffee"](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://www.buymeacoffee.com/noste)

## Acknowledgments

Built with ❤️ by the open source community. Special thanks to all [contributors](https://github.com/Noooste/azuretls-client/graphs/contributors).

---

## 🛡️ Need Antibot Bypass?

<a href="https://hypersolutions.co/?utm_source=github&utm_medium=readme&utm_campaign=azure-tls" target="_blank"><img src="./.github/assets/hypersolutions.jpg" height="47" width="149"></a>

TLS fingerprinting alone isn't enough for modern bot protection. **[Hyper Solutions](https://hypersolutions.co?utm_source=github&utm_medium=readme&utm_campaign=azure-tls)** provides the missing piece - API endpoints that generate valid antibot tokens for:

**Akamai** • **DataDome** • **Kasada** • **Incapsula**

No browser automation. Just simple API calls that return the exact cookies and headers these systems require.

🚀 **[Get Your API Key](https://hypersolutions.co?utm_source=github&utm_medium=readme&utm_campaign=azure-tls)** | 📖 **[Docs](https://docs.hypersolutions.co/)** | 💬 **[Discord](https://discord.gg/akamai)**
