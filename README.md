# AzureTLS Client 
[![GoDoc](https://godoc.org/github.com/Noooste/azuretls-client?status.svg)](https://godoc.org/github.com/Noooste/azuretls-client)
[![codecov](https://codecov.io/gh/Noooste/azuretls-client/graph/badge.svg?token=XGHX707RK6)](https://codecov.io/gh/Noooste/azuretls-client)
[![build](https://github.com/Noooste/azuretls-client/actions/workflows/push.yml/badge.svg)](https://github.com/Noooste/azuretls-client/actions/workflows/push.yml)
[![Go Report Card](https://goreportcard.com/badge/Noooste/azuretls-client)](https://goreportcard.com/report/Noooste/azuretls-client)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/Noooste/azuretls-client/blob/master/LICENSE)

## 🚀 Simple, Powerful HTTP Client for Go

AzureTLS Client is a high-performance HTTP client library for Go that combines **simplicity** with **unlimited customization**. Whether you're building a simple API client or need advanced features like TLS fingerprinting and HTTP/2 customization, AzureTLS Client has you covered.

### ✨ Why Choose AzureTLS Client?

**🎯 Simple by Default**
```go
session := azuretls.NewSession()
response, err := session.Get("https://www.google.com/")
if err != nil {
    panic(err)
}
fmt.Println(response.String())
```

**⚡ Powerful When Needed**
- Full TLS fingerprint control (JA3/JA4)
- HTTP/2 and HTTP/3 support with custom settings
- Advanced proxy support (HTTP/HTTPS/SOCKS5)
- Precise header ordering and control

## 🌟 Key Features

- **🌐 Modern Protocols** - HTTP/1.1, HTTP/2, and HTTP/3 support
- **🔧 TLS Fingerprinting** - Full control over ClientHello (JA3/JA4)
- **🎭 Browser Emulation** - Chrome, Firefox, Safari, Edge presets
- **🔗 Advanced Proxy Support** - HTTP, HTTPS, SOCKS5 with authentication
- **📋 Header Control** - Precise ordering and custom headers
- **🍪 Cookie Management** - Automatic handling with persistent jar
- **🔒 SSL Pinning** - Enhanced security with certificate validation
- **🐛 Debug Tools** - Request logging and dumping capabilities

## 🎯 Perfect For

- **API Integration** - Simple REST API clients
- **Web Scraping** - Advanced bot detection evasion
- **Security Testing** - Custom TLS fingerprinting
- **Load Testing** - High-performance concurrent requests
- **Proxy Management** - Multi-proxy rotation and testing

## 📋 Quick Examples

### Simple GET Request
```go
session := azuretls.NewSession()
defer session.Close()

response, err := session.Get("https://api.github.com/user")
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Status: %d\n", response.StatusCode)
```

### POST with JSON
```go
data := map[string]string{
    "name": "AzureTLS",
    "type": "HTTP Client",
}

response, err := session.Post("https://api.example.com/data", data)
```

### Browser Emulation
```go
session := azuretls.NewSession()
session.Browser = azuretls.Firefox // Automatic JA3 + HTTP/2 fingerprinting

response, err := session.Get("https://website.com")
```

### Custom Headers with Ordering
```go
session.OrderedHeaders = azuretls.OrderedHeaders{
    {"User-Agent", "MyApp/1.0"},
    {"Accept", "application/json"},
    {"Authorization", "Bearer token"},
}
```

### Proxy Support
```go
session := azuretls.NewSession()
err := session.SetProxy("http://username:password@proxy.example.com:8080")
if err != nil {
    log.Fatal(err)
}

response, err := session.Get("https://api.example.com")
```

## 🤝 Community & Support

- **Issues**: [GitHub Issues](https://github.com/Noooste/azuretls-client/issues)
- **Discussions**: [GitHub Discussions](https://github.com/Noooste/azuretls-client/discussions)
- **Examples**: [examples/](./examples/)
- **Shared Libraries**: [cffi/](./cffi/)

## 🙏 Acknowledgments

AzureTLS Client is built with ❤️ by the open source community. Special thanks to all [contributors](https://github.com/Noooste/azuretls-client/graphs/contributors) who help make this project better.

## ⭐ Show Your Support

If AzureTLS Client helps you build something awesome, consider:
- ⭐ **Star this repository**
- 🐛 **Report bugs** or suggest features
- 💡 **Share your use cases** in discussions
- 🤝 **Contribute** code or documentation

*Ready to build powerful HTTP clients with ease? Let's get started! 🚀*
