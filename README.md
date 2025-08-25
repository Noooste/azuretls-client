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
- Proxy chain support for multi-hop connections
- Precise header ordering and control

## 🌟 Key Features

- **🌐 Modern Protocols** - HTTP/1.1, HTTP/2, and HTTP/3 support
- **🔧 TLS Fingerprinting** - Full control over ClientHello (JA3/JA4)
- **🎭 Browser Emulation** - Chrome, Firefox, Safari, Edge presets
- **🔗 Advanced Proxy Support** - HTTP, HTTPS, SOCKS4, SOCKS5 with authentication.
- **⛓️ Proxy Chaining** - Multi-hop proxy connections for enhanced anonymity
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

## 🌍 Multi-Language Support via CFFI

AzureTLS Client can be used from **any programming language** that supports C Foreign Function Interface (FFI) through our comprehensive CFFI bindings.

### 🔗 Available CFFI Implementation

The core CFFI (C Foreign Function Interface) library is available in the [`cffi/`](./cffi/) directory, providing a C API that can be used from any language supporting C FFI.

**📦 Pre-built libraries available for:**
- **Linux** (amd64, arm64, 386, arm)
- **Windows** (amd64, 386, arm64)
- **macOS** (amd64, arm64)

### 🌐 Community Language Bindings

*Community-maintained repositories for additional languages:*

<!-- Add your language binding repository here via PR -->
- 🔗 **[Your Language]** - [Your Repository](https://github.com/yourusername/azuretls-yourlang) by [@yourusername](https://github.com/yourusername)

*Want to see your language binding featured here? See the [Contributing Language Bindings](#-contributing-language-bindings) section below!*

### 📦 Getting Started with CFFI

1. **Download** pre-built libraries from our [releases](https://github.com/Noooste/azuretls-client/releases)
2. **Choose** your platform: Linux, Windows, macOS, FreeBSD
3. **Pick** your architecture: amd64, arm64, 386, arm
4. **Follow** language-specific examples in [`cffi/examples/`](./cffi/examples/)

### 🛠️ Building CFFI Libraries

```bash
# Build for current platform
cd cffi && make

# Build for all platforms
cd cffi && make build-all

# Build for specific platform
cd cffi && make build-linux-amd64
```

### 📚 Comprehensive Documentation

Full CFFI documentation with API reference, examples, and troubleshooting guides is available at [`cffi/README.md`](./cffi/README.md).

### 🤝 Contributing Language Bindings

**We welcome and appreciate contributions for additional language support!**

If you create bindings for a new programming language, we'd love to:
- 📝 **Feature your repository** in this README
- 🏆 **Credit you as a contributor**
- 🔗 **Link to your implementation** for the community
- 🚀 **Help promote** your language bindings

**Language bindings we'd especially appreciate:**
- 🐍 **Python** - ctypes/cffi implementation
- 🟨 **Node.js** - ffi-napi integration
- 📘 **TypeScript** - Type-safe Node.js bindings
- ☕ **Java** - JNI bindings
- 🔷 **C#** - P/Invoke implementation
- 🦀 **Rust** - libc/bindgen bindings
- And any others!

**How to contribute language bindings:**

1. 🏗️ **Create your own repository** with language bindings using our CFFI
2. 🔧 **Implement the core functionality** using our C API from [`cffi/`](./cffi/)
3. 📖 **Add comprehensive examples and documentation**
4. 🧪 **Include tests** demonstrating the functionality
5. 📬 **Submit a pull request** to this repository to **add your repo link** to this README

**Repository Requirements:**
- Use the AzureTLS CFFI libraries from our releases
- Include clear installation instructions
- Provide working examples
- Add proper documentation
- Follow your language's best practices

## 🤝 Community & Support

- **Issues**: [GitHub Issues](https://github.com/Noooste/azuretls-client/issues)
- **Discussions**: [GitHub Discussions](https://github.com/Noooste/azuretls-client/discussions)
- **Examples**: [examples/](./examples/)
- **CFFI Documentation**: [cffi/README.md](./cffi/README.md)

## 🙏 Acknowledgments

AzureTLS Client is built with ❤️ by the open source community. Special thanks to all [contributors](https://github.com/Noooste/azuretls-client/graphs/contributors) who help make this project better.

## ⭐ Show Your Support

If AzureTLS Client helps you build something awesome, consider:
- ⭐ **Star this repository**
- 🐛 **Report bugs** or suggest features
- 💡 **Share your use cases** in discussions
- 🤝 **Contribute** code or documentation
- 🌍 **Create bindings** for your favorite programming language

[!["Buy Me A Coffee"](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://www.buymeacoffee.com/noste)

*Ready to build powerful HTTP clients with ease? Let's get started! 🚀*
