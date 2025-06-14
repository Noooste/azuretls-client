# AzureTLS CFFI - C Foreign Function Interface

This directory contains the C Foreign Function Interface (CFFI) for the AzureTLS client library, enabling use from any C-compatible language including Python, Node.js, Rust, C#, Java, and more.

## 🌟 Key Features

- **Universal Compatibility**: Use AzureTLS from any language with C FFI support
- **Memory Safe**: Proper memory management with explicit cleanup functions
- **Cross-Platform**: Supports Windows, Linux, macOS, and FreeBSD
- **Multi-Architecture**: AMD64, ARM64, x86, ARM support
- **Simple API**: Clean, minimal interface focusing on the `Do` method
- **JSON Configuration**: Easy configuration using JSON strings

## 📋 Table of Contents

- [Quick Start](#-quick-start)
- [Building](#-building)
- [API Reference](#-api-reference)
- [Language Examples](#-language-examples)
- [Memory Management](#-memory-management)
- [Error Handling](#-error-handling)
- [Configuration](#-configuration)
- [Advanced Usage](#-advanced-usage)
- [Troubleshooting](#-troubleshooting)

## 🚀 Quick Start

### 1. Build the Library

```bash
# Build for current platform
make

# Build for all platforms
make build-all

# Build for specific platform
make build-linux-amd64
make build-windows-amd64
make build-darwin-arm64
```

### 2. Basic Usage (C Example)

```c
#include "azuretls.h"
#include <stdio.h>
#include <stdlib.h>

int main() {
    // Initialize library
    azuretls_init();
    
    // Create session
    const char* config = "{\"browser\": \"chrome\", \"timeout_ms\": 30000}";
    uintptr_t session = azuretls_session_new((char*)config);
    
    // Make a request
    const char* request = "{\"method\": \"GET\", \"url\": \"https://httpbin.org/get\"}";
    CFfiResponse* response = azuretls_session_do(session, (char*)request);
    
    if (response->error) {
        printf("Error: %s\n", response->error);
    } else {
        printf("Status: %d\n", response->status_code);
        printf("Body: %s\n", response->body);
    }
    
    // Cleanup
    azuretls_free_response(response);
    azuretls_session_close(session);
    azuretls_cleanup();
    
    return 0;
}
```

### 3. Python Example

```python
from cffi_python import AzureTLSSession

# Create session with configuration
with AzureTLSSession({"browser": "chrome"}) as session:
   # Simple GET request
   response = session.get("https://httpbin.org/get")
   print(f"Status: {response.status_code}")
   print(f"Body: {response.body}")

   # POST with JSON
   response = session.post(
      "https://httpbin.org/post",
      body='{"message": "Hello World"}',
      headers={"Content-Type": "application/json"}
   )
```

## 🔨 Building

### Prerequisites

- Go 1.24+ with CGO enabled
- C compiler (GCC, Clang, or MSVC)
- Make (GNU Make or compatible)

### Build Commands

| Command | Description |
|---------|-------------|
| `make` | Build for current platform |
| `make build-all` | Build for all supported platforms |
| `make build-linux` | Build all Linux architectures |
| `make build-windows` | Build all Windows architectures |
| `make build-darwin` | Build all macOS architectures |
| `make clean` | Remove build artifacts |
| `make install` | Install system-wide (Unix-like) |
| `make test` | Run tests |

### Platform Support

| OS | Architecture | Library Extension | Status |
|----|--------------|-------------------|--------|
| Linux | amd64, arm64, 386, arm | `.so` | ✅ Supported |
| Windows | amd64, 386, arm64 | `.dll` | ✅ Supported |
| macOS | amd64, arm64 | `.dylib` | ✅ Supported |

## 📚 API Reference

### Session Management

#### `azuretls_session_new(config_json)`
Creates a new AzureTLS session.

**Parameters:**
- `config_json` (char*): JSON configuration string (optional, can be NULL)

**Returns:** `uintptr_t` - Session ID (0 on failure)

**Example:**
```c
const char* config = "{"
    "\"browser\": \"chrome\","
    "\"user_agent\": \"MyApp/1.0\","
    "\"timeout_ms\": 30000,"
    "\"max_redirects\": 10"
"}";
uintptr_t session = azuretls_session_new((char*)config);
```

#### `azuretls_session_close(session_id)`
Closes and cleans up a session.

**Parameters:**
- `session_id` (uintptr_t): Session ID from `azuretls_session_new`

### HTTP Requests

#### `azuretls_session_do(session_id, request_json)`
Executes an HTTP request.

**Parameters:**
- `session_id` (uintptr_t): Session ID
- `request_json` (char*): JSON request configuration

**Returns:** `CFfiResponse*` - Response structure (must be freed)

**Request JSON Format:**
```json
{
   "method": "GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH",
   "url": "https://example.com",
   "body": "request body (optional)",
   "headers": {"Header-Name": "Header-Value"},
   "ordered_headers": [["Header1", "Value1"], ["Header2", "Value2"]],
   "timeout_ms": 30000,
   "force_http1": false,
   "force_http3": false,
   "ignore_body": false,
   "no_cookie": false,
   "disable_redirects": false,
   "max_redirects": 10,
   "insecure_skip_verify": false
}
```

### TLS/HTTP Fingerprinting

#### `azuretls_session_apply_ja3(session_id, ja3, navigator)`
Applies JA3 TLS fingerprint.

**Parameters:**
- `session_id` (uintptr_t): Session ID
- `ja3` (char*): JA3 fingerprint string
- `navigator` (char*): Browser type ("chrome", "firefox", "safari", etc.)

**Returns:** `char*` - Error message (NULL on success, must be freed)

#### `azuretls_session_apply_http2(session_id, fingerprint)`
Applies HTTP/2 fingerprint.

**Parameters:**
- `session_id` (uintptr_t): Session ID
- `fingerprint` (char*): HTTP/2 fingerprint string

**Returns:** `char*` - Error message (NULL on success, must be freed)

#### `azuretls_session_apply_http3(session_id, fingerprint)`
Applies HTTP/3 fingerprint.

**Parameters:**
- `session_id` (uintptr_t): Session ID
- `fingerprint` (char*): HTTP/3 fingerprint string

**Returns:** `char*` - Error message (NULL on success, must be freed)

### Proxy Management

#### `azuretls_session_set_proxy(session_id, proxy)`
Sets proxy for the session.

**Parameters:**
- `session_id` (uintptr_t): Session ID
- `proxy` (char*): Proxy URL (e.g., "http://user:pass@proxy:8080")

**Returns:** `char*` - Error message (NULL on success, must be freed)

#### `azuretls_session_clear_proxy(session_id)`
Clears proxy from the session.

**Parameters:**
- `session_id` (uintptr_t): Session ID

### SSL Pinning

#### `azuretls_session_add_pins(session_id, url, pins_json)`
Adds SSL certificate pins for a URL.

**Parameters:**
- `session_id` (uintptr_t): Session ID
- `url` (char*): URL to pin
- `pins_json` (char*): JSON array of pin strings

**Returns:** `char*` - Error message (NULL on success, must be freed)

#### `azuretls_session_clear_pins(session_id, url)`
Clears SSL pins for a URL.

**Parameters:**
- `session_id` (uintptr_t): Session ID
- `url` (char*): URL to clear pins for

**Returns:** `char*` - Error message (NULL on success, must be freed)

### Utility Functions

#### `azuretls_session_get_ip(session_id)`
Gets the public IP address.

**Parameters:**
- `session_id` (uintptr_t): Session ID

**Returns:** `char*` - IP address string (must be freed)

#### `azuretls_version()`
Gets library version.

**Returns:** `char*` - Version string (must be freed)

### Memory Management

#### `azuretls_free_string(str)`
Frees a string returned by the library.

**Parameters:**
- `str` (char*): String to free

#### `azuretls_free_response(resp)`
Frees a response structure.

**Parameters:**
- `resp` (CFfiResponse*): Response to free

### Library Lifecycle

#### `azuretls_init()`
Initializes the library (call once at startup).

#### `azuretls_cleanup()`
Cleans up library resources (call once at shutdown).

## 🌍 Language Examples

### Python (using ctypes)

```python
import ctypes
import json
import platform

# Load library
system = platform.system().lower()
arch = 'amd64' if platform.machine() == 'x86_64' else platform.machine()
lib_name = f"libazuretls_{system}_{arch}"
lib = ctypes.CDLL(f"./{lib_name}.{'dll' if system == 'windows' else 'dylib' if system == 'darwin' else 'so'}")

# Setup function signatures
lib.azuretls_session_new.argtypes = [ctypes.c_char_p]
lib.azuretls_session_new.restype = ctypes.c_ulong

# Create session and make request
session = lib.azuretls_session_new(b'{"browser": "chrome"}')
```

### Node.js (using ffi-napi)

```javascript
const ffi = require('ffi-napi');
const ref = require('ref-napi');

// Define response structure
const CFfiResponse = ref.types.CString;

// Load library
const azuretls = ffi.Library('./libazuretls', {
  'azuretls_session_new': ['pointer', ['string']],
  'azuretls_session_do': ['pointer', ['pointer', 'string']],
  'azuretls_session_close': ['void', ['pointer']],
  'azuretls_free_response': ['void', ['pointer']]
});

// Create session
const config = JSON.stringify({browser: 'chrome'});
const session = azuretls.azuretls_session_new(config);

// Make request
const request = JSON.stringify({method: 'GET', url: 'https://httpbin.org/get'});
const response = azuretls.azuretls_session_do(session, request);
```

### Rust (using libc)

```rust
use std::ffi::{CString, CStr};
use std::os::raw::c_char;

#[link(name = "azuretls")]
extern "C" {
    fn azuretls_session_new(config: *const c_char) -> usize;
    fn azuretls_session_close(session_id: usize);
    fn azuretls_session_do(session_id: usize, request: *const c_char) -> *mut CFfiResponse;
    fn azuretls_free_response(response: *mut CFfiResponse);
}

#[repr(C)]
struct CFfiResponse {
    status_code: i32,
    body: *mut c_char,
    body_len: i32,
    headers: *mut c_char,
    url: *mut c_char,
    error: *mut c_char,
}

fn main() {
    let config = CString::new(r#"{"browser": "chrome"}"#).unwrap();
    let session = unsafe { azuretls_session_new(config.as_ptr()) };
    
    let request = CString::new(r#"{"method": "GET", "url": "https://httpbin.org/get"}"#).unwrap();
    let response = unsafe { azuretls_session_do(session, request.as_ptr()) };
    
    // Process response...
    
    unsafe {
        azuretls_free_response(response);
        azuretls_session_close(session);
    }
}
```

### C# (using P/Invoke)

```csharp
using System;
using System.Runtime.InteropServices;

[StructLayout(LayoutKind.Sequential)]
public struct CFfiResponse
{
    public int status_code;
    public IntPtr body;
    public int body_len;
    public IntPtr headers;
    public IntPtr url;
    public IntPtr error;
}

public static class AzureTLS
{
    const string DLL_NAME = "libazuretls";
    
    [DllImport(DLL_NAME)]
    public static extern UIntPtr azuretls_session_new(string config);
    
    [DllImport(DLL_NAME)]
    public static extern void azuretls_session_close(UIntPtr sessionId);
    
    [DllImport(DLL_NAME)]
    public static extern IntPtr azuretls_session_do(UIntPtr sessionId, string request);
    
    [DllImport(DLL_NAME)]
    public static extern void azuretls_free_response(IntPtr response);
}

// Usage
var session = AzureTLS.azuretls_session_new("{\"browser\": \"chrome\"}");
var response = AzureTLS.azuretls_session_do(session, "{\"method\": \"GET\", \"url\": \"https://httpbin.org/get\"}");
```

## 🧠 Memory Management

**Critical:** Always free returned pointers to prevent memory leaks.

### Cleanup Rules

1. **Responses**: Always call `azuretls_free_response()` for each response
2. **Strings**: Always call `azuretls_free_string()` for returned strings
3. **Sessions**: Always call `azuretls_session_close()` when done
4. **Library**: Call `azuretls_cleanup()` before program exit

### Example Memory-Safe Pattern

```c
// Good: Proper cleanup
CFfiResponse* response = azuretls_session_do(session, request);
if (response) {
    // Use response...
    azuretls_free_response(response);  // Always free
}

char* error = azuretls_session_apply_ja3(session, ja3, navigator);
if (error) {
    printf("Error: %s\n", error);
    azuretls_free_string(error);  // Always free error strings
}
```

## ⚠️ Error Handling

### Error Types

1. **Function Errors**: Return NULL/0 on failure
2. **String Errors**: Return error message string (must be freed)
3. **Response Errors**: Check `response->error` field

### Error Handling Pattern

```c
// Check session creation
uintptr_t session = azuretls_session_new(config);
if (session == 0) {
    printf("Failed to create session\n");
    return -1;
}

// Check response
CFfiResponse* response = azuretls_session_do(session, request);
if (!response) {
    printf("Request failed\n");
    return -1;
}

if (response->error) {
    printf("Request error: %s\n", response->error);
    azuretls_free_response(response);
    return -1;
}

// Success case
printf("Status: %d\n", response->status_code);
azuretls_free_response(response);
```

## ⚙️ Configuration

### Session Configuration

```json
{
    "browser": "chrome|firefox|safari|edge|ios",
    "user_agent": "Custom User Agent String",
    "proxy": "http://user:pass@proxy:8080",
    "timeout_ms": 30000,
    "max_redirects": 10,
    "insecure_skip_verify": false,
    "ordered_headers": [
        ["Header-Name", "Header-Value"],
        ["Another-Header", "Another-Value"]
    ],
    "headers": {
        "Global-Header": "Global-Value"
    }
}
```

### Request Configuration

```json
{
    "method": "GET",
    "url": "https://example.com",
    "body": "Request body content",
    "headers": {
        "Content-Type": "application/json",
        "Authorization": "Bearer token"
    },
    "ordered_headers": [
        ["User-Agent", "Custom-Agent/1.0"],
        ["Accept", "application/json"],
        ["Content-Type", "application/json"]
    ],
    "timeout_ms": 5000,
    "force_http1": false,
    "force_http3": false,
    "ignore_body": false,
    "no_cookie": false,
    "disable_redirects": false,
    "max_redirects": 5,
    "insecure_skip_verify": false
}
```

## 🚀 Advanced Usage

### TLS Fingerprinting

```c
// Apply Chrome JA3 fingerprint
const char* ja3 = "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0";
char* error = azuretls_session_apply_ja3(session, ja3, "chrome");
if (error) {
    printf("JA3 Error: %s\n", error);
    azuretls_free_string(error);
}

// Apply HTTP/2 fingerprint  
const char* http2_fp = "1:65536,2:0,3:1000,4:6291456,6:262144|15663105|0|m,s,a,p";
error = azuretls_session_apply_http2(session, http2_fp);
if (error) {
    printf("HTTP/2 Error: %s\n", error);
    azuretls_free_string(error);
}
```

### Proxy Usage

```c
// Set proxy
char* error = azuretls_session_set_proxy(session, "http://user:pass@proxy:8080");
if (error) {
    printf("Proxy Error: %s\n", error);
    azuretls_free_string(error);
}

// Make requests through proxy
CFfiResponse* response = azuretls_session_do(session, request_json);

// Clear proxy
azuretls_session_clear_proxy(session);
```

### SSL Pinning

```c
// Add pins
const char* pins = "[\"pin1base64\", \"pin2base64\"]";
char* error = azuretls_session_add_pins(session, "https://example.com", pins);
if (error) {
    printf("Pin Error: %s\n", error);
    azuretls_free_string(error);
}

// Requests will now validate pins
CFfiResponse* response = azuretls_session_do(session, request_json);

// Clear pins when done
error = azuretls_session_clear_pins(session, "https://example.com");
```

## 🔧 Troubleshooting

### Common Issues

#### Build Errors

**Problem**: `gcc failed: exit status 1`
**Solution**: Ensure CGO is enabled and C compiler is installed
```bash
export CGO_ENABLED=1
# Install build tools (varies by OS)
```

**Problem**: `multiple definition of 'free_response'`
**Solution**: Already fixed in the updated code

#### Runtime Errors

**Problem**: Library not found
**Solution**:
- Check library path
- Set `LD_LIBRARY_PATH` (Linux) or `PATH` (Windows)
- Use absolute path to library file

**Problem**: Session creation fails
**Solution**: Check JSON configuration syntax

**Problem**: Memory leaks
**Solution**: Always free returned pointers

### Debug Tips

1. **Enable Verbose Logging**: Check Go/CGO build output
2. **Validate JSON**: Use online JSON validators for config
3. **Check Return Values**: Always verify non-NULL returns
4. **Memory Tools**: Use Valgrind (Linux) or Address Sanitizer

### Platform-Specific Notes

#### Windows
- Requires MSYS2/MinGW or Visual Studio Build Tools
- DLL must be in PATH or same directory as executable

#### macOS
- May require Developer Tools: `xcode-select --install`
- Use `otool -L` to check library dependencies

#### Linux
- Install build-essential: `sudo apt install build-essential`
- Use `ldd` to check library dependencies

## 📞 Support

For issues and questions:

1. Check this README thoroughly
2. Review the [main project documentation](../README.md)
3. Check existing [GitHub issues](https://github.com/Noooste/azuretls-client/issues)
4. Create a new issue with:
   - Platform/architecture
   - Build command used
   - Complete error output
   - Minimal reproduction case

## 📄 License

This CFFI interface follows the same license as the main AzureTLS project (MIT License).