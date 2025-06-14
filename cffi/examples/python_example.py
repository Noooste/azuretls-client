#!/usr/bin/env python3
"""
AzureTLS Python Example using ctypes

This example demonstrates how to use the AzureTLS CFFI library from Python.
"""

import ctypes
import json
import os
import platform
from typing import Optional, Dict, Any, List


class AzureTLSResponse:
    """Wrapper for AzureTLS response"""

    def __init__(self, c_response):
        self.status_code = c_response.contents.status_code
        self.body = None
        self.headers = None
        self.url = None
        self.error = None

        if c_response.contents.body:
            self.body = ctypes.string_at(c_response.contents.body, c_response.contents.body_len).decode('utf-8')

        if c_response.contents.headers:
            headers_str = ctypes.string_at(c_response.contents.headers).decode('utf-8')
            self.headers = json.loads(headers_str) if headers_str else {}

        if c_response.contents.url:
            self.url = ctypes.string_at(c_response.contents.url).decode('utf-8')

        if c_response.contents.error:
            self.error = ctypes.string_at(c_response.contents.error).decode('utf-8')


class CFfiResponse(ctypes.Structure):
    """C structure for response"""
    _fields_ = [
        ("status_code", ctypes.c_int),
        ("body", ctypes.c_char_p),
        ("body_len", ctypes.c_int),
        ("headers", ctypes.c_char_p),
        ("url", ctypes.c_char_p),
        ("error", ctypes.c_char_p),
    ]


class AzureTLSSession:
    """Python wrapper for AzureTLS session"""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        # Load the shared library
        self.lib = self._load_library()

        # Define function signatures
        self._setup_function_signatures()

        # Initialize library
        self.lib.azuretls_init()

        # Create session
        config_json = json.dumps(config).encode('utf-8') if config else None
        self.session_id = self.lib.azuretls_session_new(config_json)

        if self.session_id == 0:
            raise RuntimeError("Failed to create AzureTLS session")

    def _load_library(self):
        """Load the appropriate shared library for the current platform"""
        system = platform.system().lower()
        machine = platform.machine().lower()

        # Map Python architecture names to Go architecture names
        arch_map = {
            'x86_64': 'amd64',
            'amd64': 'amd64',
            'i386': '386',
            'i686': '386',
            'arm64': 'arm64',
            'aarch64': 'arm64',
            'armv7l': 'arm',
        }

        arch = arch_map.get(machine, machine)

        # Determine library extension
        if system == 'windows':
            ext = '.dll'
        elif system == 'darwin':
            ext = '.dylib'
        else:
            ext = '.so'

        # Try to find the library
        lib_name = f"libazuretls_{system}_{arch}{ext}"

        # Search paths
        search_paths = [
            os.path.join(os.path.dirname(__file__), '..', 'build', lib_name),
            os.path.join(os.path.dirname(__file__), lib_name),
            lib_name,  # Try system paths
        ]

        lib = None
        for path in search_paths:
            try:
                if os.path.exists(path):
                    lib = ctypes.CDLL(path)
                    break
            except OSError:
                continue

        if lib is None:
            raise RuntimeError(f"Could not load AzureTLS library. Tried: {search_paths}")

        return lib

    def _setup_function_signatures(self):
        """Setup ctypes function signatures"""
        # azuretls_session_new
        self.lib.azuretls_session_new.argtypes = [ctypes.c_char_p]
        self.lib.azuretls_session_new.restype = ctypes.c_ulong

        # azuretls_session_close
        self.lib.azuretls_session_close.argtypes = [ctypes.c_ulong]
        self.lib.azuretls_session_close.restype = None

        # azuretls_session_do
        self.lib.azuretls_session_do.argtypes = [ctypes.c_ulong, ctypes.c_char_p]
        self.lib.azuretls_session_do.restype = ctypes.POINTER(CFfiResponse)

        # azuretls_session_apply_ja3
        self.lib.azuretls_session_apply_ja3.argtypes = [ctypes.c_ulong, ctypes.c_char_p, ctypes.c_char_p]
        self.lib.azuretls_session_apply_ja3.restype = ctypes.c_char_p

        # azuretls_session_apply_http2
        self.lib.azuretls_session_apply_http2.argtypes = [ctypes.c_ulong, ctypes.c_char_p]
        self.lib.azuretls_session_apply_http2.restype = ctypes.c_char_p

        # azuretls_session_apply_http3
        self.lib.azuretls_session_apply_http3.argtypes = [ctypes.c_ulong, ctypes.c_char_p]
        self.lib.azuretls_session_apply_http3.restype = ctypes.c_char_p

        # azuretls_session_set_proxy
        self.lib.azuretls_session_set_proxy.argtypes = [ctypes.c_ulong, ctypes.c_char_p]
        self.lib.azuretls_session_set_proxy.restype = ctypes.c_char_p

        # azuretls_session_clear_proxy
        self.lib.azuretls_session_clear_proxy.argtypes = [ctypes.c_ulong]
        self.lib.azuretls_session_clear_proxy.restype = None

        # azuretls_session_add_pins
        self.lib.azuretls_session_add_pins.argtypes = [ctypes.c_ulong, ctypes.c_char_p, ctypes.c_char_p]
        self.lib.azuretls_session_add_pins.restype = ctypes.c_char_p

        # azuretls_session_clear_pins
        self.lib.azuretls_session_clear_pins.argtypes = [ctypes.c_ulong, ctypes.c_char_p]
        self.lib.azuretls_session_clear_pins.restype = ctypes.c_char_p

        # azuretls_session_get_ip
        self.lib.azuretls_session_get_ip.argtypes = [ctypes.c_ulong]
        self.lib.azuretls_session_get_ip.restype = ctypes.c_char_p

        # azuretls_free_string
        self.lib.azuretls_free_string.argtypes = [ctypes.c_char_p]
        self.lib.azuretls_free_string.restype = None

        # azuretls_free_response
        self.lib.azuretls_free_response.argtypes = [ctypes.POINTER(CFfiResponse)]
        self.lib.azuretls_free_response.restype = None

        # azuretls_version
        self.lib.azuretls_version.argtypes = []
        self.lib.azuretls_version.restype = ctypes.c_char_p

        # azuretls_init
        self.lib.azuretls_init.argtypes = []
        self.lib.azuretls_init.restype = None

        # azuretls_cleanup
        self.lib.azuretls_cleanup.argtypes = []
        self.lib.azuretls_cleanup.restype = None

    def do(self,
           method: str,
           url: str,
           body: Optional[str] = None,
           headers: Optional[Dict[str, str]] = None,
           ordered_headers: Optional[List[List[str]]] = None,
           timeout_ms: Optional[int] = None,
           force_http1: bool = False,
           force_http3: bool = False,
           ignore_body: bool = False,
           no_cookie: bool = False,
           disable_redirects: bool = False,
           max_redirects: Optional[int] = None,
           insecure_skip_verify: bool = False) -> AzureTLSResponse:
        """Make an HTTP request"""

        request_data = {
            "method": method,
            "url": url,
        }

        if body is not None:
            request_data["body"] = body
        if headers is not None:
            request_data["headers"] = headers
        if ordered_headers is not None:
            request_data["ordered_headers"] = ordered_headers
        if timeout_ms is not None:
            request_data["timeout_ms"] = timeout_ms
        if force_http1:
            request_data["force_http1"] = True
        if force_http3:
            request_data["force_http3"] = True
        if ignore_body:
            request_data["ignore_body"] = True
        if no_cookie:
            request_data["no_cookie"] = True
        if disable_redirects:
            request_data["disable_redirects"] = True
        if max_redirects is not None:
            request_data["max_redirects"] = max_redirects
        if insecure_skip_verify:
            request_data["insecure_skip_verify"] = True

        request_json = json.dumps(request_data).encode('utf-8')
        c_response = self.lib.azuretls_session_do(self.session_id, request_json)

        if not c_response:
            raise RuntimeError("Failed to execute request")

        try:
            response = AzureTLSResponse(c_response)
            return response
        finally:
            self.lib.azuretls_free_response(c_response)

    def get(self, url: str, **kwargs) -> AzureTLSResponse:
        """Make a GET request"""
        return self.do("GET", url, **kwargs)

    def post(self, url: str, body: Optional[str] = None, **kwargs) -> AzureTLSResponse:
        """Make a POST request"""
        return self.do("POST", url, body=body, **kwargs)

    def put(self, url: str, body: Optional[str] = None, **kwargs) -> AzureTLSResponse:
        """Make a PUT request"""
        return self.do("PUT", url, body=body, **kwargs)

    def delete(self, url: str, **kwargs) -> AzureTLSResponse:
        """Make a DELETE request"""
        return self.do("DELETE", url, **kwargs)

    def head(self, url: str, **kwargs) -> AzureTLSResponse:
        """Make a HEAD request"""
        return self.do("HEAD", url, ignore_body=True, **kwargs)

    def options(self, url: str, **kwargs) -> AzureTLSResponse:
        """Make an OPTIONS request"""
        return self.do("OPTIONS", url, **kwargs)

    def patch(self, url: str, body: Optional[str] = None, **kwargs) -> AzureTLSResponse:
        """Make a PATCH request"""
        return self.do("PATCH", url, body=body, **kwargs)

    def apply_ja3(self, ja3: str, navigator: str = "chrome") -> None:
        """Apply JA3 fingerprint"""
        ja3_bytes = ja3.encode('utf-8')
        navigator_bytes = navigator.encode('utf-8')

        error = self.lib.azuretls_session_apply_ja3(self.session_id, ja3_bytes, navigator_bytes)
        if error:
            error_str = ctypes.string_at(error).decode('utf-8')
            self.lib.azuretls_free_string(error)
            raise RuntimeError(f"Failed to apply JA3: {error_str}")

    def apply_http2(self, fingerprint: str) -> None:
        """Apply HTTP/2 fingerprint"""
        fp_bytes = fingerprint.encode('utf-8')

        error = self.lib.azuretls_session_apply_http2(self.session_id, fp_bytes)
        if error:
            error_str = ctypes.string_at(error).decode('utf-8')
            self.lib.azuretls_free_string(error)
            raise RuntimeError(f"Failed to apply HTTP/2 fingerprint: {error_str}")

    def apply_http3(self, fingerprint: str) -> None:
        """Apply HTTP/3 fingerprint"""
        fp_bytes = fingerprint.encode('utf-8')

        error = self.lib.azuretls_session_apply_http3(self.session_id, fp_bytes)
        if error:
            error_str = ctypes.string_at(error).decode('utf-8')
            self.lib.azuretls_free_string(error)
            raise RuntimeError(f"Failed to apply HTTP/3 fingerprint: {error_str}")

    def set_proxy(self, proxy: str) -> None:
        """Set proxy for the session"""
        proxy_bytes = proxy.encode('utf-8')

        error = self.lib.azuretls_session_set_proxy(self.session_id, proxy_bytes)
        if error:
            error_str = ctypes.string_at(error).decode('utf-8')
            self.lib.azuretls_free_string(error)
            raise RuntimeError(f"Failed to set proxy: {error_str}")

    def clear_proxy(self) -> None:
        """Clear proxy from the session"""
        self.lib.azuretls_session_clear_proxy(self.session_id)

    def add_pins(self, url: str, pins: List[str]) -> None:
        """Add SSL pins for a URL"""
        url_bytes = url.encode('utf-8')
        pins_json = json.dumps(pins).encode('utf-8')

        error = self.lib.azuretls_session_add_pins(self.session_id, url_bytes, pins_json)
        if error:
            error_str = ctypes.string_at(error).decode('utf-8')
            self.lib.azuretls_free_string(error)
            raise RuntimeError(f"Failed to add pins: {error_str}")

    def clear_pins(self, url: str) -> None:
        """Clear SSL pins for a URL"""
        url_bytes = url.encode('utf-8')

        error = self.lib.azuretls_session_clear_pins(self.session_id, url_bytes)
        if error:
            error_str = ctypes.string_at(error).decode('utf-8')
            self.lib.azuretls_free_string(error)
            raise RuntimeError(f"Failed to clear pins: {error_str}")

    def get_ip(self) -> str:
        """Get the public IP address"""
        result = self.lib.azuretls_session_get_ip(self.session_id)
        if result:
            ip = ctypes.string_at(result).decode('utf-8')
            self.lib.azuretls_free_string(result)
            if ip.startswith("error:"):
                raise RuntimeError(ip)
            return ip
        raise RuntimeError("Failed to get IP address")

    def get_version(self) -> str:
        """Get library version"""
        result = self.lib.azuretls_version()
        if result:
            version = ctypes.string_at(result).decode('utf-8')
            self.lib.azuretls_free_string(result)
            return version
        return "unknown"

    def close(self):
        """Close the session and free resources"""
        if hasattr(self, 'session_id') and self.session_id != 0:
            self.lib.azuretls_session_close(self.session_id)
            self.session_id = 0

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def __del__(self):
        self.close()


def main():
    """Example usage"""
    print("AzureTLS Python Example")
    print("=" * 40)

    # Create session with configuration
    config = {
        "browser": "chrome",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "timeout_ms": 30000,
        "max_redirects": 10,
    }

    try:
        with AzureTLSSession(config) as session:
            # Example 1: Simple GET request
            print("\n1. Simple GET request:")
            response = session.get("https://httpbin.org/get")
            if response.error:
                print(f"Error: {response.error}")
            else:
                print(f"Status: {response.status_code}")
                print(f"URL: {response.url}")
                if response.body:
                    body_json = json.loads(response.body)
                    print(f"User-Agent: {body_json.get('headers', {}).get('User-Agent', 'N/A')}")

            # Example 2: POST request with JSON body
            print("\n2. POST request with JSON:")
            post_data = json.dumps({"message": "Hello from AzureTLS Python!"})
            response = session.post("https://httpbin.org/post", body=post_data, headers={
                "Content-Type": "application/json"
            })
            if response.error:
                print(f"Error: {response.error}")
            else:
                print(f"Status: {response.status_code}")
                if response.body:
                    body_json = json.loads(response.body)
                    print(f"Received data: {body_json.get('json', {})}")

            # Example 3: JA3 fingerprinting
            print("\n3. Applying JA3 fingerprint:")
            try:
                ja3 = "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0"
                session.apply_ja3(ja3, "chrome")
                print("JA3 fingerprint applied successfully")

                response = session.get("https://tls.peet.ws/api/all")
                if response.error:
                    print(f"Error: {response.error}")
                else:
                    print(f"TLS fingerprint test status: {response.status_code}")
            except Exception as e:
                print(f"JA3 error: {e}")

            # Example 4: HTTP/2 fingerprinting
            print("\n4. Applying HTTP/2 fingerprint:")
            try:
                http2_fp = "1:65536,2:0,3:1000,4:6291456,6:262144|15663105|0|m,s,a,p"
                session.apply_http2(http2_fp)
                print("HTTP/2 fingerprint applied successfully")
            except Exception as e:
                print(f"HTTP/2 error: {e}")

            # print("\n5. Using proxy:")
            # try:
            #     session.set_proxy("http://proxy.example.com:8080")
            #     response = session.get("https://httpbin.org/ip")
            #     print(f"IP with proxy: {response.body}")
            #     session.clear_proxy()
            # except Exception as e:
            #     print(f"Proxy error: {e}")

            # Example 6: Custom headers with order
            print("\n6. Custom ordered headers:")
            ordered_headers = [
                ["User-Agent", "Custom-Agent/1.0"],
                ["Accept", "application/json"],
                ["X-Custom-Header", "CustomValue"]
            ]
            response = session.get("https://tls.peet.ws/api/all", ordered_headers=ordered_headers)
            if response.error:
                print(f"Error: {response.error}")
            else:
                print(f"Status: {response.status_code}")
                if response.body:
                    body_json = json.loads(response.body)
                    print(body_json)
                    print(f"Headers received by server: {body_json.get('headers', {})}")

            print("\nExample completed successfully!")

    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()