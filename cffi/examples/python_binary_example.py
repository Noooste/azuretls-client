#!/usr/bin/env python3
"""
Python Example demonstrating binary upload functionality

This example shows how to use both the base64 JSON approach
and the new direct binary bytes approach for uploading files.
"""

import base64
import ctypes
import json
from ctypes import c_char_p, c_ulong, c_int, c_size_t, POINTER, Structure


# Load the shared library (adjust path as needed)
# lib = ctypes.CDLL('./libazuretls.so')  # Linux
# lib = ctypes.CDLL('./libazuretls.dylib')  # macOS
# lib = ctypes.CDLL('./azuretls.dll')  # Windows

class CFfiResponse(Structure):
    _fields_ = [
        ("status_code", c_int),
        ("body", c_char_p),
        ("body_len", c_int),
        ("headers", c_char_p),
        ("url", c_char_p),
        ("error", c_char_p),
    ]

class AzureTLSClient:
    def __init__(self, lib_path="./libazuretls.so"):
        """Initialize the AzureTLS client with the shared library."""
        self.lib = ctypes.CDLL(lib_path)
        self._setup_function_signatures()
        self.lib.azuretls_init()

    def _setup_function_signatures(self):
        """Setup C function signatures for proper calling."""
        # Session management
        self.lib.azuretls_session_new.argtypes = [c_char_p]
        self.lib.azuretls_session_new.restype = c_ulong

        self.lib.azuretls_session_close.argtypes = [c_ulong]
        self.lib.azuretls_session_close.restype = None

        # Original JSON request
        self.lib.azuretls_session_do.argtypes = [c_ulong, c_char_p]
        self.lib.azuretls_session_do.restype = POINTER(CFfiResponse)

        # New binary request
        self.lib.azuretls_session_do_bytes.argtypes = [
            c_ulong, c_char_p, c_char_p, c_char_p,
            ctypes.POINTER(ctypes.c_ubyte), c_size_t
        ]
        self.lib.azuretls_session_do_bytes.restype = POINTER(CFfiResponse)

        # Memory management
        self.lib.azuretls_free_response.argtypes = [POINTER(CFfiResponse)]
        self.lib.azuretls_free_response.restype = None

        # Version info
        self.lib.azuretls_version.argtypes = []
        self.lib.azuretls_version.restype = c_char_p

    def create_session(self, config=None):
        """Create a new HTTP session."""
        config_json = json.dumps(config).encode() if config else None
        return self.lib.azuretls_session_new(config_json)

    def close_session(self, session_id):
        """Close an HTTP session."""
        self.lib.azuretls_session_close(session_id)

    def request_json(self, session_id, request_data):
        """Make a request using JSON (supports body_b64 for binary)."""
        request_json = json.dumps(request_data).encode()
        response_ptr = self.lib.azuretls_session_do(session_id, request_json)
        return self._process_response(response_ptr)

    def request_bytes(self, session_id, method, url, headers=None, body=None):
        """Make a request with direct binary body data."""
        headers_json = json.dumps(headers).encode() if headers else None

        if body:
            # Convert Python bytes to C array
            body_array = (ctypes.c_ubyte * len(body)).from_buffer_copy(body)
            body_ptr = ctypes.cast(body_array, ctypes.POINTER(ctypes.c_ubyte))
            body_len = len(body)
        else:
            body_ptr = None
            body_len = 0

        response_ptr = self.lib.azuretls_session_do_bytes(
            session_id, method.encode(), url.encode(),
            headers_json, body_ptr, body_len
        )
        return self._process_response(response_ptr)

    def _process_response(self, response_ptr):
        """Process C response and convert to Python dict."""
        if not response_ptr:
            return {"error": "Failed to get response"}

        response = response_ptr.contents
        result = {
            "status_code": response.status_code,
            "body": response.body.decode() if response.body else None,
            "body_len": response.body_len,
            "headers": json.loads(response.headers.decode()) if response.headers else {},
            "url": response.url.decode() if response.url else None,
            "error": response.error.decode() if response.error else None,
        }

        # Free the C response
        self.lib.azuretls_free_response(response_ptr)
        return result

    def get_version(self):
        """Get library version."""
        return self.lib.azuretls_version().decode()

    def cleanup(self):
        """Cleanup library resources."""
        self.lib.azuretls_cleanup()

def example_text_upload():
    """Example 1: Regular text upload (existing functionality)."""
    print("\n=== Example 1: Regular Text Upload (Existing) ===")

    client = AzureTLSClient()
    session = client.create_session()

    request_data = {
        "method": "POST",
        "url": "https://httpbin.org/post",
        "headers": {"Content-Type": "application/json"},
        "body": {"message": "Hello World"}
    }

    response = client.request_json(session, request_data)
    print(f"Status: {response['status_code']}")
    print(f"Error: {response['error']}")

    client.close_session(session)
    client.cleanup()

def example_binary_upload_base64():
    """Example 2: Binary upload using base64 in JSON."""
    print("\n=== Example 2: Base64 Binary Upload via JSON ===")

    client = AzureTLSClient()
    session = client.create_session()

    # Sample binary data (PNG header)
    binary_data = bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])
    base64_data = base64.b64encode(binary_data).decode()

    request_data = {
        "method": "POST",
        "url": "https://httpbin.org/post",
        "headers": {"Content-Type": "image/png"},
        "body_b64": base64_data  # Use body_b64 instead of body
    }

    response = client.request_json(session, request_data)
    print(f"Status: {response['status_code']}")
    print(f"Error: {response['error']}")

    client.close_session(session)
    client.cleanup()

def example_binary_upload_direct():
    """Example 3: Direct binary upload using new bytes function."""
    print("\n=== Example 3: Direct Binary Upload ===")

    client = AzureTLSClient()
    session = client.create_session()

    # Sample binary data
    binary_data = bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])

    response = client.request_bytes(
        session,
        method="POST",
        url="https://httpbin.org/post",
        headers={"Content-Type": "application/octet-stream"},
        body=binary_data
    )

    print(f"Status: {response['status_code']}")
    print(f"Error: {response['error']}")

    client.close_session(session)
    client.cleanup()

def example_file_upload():
    """Example 4: Upload a real file."""
    print("\n=== Example 4: File Upload ===")

    # Try to read a test file
    try:
        with open("test_file.txt", "rb") as f:
            file_data = f.read()
    except FileNotFoundError:
        print("No test file found, creating sample data...")
        file_data = b"This is a test file content for binary upload demo."

    client = AzureTLSClient()
    session = client.create_session()

    # Upload using direct bytes method
    response = client.request_bytes(
        session,
        method="POST",
        url="https://httpbin.org/post",
        headers={
            "Content-Type": "text/plain",
            "Content-Length": str(len(file_data))
        },
        body=file_data
    )

    print(f"Status: {response['status_code']}")
    print(f"Uploaded {len(file_data)} bytes")
    print(f"Error: {response['error']}")

    client.close_session(session)
    client.cleanup()

if __name__ == "__main__":
    print("AzureTLS-Client Python Binary Upload Examples")

    try:
        example_text_upload()
        example_binary_upload_base64()
        example_binary_upload_direct()
        example_file_upload()

        print("\nAll examples completed!")

    except Exception as e:
        print(f"Error: {e}")
        print("Make sure to build the shared library first: cd cffi && make")
