#!/usr/bin/env node

/**
 * AzureTLS Node.js Example using ffi-napi
 *
 * This example demonstrates how to use the AzureTLS CFFI library from Node.js.
 *
 * Installation:
 * npm install ffi-napi ref-napi ref-struct-napi
 */

const ffi = require('ffi-napi');
const ref = require('ref-napi');
const Struct = require('ref-struct-napi');
const path = require('path');
const os = require('os');

// Define C types
const uintptr_t = ref.types.uint64;
const char_ptr = ref.types.CString;

// Define CFfiResponse structure
const CFfiResponse = Struct({
    'status_code': ref.types.int,
    'body': char_ptr,
    'body_len': ref.types.int,
    'headers': char_ptr,
    'url': char_ptr,
    'error': char_ptr
});

const CFfiResponsePtr = ref.refType(CFfiResponse);

class AzureTLSSession {
    constructor(config = null) {
        this.lib = this._loadLibrary();
        this.sessionId = null;

        // Initialize library
        this.lib.azuretls_init();

        // Create session
        const configJson = config ? JSON.stringify(config) : null;
        this.sessionId = this.lib.azuretls_session_new(configJson);

        if (this.sessionId.equals(0)) {
            throw new Error('Failed to create AzureTLS session');
        }
    }

    _loadLibrary() {
        // Determine platform and architecture
        const platform = os.platform();
        const arch = os.arch();

        // Map Node.js arch names to Go arch names
        const archMap = {
            'x64': 'amd64',
            'ia32': '386',
            'arm64': 'arm64',
            'arm': 'arm'
        };

        const goArch = archMap[arch] || arch;

        let libName;
        let libPath;

        switch (platform) {
            case 'win32':
                libName = `libazuretls_windows_${goArch}.dll`;
                break;
            case 'darwin':
                libName = `libazuretls_darwin_${goArch}.dylib`;
                break;
            default: // linux, freebsd, etc.
                libName = `libazuretls_${platform}_${goArch}.so`;
                break;
        }

        // Try different paths
        const searchPaths = [
            path.join(__dirname, '..', 'build', libName),
            path.join(__dirname, libName),
            libName
        ];

        let lib = null;
        for (const libPath of searchPaths) {
            try {
                lib = ffi.Library(libPath, {
                    // Session management
                    'azuretls_session_new': [uintptr_t, [char_ptr]],
                    'azuretls_session_close': ['void', [uintptr_t]],

                    // HTTP requests
                    'azuretls_session_do': [CFfiResponsePtr, [uintptr_t, char_ptr]],

                    // TLS/HTTP fingerprinting
                    'azuretls_session_apply_ja3': [char_ptr, [uintptr_t, char_ptr, char_ptr]],
                    'azuretls_session_apply_http2': [char_ptr, [uintptr_t, char_ptr]],
                    'azuretls_session_apply_http3': [char_ptr, [uintptr_t, char_ptr]],

                    // Proxy management
                    'azuretls_session_set_proxy': [char_ptr, [uintptr_t, char_ptr]],
                    'azuretls_session_clear_proxy': ['void', [uintptr_t]],

                    // SSL pinning
                    'azuretls_session_add_pins': [char_ptr, [uintptr_t, char_ptr, char_ptr]],
                    'azuretls_session_clear_pins': [char_ptr, [uintptr_t, char_ptr]],

                    // Utility functions
                    'azuretls_session_get_ip': [char_ptr, [uintptr_t]],
                    'azuretls_version': [char_ptr, []],

                    // Memory management
                    'azuretls_free_string': ['void', [char_ptr]],
                    'azuretls_free_response': ['void', [CFfiResponsePtr]],

                    // Library lifecycle
                    'azuretls_init': ['void', []],
                    'azuretls_cleanup': ['void', []]
                });
                break;
            } catch (error) {
                // Try next path
                continue;
            }
        }

        if (!lib) {
            throw new Error(`Could not load AzureTLS library. Tried: ${searchPaths.join(', ')}`);
        }

        return lib;
    }

    async do(options) {
        const {
            method,
            url,
            body,
            headers,
            orderedHeaders,
            timeoutMs,
            forceHttp1 = false,
            forceHttp3 = false,
            ignoreBody = false,
            noCookie = false,
            disableRedirects = false,
            maxRedirects,
            insecureSkipVerify = false
        } = options;

        const requestData = {
            method,
            url
        };

        if (body !== undefined) requestData.body = body;
        if (headers !== undefined) requestData.headers = headers;
        if (orderedHeaders !== undefined) requestData.ordered_headers = orderedHeaders;
        if (timeoutMs !== undefined) requestData.timeout_ms = timeoutMs;
        if (forceHttp1) requestData.force_http1 = true;
        if (forceHttp3) requestData.force_http3 = true;
        if (ignoreBody) requestData.ignore_body = true;
        if (noCookie) requestData.no_cookie = true;
        if (disableRedirects) requestData.disable_redirects = true;
        if (maxRedirects !== undefined) requestData.max_redirects = maxRedirects;
        if (insecureSkipVerify) requestData.insecure_skip_verify = true;

        const requestJson = JSON.stringify(requestData);
        const responsePtr = this.lib.azuretls_session_do(this.sessionId, requestJson);

        if (responsePtr.isNull()) {
            throw new Error('Failed to execute request');
        }

        try {
            const response = responsePtr.deref();

            const result = {
                statusCode: response.status_code,
                body: null,
                headers: null,
                url: null,
                error: null
            };

            if (!response.error.isNull()) {
                result.error = response.error.readCString();
                return result;
            }

            if (!response.body.isNull() && response.body_len > 0) {
                result.body = ref.reinterpret(response.body, response.body_len).toString();
            }

            if (!response.headers.isNull()) {
                try {
                    result.headers = JSON.parse(response.headers.readCString());
                } catch (e) {
                    result.headers = {};
                }
            }

            if (!response.url.isNull()) {
                result.url = response.url.readCString();
            }

            return result;
        } finally {
            this.lib.azuretls_free_response(responsePtr);
        }
    }

    async get(url, options = {}) {
        return this.do({ method: 'GET', url, ...options });
    }

    async post(url, body, options = {}) {
        return this.do({ method: 'POST', url, body, ...options });
    }

    async put(url, body, options = {}) {
        return this.do({ method: 'PUT', url, body, ...options });
    }

    async delete(url, options = {}) {
        return this.do({ method: 'DELETE', url, ...options });
    }

    async head(url, options = {}) {
        return this.do({ method: 'HEAD', url, ignoreBody: true, ...options });
    }

    async options(url, options = {}) {
        return this.do({ method: 'OPTIONS', url, ...options });
    }

    async patch(url, body, options = {}) {
        return this.do({ method: 'PATCH', url, body, ...options });
    }

    applyJa3(ja3, navigator = 'chrome') {
        const errorPtr = this.lib.azuretls_session_apply_ja3(this.sessionId, ja3, navigator);
        if (!errorPtr.isNull()) {
            const error = errorPtr.readCString();
            this.lib.azuretls_free_string(errorPtr);
            throw new Error(`Failed to apply JA3: ${error}`);
        }
    }

    applyHttp2(fingerprint) {
        const errorPtr = this.lib.azuretls_session_apply_http2(this.sessionId, fingerprint);
        if (!errorPtr.isNull()) {
            const error = errorPtr.readCString();
            this.lib.azuretls_free_string(errorPtr);
            throw new Error(`Failed to apply HTTP/2 fingerprint: ${error}`);
        }
    }

    applyHttp3(fingerprint) {
        const errorPtr = this.lib.azuretls_session_apply_http3(this.sessionId, fingerprint);
        if (!errorPtr.isNull()) {
            const error = errorPtr.readCString();
            this.lib.azuretls_free_string(errorPtr);
            throw new Error(`Failed to apply HTTP/3 fingerprint: ${error}`);
        }
    }

    setProxy(proxy) {
        const errorPtr = this.lib.azuretls_session_set_proxy(this.sessionId, proxy);
        if (!errorPtr.isNull()) {
            const error = errorPtr.readCString();
            this.lib.azuretls_free_string(errorPtr);
            throw new Error(`Failed to set proxy: ${error}`);
        }
    }

    clearProxy() {
        this.lib.azuretls_session_clear_proxy(this.sessionId);
    }

    addPins(url, pins) {
        const pinsJson = JSON.stringify(pins);
        const errorPtr = this.lib.azuretls_session_add_pins(this.sessionId, url, pinsJson);
        if (!errorPtr.isNull()) {
            const error = errorPtr.readCString();
            this.lib.azuretls_free_string(errorPtr);
            throw new Error(`Failed to add pins: ${error}`);
        }
    }

    clearPins(url) {
        const errorPtr = this.lib.azuretls_session_clear_pins(this.sessionId, url);
        if (!errorPtr.isNull()) {
            const error = errorPtr.readCString();
            this.lib.azuretls_free_string(errorPtr);
            throw new Error(`Failed to clear pins: ${error}`);
        }
    }

    async getIp() {
        const resultPtr = this.lib.azuretls_session_get_ip(this.sessionId);
        if (resultPtr.isNull()) {
            throw new Error('Failed to get IP address');
        }

        try {
            const result = resultPtr.readCString();
            if (result.startsWith('error:')) {
                throw new Error(result);
            }
            return result;
        } finally {
            this.lib.azuretls_free_string(resultPtr);
        }
    }

    getVersion() {
        const versionPtr = this.lib.azuretls_version();
        if (versionPtr.isNull()) {
            return 'unknown';
        }

        try {
            return versionPtr.readCString();
        } finally {
            this.lib.azuretls_free_string(versionPtr);
        }
    }

    close() {
        if (this.sessionId && !this.sessionId.equals(0)) {
            this.lib.azuretls_session_close(this.sessionId);
            this.sessionId = null;
        }
    }
}

// Example usage
async function main() {
    console.log('AzureTLS Node.js Example');
    console.log('='.repeat(40));

    try {
        // Create session with configuration
        const session = new AzureTLSSession({
            browser: 'chrome',
            user_agent: 'AzureTLS-NodeJS/1.0',
            timeout_ms: 30000,
            max_redirects: 10
        });

        console.log(`Library version: ${session.getVersion()}`);

        // Example 1: Simple GET request
        console.log('\n1. Simple GET request:');
        const response1 = await session.get('https://httpbin.org/get');
        if (response1.error) {
            console.log(`Error: ${response1.error}`);
        } else {
            console.log(`Status: ${response1.statusCode}`);
            console.log(`URL: ${response1.url}`);
            if (response1.body) {
                const bodyJson = JSON.parse(response1.body);
                console.log(`User-Agent: ${bodyJson.headers['User-Agent'] || 'N/A'}`);
            }
        }

        // Example 2: POST request with JSON body
        console.log('\n2. POST request with JSON:');
        const postData = JSON.stringify({ message: 'Hello from AzureTLS Node.js!' });
        const response2 = await session.post('https://httpbin.org/post', postData, {
            headers: { 'Content-Type': 'application/json' }
        });
        if (response2.error) {
            console.log(`Error: ${response2.error}`);
        } else {
            console.log(`Status: ${response2.statusCode}`);
            if (response2.body) {
                const bodyJson = JSON.parse(response2.body);
                console.log(`Received data: ${JSON.stringify(bodyJson.json || {})}`);
            }
        }

        // Example 3: JA3 fingerprinting
        console.log('\n3. Applying JA3 fingerprint:');
        try {
            const ja3 = '771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0';
            session.applyJa3(ja3, 'chrome');
            console.log('JA3 fingerprint applied successfully');

            const response3 = await session.get('https://tls.peet.ws/api/all');
            if (response3.error) {
                console.log(`Error: ${response3.error}`);
            } else {
                console.log(`TLS fingerprint test status: ${response3.statusCode}`);
            }
        } catch (error) {
            console.log(`JA3 error: ${error.message}`);
        }

        // Example 4: HTTP/2 fingerprinting
        console.log('\n4. Applying HTTP/2 fingerprint:');
        try {
            const http2Fp = '1:65536,2:0,3:1000,4:6291456,6:262144|15663105|0|m,s,a,p';
            session.applyHttp2(http2Fp);
            console.log('HTTP/2 fingerprint applied successfully');
        } catch (error) {
            console.log(`HTTP/2 error: ${error.message}`);
        }

        // Example 5: Custom headers with order
        console.log('\n5. Custom ordered headers:');
        const orderedHeaders = [
            ['User-Agent', 'Custom-Agent/1.0'],
            ['Accept', 'application/json'],
            ['X-Custom-Header', 'CustomValue']
        ];
        const response5 = await session.get('https://httpbin.org/headers', {
            orderedHeaders
        });
        if (response5.error) {
            console.log(`Error: ${response5.error}`);
        } else {
            console.log(`Status: ${response5.statusCode}`);
            if (response5.body) {
                const bodyJson = JSON.parse(response5.body);
                console.log(`Headers received by server:`, bodyJson.headers || {});
            }
        }

        // Example 6: Force HTTP/1.1
        console.log('\n6. Force HTTP/1.1:');
        const response6 = await session.get('https://httpbin.org/get', {
            forceHttp1: true
        });
        if (response6.error) {
            console.log(`Error: ${response6.error}`);
        } else {
            console.log(`Status: ${response6.statusCode} (forced HTTP/1.1)`);
        }

        // Example 7: Timeout test
        console.log('\n7. Timeout test:');
        try {
            const response7 = await session.get('https://httpbin.org/delay/2', {
                timeoutMs: 1000
            });
            if (response7.error) {
                console.log(`Expected timeout error: ${response7.error}`);
            } else {
                console.log(`Request completed: ${response7.statusCode}`);
            }
        } catch (error) {
            console.log(`Timeout error: ${error.message}`);
        }

        // Example 8: Get IP address
        console.log('\n8. Get public IP:');
        try {
            const ip = await session.getIp();
            console.log(`Public IP: ${ip}`);
        } catch (error) {
            console.log(`IP error: ${error.message}`);
        }

        console.log('\nExample completed successfully!');

        // Cleanup
        session.close();

    } catch (error) {
        console.error(`Error: ${error.message}`);
        process.exit(1);
    }
}

// Export for module usage
module.exports = { AzureTLSSession };

// Run example if called directly
if (require.main === module) {
    main().catch(console.error);
}