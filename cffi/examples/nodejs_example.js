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
const StructType = require('ref-struct-di')(ref);
const path = require('path');

// Define the C structures as JavaScript objects using ref-struct
const CFfiResponse = StructType({
    status_code: 'int',
    body: 'char*',
    body_len: 'int',
    headers: 'char*',
    url: 'char*',
    error: 'char*'
});

const CFfiRequest = StructType({
    method: 'char*',
    url: 'char*',
    body: 'char*',
    headers: 'char*',
    proxy: 'char*',
    timeout_ms: 'int',
    force_http1: 'int',
    force_http3: 'int',
    ignore_body: 'int',
    no_cookie: 'int',
    disable_redirects: 'int',
    max_redirects: 'int',
    insecure_skip_verify: 'int'
});

// Load the shared library
const azureTLS = ffi.Library(path.join(__dirname, 'azuretls-1.10.4-darwin-arm64.dylib'), {
    // Library initialization
    'azuretls_init': ['void', []],
    'azuretls_cleanup': ['void', []],

    // Session management
    'azuretls_session_new': ['uint64', ['char*']],
    'azuretls_session_close': ['void', ['uint64']],

    // HTTP requests
    'azuretls_session_do': [ref.refType(CFfiResponse), ['uint64', 'char*']],

    // TLS/HTTP fingerprinting
    'azuretls_session_apply_ja3': ['char*', ['uint64', 'char*', 'char*']],
    'azuretls_session_apply_http2': ['char*', ['uint64', 'char*']],
    'azuretls_session_apply_http3': ['char*', ['uint64', 'char*']],

    // Proxy management
    'azuretls_session_set_proxy': ['char*', ['uint64', 'char*']],
    'azuretls_session_clear_proxy': ['void', ['uint64']],

    // SSL pinning
    'azuretls_session_add_pins': ['char*', ['uint64', 'char*', 'char*']],
    'azuretls_session_clear_pins': ['char*', ['uint64', 'char*']],

    // Utility functions
    'azuretls_session_get_ip': ['char*', ['uint64']],
    'azuretls_version': ['char*', []],

    // Memory management
    'azuretls_free_string': ['void', ['char*']],
    'azuretls_free_response': ['void', [ref.refType(CFfiResponse)]]
});

class AzureTLSClient {
    constructor(config = {}) {
        // Initialize the library
        azureTLS.azuretls_init();

        // Default session configuration
        const sessionConfig = {
            browser: config.browser || 'chrome',
            user_agent: config.userAgent || 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            proxy: config.proxy || null,
            timeout_ms: config.timeout || 30000,
            max_redirects: config.maxRedirects || 10,
            insecure_skip_verify: config.insecureSkipVerify === true,
            ordered_headers: config.orderedHeaders || null
        };

        // Create session
        const configJson = JSON.stringify(sessionConfig);
        const configBuffer = Buffer.from(configJson + '\0', 'utf8');
        this.sessionId = azureTLS.azuretls_session_new(configBuffer);

        if (!this.sessionId) {
            throw new Error('Failed to create AzureTLS session');
        }
    }

    async request(options) {
        const requestConfig = {
            method: options.method || 'GET',
            url: options.url,
            body: options.body || null,
            headers: options.headers ? options.headers : null,
            proxy: options.proxy || null,
            timeout_ms: options.timeout || 30000,
            force_http1: options.forceHttp1 === true,
            force_http3: options.forceHttp3 === true,
            ignore_body: options.ignoreBody === true,
            no_cookie: options.noCookie === true,
            disable_redirects: options.disableRedirects === true,
            max_redirects: options.maxRedirects || 10,
            insecure_skip_verify: options.insecureSkipVerify === true
        };

        const requestJson = JSON.stringify(requestConfig);
        const requestBuffer = Buffer.from(requestJson + '\0', 'utf8');
        const responsePtr = azureTLS.azuretls_session_do(this.sessionId, requestBuffer);

        if (responsePtr.isNull()) {
            throw new Error('Request failed - null response');
        }

        // Dereference the pointer to get the actual response structure
        const response = responsePtr.deref();

        // Extract response data with proper null checking
        const result = {
            statusCode: response.status_code,
            body: null,
            bodyLength: response.body_len,
            headers: {},
            url: null,
            error: null
        };

        // Safely read body
        if (response.body && !response.body.isNull()) {
            result.body = response.body.readCString();
        }

        // Safely read headers
        if (response.headers && !response.headers.isNull()) {
            try {
                const headersStr = response.headers.readCString();
                result.headers = headersStr ? JSON.parse(headersStr) : {};
            } catch (e) {
                result.headers = {};
            }
        }

        // Safely read URL
        if (response.url && !response.url.isNull()) {
            result.url = response.url.readCString();
        }

        // Safely read error
        if (response.error && !response.error.isNull()) {
            result.error = response.error.readCString();
        }

        // Free the response memory
        azureTLS.azuretls_free_response(responsePtr);

        if (result.error) {
            throw new Error(`Request failed: ${result.error}`);
        }

        return result;
    }

    async get(url, options = {}) {
        return this.request({ ...options, method: 'GET', url });
    }

    async post(url, data, options = {}) {
        const body = typeof data === 'object' ? JSON.stringify(data) : data;
        return this.request({ ...options, method: 'POST', url, body });
    }

    async put(url, data, options = {}) {
        const body = typeof data === 'object' ? JSON.stringify(data) : data;
        return this.request({ ...options, method: 'PUT', url, body });
    }

    async delete(url, options = {}) {
        return this.request({ ...options, method: 'DELETE', url });
    }

    // Apply JA3 fingerprint for TLS fingerprinting
    applyJA3(ja3String, navigator = null) {
        const ja3Buffer = Buffer.from(ja3String + '\0', 'utf8');
        const navBuffer = navigator ? Buffer.from(navigator + '\0', 'utf8') : null;
        const result = azureTLS.azuretls_session_apply_ja3(this.sessionId, ja3Buffer, navBuffer);
        if (result && !result.isNull()) {
            const error = result.readCString();
            azureTLS.azuretls_free_string(result);
            if (error) {
                throw new Error(`Failed to apply JA3: ${error}`);
            }
        }
    }

    // Apply HTTP/2 fingerprint
    applyHTTP2Fingerprint(fingerprint) {
        const fpBuffer = Buffer.from(fingerprint + '\0', 'utf8');
        const result = azureTLS.azuretls_session_apply_http2(this.sessionId, fpBuffer);
        if (result && !result.isNull()) {
            const error = result.readCString();
            azureTLS.azuretls_free_string(result);
            if (error) {
                throw new Error(`Failed to apply HTTP/2 fingerprint: ${error}`);
            }
        }
    }

    // Set proxy
    setProxy(proxyUrl) {
        const proxyBuffer = Buffer.from(proxyUrl + '\0', 'utf8');
        const result = azureTLS.azuretls_session_set_proxy(this.sessionId, proxyBuffer);
        if (result && !result.isNull()) {
            const error = result.readCString();
            azureTLS.azuretls_free_string(result);
            if (error) {
                throw new Error(`Failed to set proxy: ${error}`);
            }
        }
    }

    // Clear proxy
    clearProxy() {
        azureTLS.azuretls_session_clear_proxy(this.sessionId);
    }

    // Get current IP
    async getIP() {
        const result = azureTLS.azuretls_session_get_ip(this.sessionId);
        if (result && !result.isNull()) {
            const ip = result.readCString();
            azureTLS.azuretls_free_string(result);
            return ip;
        }
        return null;
    }

    // Get library version
    static getVersion() {
        const result = azureTLS.azuretls_version();
        if (result && !result.isNull()) {
            const version = result.readCString();
            azureTLS.azuretls_free_string(result);
            return version;
        }
        return 'unknown';
    }

    // Clean up resources
    close() {
        if (this.sessionId) {
            azureTLS.azuretls_session_close(this.sessionId);
            this.sessionId = null;
        }
    }

    // Cleanup library resources (call when your app is shutting down)
    static cleanup() {
        azureTLS.azuretls_cleanup();
    }
}

// Usage examples
async function examples() {
    try {
        console.log('AzureTLS Version:', AzureTLSClient.getVersion());

        // Create a client instance
        const client = new AzureTLSClient({
            browser: 'chrome',
            timeout: 30000,
            userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36'
        });

        // Example 1: Simple GET request
        console.log('\n--- Example 1: Simple GET request ---');
        const response1 = await client.get('https://httpbin.org/json');
        console.log('Status Code:', response1.statusCode);
        console.log('Response Body:', response1.body);

        // Example 2: POST request with JSON data
        console.log('\n--- Example 2: POST request ---');
        const postData = { name: 'John Doe', email: 'john@example.com' };
        const response2 = await client.post('https://httpbin.org/post', postData, {
            headers: {
                'Content-Type': 'application/json',
                'User-Agent': 'AzureTLS-Node-Client/1.0'
            }
        });
        console.log('Status Code:', response2.statusCode);
        console.log('Response Headers:', response2.headers);

        // Example 3: GET request with custom headers
        console.log('\n--- Example 3: GET with custom headers ---');
        const response3 = await client.get('https://httpbin.org/headers', {
            headers: {
                'X-Custom-Header': 'MyValue',
                'Authorization': 'Bearer token123'
            }
        });
        console.log('Status Code:', response3.statusCode);
        console.log('Response Body:', response3.body);

        // Example 4: Apply JA3 fingerprint (example JA3)
        console.log('\n--- Example 4: JA3 Fingerprinting ---');
        try {
            const ja3 = '771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0';
            client.applyJA3(ja3);
            console.log('JA3 fingerprint applied successfully');

            const response4 = await client.get('https://httpbin.org/json');
            console.log('Request with JA3 - Status Code:', response4.statusCode);
        } catch (error) {
            console.log('JA3 Error:', error.message);
        }

        // Example 5: Get current IP
        console.log('\n--- Example 5: Get IP ---');
        try {
            const ip = await client.getIP();
            console.log('Current IP:', ip);
        } catch (error) {
            console.log('IP Error:', error.message);
        }

        // Clean up
        client.close();

    } catch (error) {
        console.error('Error:', error.message);
    }
}

// Run examples if this file is executed directly
if (require.main === module) {
    examples().catch(console.error);
}

// Export the class for use in other modules
module.exports = AzureTLSClient;
