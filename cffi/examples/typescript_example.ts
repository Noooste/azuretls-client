#!/usr/bin/env ts-node

/**
 * AzureTLS TypeScript Example using ffi-napi
 *
 * This example demonstrates how to use the AzureTLS CFFI library from TypeScript.
 *
 * Installation:
 * npm install ffi-napi ref-napi ref-struct-napi @types/node
 * npm install -g typescript ts-node
 */

import * as ffi from 'ffi-napi';
import * as ref from 'ref-napi';
import * as Struct from 'ref-struct-napi';
import * as path from 'path';
import * as os from 'os';

// Type definitions
type UintPtr = Buffer;
type CharPtr = Buffer;

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

type CFfiResponseStruct = {
    status_code: number;
    body: CharPtr;
    body_len: number;
    headers: CharPtr;
    url: CharPtr;
    error: CharPtr;
};

const CFfiResponsePtr = ref.refType(CFfiResponse);

// Session configuration interface
interface SessionConfig {
    browser?: 'chrome' | 'firefox' | 'safari' | 'edge' | 'ios';
    user_agent?: string;
    proxy?: string;
    timeout_ms?: number;
    max_redirects?: number;
    insecure_skip_verify?: boolean;
    ordered_headers?: [string, string][];
    headers?: Record<string, string>;
}

// Request options interface
interface RequestOptions {
    method: string;
    url: string;
    body?: string;
    headers?: Record<string, string>;
    orderedHeaders?: [string, string][];
    timeoutMs?: number;
    forceHttp1?: boolean;
    forceHttp3?: boolean;
    ignoreBody?: boolean;
    noCookie?: boolean;
    disableRedirects?: boolean;
    maxRedirects?: number;
    insecureSkipVerify?: boolean;
}

// Response interface
interface AzureTLSResponse {
    statusCode: number;
    body: string | null;
    headers: Record<string, string> | null;
    url: string | null;
    error: string | null;
}

// Library interface
interface AzureTLSLibrary {
    // Session management
    azuretls_session_new: (config: string | null) => UintPtr;
    azuretls_session_close: (sessionId: UintPtr) => void;

    // HTTP requests
    azuretls_session_do: (sessionId: UintPtr, request: string) => Buffer;

    // TLS/HTTP fingerprinting
    azuretls_session_apply_ja3: (sessionId: UintPtr, ja3: string, navigator: string) => CharPtr;
    azuretls_session_apply_http2: (sessionId: UintPtr, fingerprint: string) => CharPtr;
    azuretls_session_apply_http3: (sessionId: UintPtr, fingerprint: string) => CharPtr;

    // Proxy management
    azuretls_session_set_proxy: (sessionId: UintPtr, proxy: string) => CharPtr;
    azuretls_session_clear_proxy: (sessionId: UintPtr) => void;

    // SSL pinning
    azuretls_session_add_pins: (sessionId: UintPtr, url: string, pins: string) => CharPtr;
    azuretls_session_clear_pins: (sessionId: UintPtr, url: string) => CharPtr;

    // Utility functions
    azuretls_session_get_ip: (sessionId: UintPtr) => CharPtr;
    azuretls_version: () => CharPtr;

    // Memory management
    azuretls_free_string: (str: CharPtr) => void;
    azuretls_free_response: (response: Buffer) => void;

    // Library lifecycle
    azuretls_init: () => void;
    azuretls_cleanup: () => void;
}

class AzureTLSSession {
    private lib: AzureTLSLibrary;
    private sessionId: UintPtr | null = null;

    constructor(config: SessionConfig | null = null) {
        this.lib = this._loadLibrary();

        // Initialize library
        this.lib.azuretls_init();

        // Create session
        const configJson = config ? JSON.stringify(config) : null;
        this.sessionId = this.lib.azuretls_session_new(configJson);

        if (this.sessionId.equals(0)) {
            throw new Error('Failed to create AzureTLS session');
        }
    }

    private _loadLibrary(): AzureTLSLibrary {
        // Determine platform and architecture
        const platform = os.platform();
        const arch = os.arch();

        // Map Node.js arch names to Go arch names
        const archMap: Record<string, string> = {
            'x64': 'amd64',
            'ia32': '386',
            'arm64': 'arm64',
            'arm': 'arm'
        };

        const goArch = archMap[arch] || arch;

        let libName: string;

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

        let lib: AzureTLSLibrary | null = null;
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
                }) as AzureTLSLibrary;
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

    async do(options: RequestOptions): Promise<AzureTLSResponse> {
        if (!this.sessionId) {
            throw new Error('Session is closed');
        }

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

        const requestData: any = {
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
            const response = responsePtr.deref() as CFfiResponseStruct;

            const result: AzureTLSResponse = {
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

    async get(url: string, options: Omit<RequestOptions, 'method' | 'url'> = {}): Promise<AzureTLSResponse> {
        return this.do({ method: 'GET', url, ...options });
    }

    async post(url: string, body?: string, options: Omit<RequestOptions, 'method' | 'url' | 'body'> = {}): Promise<AzureTLSResponse> {
        return this.do({ method: 'POST', url, body, ...options });
    }

    async put(url: string, body?: string, options: Omit<RequestOptions, 'method' | 'url' | 'body'> = {}): Promise<AzureTLSResponse> {
        return this.do({ method: 'PUT', url, body, ...options });
    }

    async delete(url: string, options: Omit<RequestOptions, 'method' | 'url'> = {}): Promise<AzureTLSResponse> {
        return this.do({ method: 'DELETE', url, ...options });
    }

    async head(url: string, options: Omit<RequestOptions, 'method' | 'url'> = {}): Promise<AzureTLSResponse> {
        return this.do({ method: 'HEAD', url, ignoreBody: true, ...options });
    }

    async options(url: string, options: Omit<RequestOptions, 'method' | 'url'> = {}): Promise<AzureTLSResponse> {
        return this.do({ method: 'OPTIONS', url, ...options });
    }

    async patch(url: string, body?: string, options: Omit<RequestOptions, 'method' | 'url' | 'body'> = {}): Promise<AzureTLSResponse> {
        return this.do({ method: 'PATCH', url, body, ...options });
    }

    applyJa3(ja3: string, navigator: string = 'chrome'): void {
        if (!this.sessionId) {
            throw new Error('Session is closed');
        }

        const errorPtr = this.lib.azuretls_session_apply_ja3(this.sessionId, ja3, navigator);
        if (!errorPtr.isNull()) {
            const error = errorPtr.readCString();
            this.lib.azuretls_free_string(errorPtr);
            throw new Error(`Failed to apply JA3: ${error}`);
        }
    }

    applyHttp2(fingerprint: string): void {
        if (!this.sessionId) {
            throw new Error('Session is closed');
        }

        const errorPtr = this.lib.azuretls_session_apply_http2(this.sessionId, fingerprint);
        if (!errorPtr.isNull()) {
            const error = errorPtr.readCString();
            this.lib.azuretls_free_string(errorPtr);
            throw new Error(`Failed to apply HTTP/2 fingerprint: ${error}`);
        }
    }

    applyHttp3(fingerprint: string): void {
        if (!this.sessionId) {
            throw new Error('Session is closed');
        }

        const errorPtr = this.lib.azuretls_session_apply_http3(this.sessionId, fingerprint);
        if (!errorPtr.isNull()) {
            const error = errorPtr.readCString();
            this.lib.azuretls_free_string(errorPtr);
            throw new Error(`Failed to apply HTTP/3 fingerprint: ${error}`);
        }
    }

    setProxy(proxy: string): void {
        if (!this.sessionId) {
            throw new Error('Session is closed');
        }

        const errorPtr = this.lib.azuretls_session_set_proxy(this.sessionId, proxy);
        if (!errorPtr.isNull()) {
            const error = errorPtr.readCString();
            this.lib.azuretls_free_string(errorPtr);
            throw new Error(`Failed to set proxy: ${error}`);
        }
    }

    clearProxy(): void {
        if (!this.sessionId) {
            throw new Error('Session is closed');
        }

        this.lib.azuretls_session_clear_proxy(this.sessionId);
    }

    addPins(url: string, pins: string[]): void {
        if (!this.sessionId) {
            throw new Error('Session is closed');
        }

        const pinsJson = JSON.stringify(pins);
        const errorPtr = this.lib.azuretls_session_add_pins(this.sessionId, url, pinsJson);
        if (!errorPtr.isNull()) {
            const error = errorPtr.readCString();
            this.lib.azuretls_free_string(errorPtr);
            throw new Error(`Failed to add pins: ${error}`);
        }
    }

    clearPins(url: string): void {
        if (!this.sessionId) {
            throw new Error('Session is closed');
        }

        const errorPtr = this.lib.azuretls_session_clear_pins(this.sessionId, url);
        if (!errorPtr.isNull()) {
            const error = errorPtr.readCString();
            this.lib.azuretls_free_string(errorPtr);
            throw new Error(`Failed to clear pins: ${error}`);
        }
    }

    async getIp(): Promise<string> {
        if (!this.sessionId) {
            throw new Error('Session is closed');
        }

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

    getVersion(): string {
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

    close(): void {
        if (this.sessionId && !this.sessionId.equals(0)) {
            this.lib.azuretls_session_close(this.sessionId);
            this.sessionId = null;
        }
    }
}

// Example usage
async function main(): Promise<void> {
    console.log('AzureTLS TypeScript Example');
    console.log('='.repeat(40));

    try {
        // Create session with configuration
        const session = new AzureTLSSession({
            browser: 'chrome',
            user_agent: 'AzureTLS-TypeScript/1.0',
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
        const postData = JSON.stringify({ message: 'Hello from AzureTLS TypeScript!' });
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
            console.log(`JA3 error: ${(error as Error).message}`);
        }

        // Example 4: HTTP/2 fingerprinting
        console.log('\n4. Applying HTTP/2 fingerprint:');
        try {
            const http2Fp = '1:65536,2:0,3:1000,4:6291456,6:262144|15663105|0|m,s,a,p';
            session.applyHttp2(http2Fp);
            console.log('HTTP/2 fingerprint applied successfully');
        } catch (error) {
            console.log(`HTTP/2 error: ${(error as Error).message}`);
        }

        // Example 5: Custom headers with order
        console.log('\n5. Custom ordered headers:');
        const orderedHeaders: [string, string][] = [
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
            console.log(`Timeout error: ${(error as Error).message}`);
        }

        // Example 8: Get IP address
        console.log('\n8. Get public IP:');
        try {
            const ip = await session.getIp();
            console.log(`Public IP: ${ip}`);
        } catch (error) {
            console.log(`IP error: ${(error as Error).message}`);
        }

        console.log('\nExample completed successfully!');

        // Cleanup
        session.close();

    } catch (error) {
        console.error(`Error: ${(error as Error).message}`);
        process.exit(1);
    }
}

// Export for module usage
export { AzureTLSSession, SessionConfig, RequestOptions, AzureTLSResponse };

// Run example if called directly
if (require.main === module) {
    main().catch(console.error);
}