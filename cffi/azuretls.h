#ifndef AZURETLS_H
#define AZURETLS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdlib.h>

// Response structure for C
typedef struct {
    int status_code;
    char* body;
    int body_len;
    char* headers;
    char* url;
    char* error;
} CFfiResponse;

// Request structure for C
typedef struct {
    char* method;
    char* url;
    char* body;
    char* headers;
    char* proxy;
    int timeout_ms;
    int force_http1;
    int force_http3;
    int ignore_body;
    int no_cookie;
    int disable_redirects;
    int max_redirects;
    int insecure_skip_verify;
} CFfiRequest;

// Session configuration structure
typedef struct {
    char* browser;
    char* user_agent;
    char* proxy;
    int timeout_ms;
    int max_redirects;
    int insecure_skip_verify;
    char* ordered_headers;
} CFfiSessionConfig;

// Session management
uintptr_t azuretls_session_new(char* config_json);
void azuretls_session_close(uintptr_t session_id);

// HTTP requests
CFfiResponse* azuretls_session_do(uintptr_t session_id, char* request_json);

// TLS/HTTP fingerprinting
char* azuretls_session_apply_ja3(uintptr_t session_id, char* ja3, char* navigator);
char* azuretls_session_apply_http2(uintptr_t session_id, char* fingerprint);
char* azuretls_session_apply_http3(uintptr_t session_id, char* fingerprint);

// Proxy management
char* azuretls_session_set_proxy(uintptr_t session_id, char* proxy);
void azuretls_session_clear_proxy(uintptr_t session_id);

// SSL pinning
char* azuretls_session_add_pins(uintptr_t session_id, char* url, char* pins_json);
char* azuretls_session_clear_pins(uintptr_t session_id, char* url);

// Utility functions
char* azuretls_session_get_ip(uintptr_t session_id);
char* azuretls_version();

// Memory management
void azuretls_free_string(char* str);
void azuretls_free_response(CFfiResponse* resp);

// Library initialization
void azuretls_init();
void azuretls_cleanup();

#ifdef __cplusplus
}
#endif

#endif // AZURETLS_H