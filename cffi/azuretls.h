#ifndef AZURETLS_H
#define AZURETLS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Response structure for C
typedef struct {
    int status_code;
    char* body;
    int body_len;
    char* headers;
    char* url;
    char* error;
    char* protocol;
} CFfiResponse;

// Session management functions
uintptr_t azuretls_session_new(char* config_json);
void azuretls_session_close(uintptr_t session_id);

// Request functions
// Original JSON-based request function (now supports body_b64 for binary data)
CFfiResponse* azuretls_session_do(uintptr_t session_id, char* request_json);

// New binary request function for direct binary uploads
CFfiResponse* azuretls_session_do_bytes(
    uintptr_t session_id,
    const char* method,
    const char* url,
    const char* headers_json,
    const unsigned char* body,
    size_t body_len
);

// Session configuration functions
char* azuretls_session_apply_ja3(uintptr_t session_id, char* ja3, char* navigator);
char* azuretls_session_apply_http2(uintptr_t session_id, char* fingerprint);
char* azuretls_session_apply_http3(uintptr_t session_id, char* fingerprint);
char* azuretls_session_set_proxy(uintptr_t session_id, char* proxy);
void azuretls_session_clear_proxy(uintptr_t session_id);

// Certificate pinning functions
char* azuretls_session_add_pins(uintptr_t session_id, char* url, char* pins_json);
char* azuretls_session_clear_pins(uintptr_t session_id, char* url);

// Utility functions
char* azuretls_session_get_ip(uintptr_t session_id);
char* azuretls_session_get_cookies(uintptr_t session_id, char* url);
char* azuretls_version(void);

// Library lifecycle functions
void azuretls_init(void);
void azuretls_cleanup(void);

// Memory management functions
void azuretls_free_string(char* str);
void azuretls_free_response(CFfiResponse* resp);

#ifdef __cplusplus
}
#endif

#endif // AZURETLS_H
