#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../azuretls.h"

void print_response(CFfiResponse* resp) {
    if (!resp) {
        printf("Response is NULL\n");
        return;
    }

    if (resp->error) {
        printf("Error: %s\n", resp->error);
        return;
    }

    printf("Status Code: %d\n", resp->status_code);

    if (resp->url) {
        printf("URL: %s\n", resp->url);
    }

    if (resp->headers) {
        printf("Headers: %s\n", resp->headers);
    }

    if (resp->body && resp->body_len > 0) {
        printf("Body Length: %d\n", resp->body_len);
        printf("Body: %.200s%s\n", resp->body,
               resp->body_len > 200 ? "..." : "");
    }

    printf("----------------------------------------\n");
}

int main() {
    printf("AzureTLS C Example\n");
    printf("==================\n\n");

    // Initialize the library
    azuretls_init();

    // Print library version
    char* version = azuretls_version();
    if (version) {
        printf("Library Version: %s\n\n", version);
        azuretls_free_string(version);
    }

    // Create session configuration
    const char* config_json = "{"
        "\"browser\": \"chrome\","
        "\"user_agent\": \"AzureTLS-C-Example/1.0\","
        "\"timeout_ms\": 30000,"
        "\"max_redirects\": 10"
    "}";

    // Create session
    uintptr_t session = azuretls_session_new((char*)config_json);
    if (session == 0) {
        printf("Failed to create session\n");
        return 1;
    }

    printf("Session created successfully\n\n");

    // Example 1: Simple GET request
    printf("1. Simple GET Request\n");
    printf("--------------------\n");

    const char* get_request = "{"
        "\"method\": \"GET\","
        "\"url\": \"https://httpbin.org/get\""
    "}";

    CFfiResponse* response = azuretls_session_do(session, (char*)get_request);
    print_response(response);
    azuretls_free_response(response);

    // Example 2: POST request with JSON body
    printf("2. POST Request with JSON\n");
    printf("-------------------------\n");

    const char* post_request = "{"
        "\"method\": \"POST\","
        "\"url\": \"https://httpbin.org/post\","
        "\"body\": \"{\\\"message\\\": \\\"Hello from AzureTLS C!\\\"}\","
        "\"headers\": {"
            "\"Content-Type\": \"application/json\""
        "}"
    "}";

    response = azuretls_session_do(session, (char*)post_request);
    print_response(response);
    azuretls_free_response(response);

    // Example 3: Custom headers with specific order
    printf("3. Custom Ordered Headers\n");
    printf("-------------------------\n");

    const char* headers_request = "{"
        "\"method\": \"GET\","
        "\"url\": \"https://httpbin.org/headers\","
        "\"ordered_headers\": ["
            "[\"User-Agent\", \"Custom-Agent/1.0\"],"
            "[\"Accept\", \"application/json\"],"
            "[\"X-Custom-Header\", \"CustomValue\"]"
        "]"
    "}";

    response = azuretls_session_do(session, (char*)headers_request);
    print_response(response);
    azuretls_free_response(response);

    // Example 4: Apply JA3 fingerprint
    printf("4. JA3 Fingerprinting\n");
    printf("---------------------\n");

    const char* ja3 = "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0";
    char* ja3_error = azuretls_session_apply_ja3(session, (char*)ja3, "chrome");

    if (ja3_error) {
        printf("JA3 Error: %s\n", ja3_error);
        azuretls_free_string(ja3_error);
    } else {
        printf("JA3 fingerprint applied successfully\n");

        // Test the fingerprint
        const char* ja3_test_request = "{"
            "\"method\": \"GET\","
            "\"url\": \"https://tls.peet.ws/api/all\""
        "}";

        response = azuretls_session_do(session, (char*)ja3_test_request);
        if (response && !response->error) {
            printf("TLS fingerprint test successful (Status: %d)\n", response->status_code);
        } else if (response && response->error) {
            printf("TLS fingerprint test failed: %s\n", response->error);
        }
        azuretls_free_response(response);
    }
    printf("\n");

    // Example 5: Apply HTTP/2 fingerprint
    printf("5. HTTP/2 Fingerprinting\n");
    printf("------------------------\n");

    const char* http2_fp = "1:65536,2:0,3:1000,4:6291456,6:262144|15663105|0|m,s,a,p";
    char* http2_error = azuretls_session_apply_http2(session, (char*)http2_fp);

    if (http2_error) {
        printf("HTTP/2 Error: %s\n", http2_error);
        azuretls_free_string(http2_error);
    } else {
        printf("HTTP/2 fingerprint applied successfully\n");
    }
    printf("\n");

    // Example 6: Force HTTP/1.1
    printf("6. Force HTTP/1.1\n");
    printf("-----------------\n");

    const char* http1_request = "{"
        "\"method\": \"GET\","
        "\"url\": \"https://httpbin.org/get\","
        "\"force_http1\": true"
    "}";

    response = azuretls_session_do(session, (char*)http1_request);
    print_response(response);
    azuretls_free_response(response);

    // Example 7: Timeout and error handling
    printf("7. Timeout Test\n");
    printf("---------------\n");

    const char* timeout_request = "{"
        "\"method\": \"GET\","
        "\"url\": \"https://httpbin.org/delay/2\","
        "\"timeout_ms\": 1000"
    "}";

    response = azuretls_session_do(session, (char*)timeout_request);
    if (response && response->error) {
        printf("Expected timeout error: %s\n", response->error);
    } else {
        printf("Request completed (Status: %d)\n", response ? response->status_code : -1);
    }
    azuretls_free_response(response);
    printf("\n");

    // Example 8: SSL Pinning (commented out as it's just an example)
    /*
    printf("8. SSL Pinning Example\n");
    printf("----------------------\n");

    const char* pins_json = "["
        "\"j5bzD/UjYVE+0feXsngcrVs3i1vSaoOOtPgpLBb9Db8=\","
        "\"18tkPyr2nckv4fgo0dhAkaUtJ2hu2831xlO2SKhq8dg=\""
    "]";

    char* pin_error = azuretls_session_add_pins(session, "https://httpbin.org", (char*)pins_json);
    if (pin_error) {
        printf("Pin Error: %s\n", pin_error);
        azuretls_free_string(pin_error);
    } else {
        printf("SSL pins added successfully\n");

        // Clear pins
        char* clear_error = azuretls_session_clear_pins(session, "https://httpbin.org");
        if (clear_error) {
            printf("Clear pins error: %s\n", clear_error);
            azuretls_free_string(clear_error);
        } else {
            printf("SSL pins cleared successfully\n");
        }
    }
    printf("\n");
    */

    // Example 9: Get IP address
    printf("9. Get Public IP\n");
    printf("----------------\n");

    char* ip = azuretls_session_get_ip(session);
    if (ip) {
        if (strncmp(ip, "error:", 6) == 0) {
            printf("IP Error: %s\n", ip);
        } else {
            printf("Public IP: %s\n", ip);
        }
        azuretls_free_string(ip);
    } else {
        printf("Failed to get IP address\n");
    }
    printf("\n");

    // Clean up
    printf("Cleaning up...\n");
    azuretls_session_close(session);
    azuretls_cleanup();

    printf("Example completed successfully!\n");

    return 0;
}