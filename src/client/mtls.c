#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>

#define BUFFER_SIZE 4096
#define VERBOSE

#ifdef VERBOSE
    #define DEBUG_PRINT(fmt, ...) \
        do { \
            fprintf(stderr, "DEBUG: " fmt "\n", ##__VA_ARGS__); \
        } while (0)
#else
    // No-op if VERBOSE is not defined
    #define DEBUG_PRINT(fmt, ...) \
        do { } while (0)
#endif
    

void handle_openssl_error() {
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

struct Memory {
    char *data;
    size_t size;
};

struct Memory global_mem;

int main() {
    const char *hostname = HOST;
    const int port = PORT;
    const char *request = "GET / HTTP/1.1\r\nHost: server\r\nConnection: close\r\n\r\n";

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    DEBUG_PRINT("Initialized OpenSSL successfully");

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        handle_openssl_error();
    }
    DEBUG_PRINT("Created SSL context successfully");

    if (SSL_CTX_use_certificate_file(ctx, "certs/client-cert.pem", SSL_FILETYPE_PEM) <= 0) {
        handle_openssl_error();
    }
    DEBUG_PRINT("Loaded client certificate successfully");

    if (SSL_CTX_use_PrivateKey_file(ctx, "certs/client-key.pem", SSL_FILETYPE_PEM) <= 0) {
        handle_openssl_error();
    }
    DEBUG_PRINT("Loaded client private key successfully");

    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match the certificate\n");
        exit(EXIT_FAILURE);
    }
    DEBUG_PRINT("Verified private key successfully");

    if (SSL_CTX_load_verify_locations(ctx, "certs/ca-cert.pem", NULL) <= 0) {
        handle_openssl_error();
    }
    DEBUG_PRINT("Loaded CA certificate successfully");

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    // Create a new SSL connection
    BIO *bio = BIO_new_ssl_connect(ctx);
    if (!bio) {
        handle_openssl_error();
    }
    DEBUG_PRINT("Created new SSL connection successfully");

    // Set hostname and port
    char *hostport;
    sprintf(hostport, "%s:%d", hostname, port);
    BIO_set_conn_hostname(bio, hostport);
    DEBUG_PRINT("Set hostname and port successfully");

    // Set SSL mode
    SSL *ssl = NULL;
    BIO_get_ssl(bio, &ssl);
    if (!ssl) {
        handle_openssl_error();
    }

    // Enable hostname verification
    SSL_set_tlsext_host_name(ssl, hostname);
    DEBUG_PRINT("Set hostname verification to: %s", hostname);

    if (BIO_do_connect(bio) <= 0) {
        fprintf(stderr, "Error connecting to server\n");
        handle_openssl_error();
    }
    DEBUG_PRINT("Connected to server successfully");

    if (BIO_do_handshake(bio) <= 0) {
        fprintf(stderr, "Error performing SSL/TLS handshake\n");
        handle_openssl_error();
    }
    DEBUG_PRINT("SSL/TLS handshake completed successfully");

    // Send the HTTPS request
    if (BIO_write(bio, request, strlen(request)) <= 0) {
        fprintf(stderr, "Error sending request\n");
        handle_openssl_error();
    }
    DEBUG_PRINT("Sent request successfully");

    // Read the response
    char buffer[BUFFER_SIZE];

    int bytes_read;
    
    while ((bytes_read = BIO_read(bio, buffer, BUFFER_SIZE - 1)) > 0) {
        buffer[bytes_read] = '\0'; // Null-terminate the buffer
        printf("%s", buffer);     // Print to stdout
        fprintf(output, "%s", buffer); // Write to the file
    }
    DEBUG_PRINT("Received response successfully");

    fclose(output);

    // Clean up
    BIO_free_all(bio);
    SSL_CTX_free(ctx);
    EVP_cleanup();

    return 0;
}
