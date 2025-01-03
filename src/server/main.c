#include <arpa/inet.h>
#include <net/if.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include "server.h"

#define DEFAULT_PORT 8443
#define CERT_FILE "./certs/server-cert.pem"
#define KEY_FILE "./certs/server-key.pem"
#define CA_FILE "./certs/ca-cert.pem"
#define DEFAULT_BINNAME "dylight_server"

const char *file_to_serve = "./downloads/file.txt";

void initialize_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl() {
    EVP_cleanup();
}

SSL_CTX *create_context() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_server_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("[ERROR] Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

void configure_context(SSL_CTX *ctx) {
    SSL_CTX_set_ecdh_auto(ctx, 1);

    int error_flag = 0;

    if (SSL_CTX_use_certificate_file(ctx, CERT_FILE, SSL_FILETYPE_PEM) <= 0) {
        #ifdef VERBOSE
        ERR_print_errors_fp(stderr);
        #endif
        perror("[ERROR] Unable to set certificate");
        error_flag = 1;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, SSL_FILETYPE_PEM) <= 0 ) {
        #ifdef VERBOSE
        ERR_print_errors_fp(stderr);
        #endif
        perror("[ERROR] Unable to set private key");
        error_flag = 1;
    }

    if (SSL_CTX_load_verify_locations(ctx, CA_FILE, NULL) <= 0) {
        #ifdef VERBOSE
        ERR_print_errors_fp(stderr);
        #endif
        perror("[ERROR] Unable to set CA file");
        error_flag = 1;
    }

    if (error_flag) {
        exit(EXIT_FAILURE);
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    SSL_CTX_set_verify_depth(ctx, 1);
}

void serve_file(SSL *ssl) {
    FILE *file = fopen(file_to_serve, "rb");

    char buffer[1024];
    int bytes;
    while ((bytes = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        SSL_write(ssl, buffer, bytes);
    }

    fclose(file);
}

void print_help() {
    printf("Usage: ./" DEFAULT_BINNAME " -p <port> -f <file>\n"
           "Options:\n"
           "\t-h, --help\t\tShow this help message and exit\n"
           "\t-p PORT, --port=PORT\tPort to listen on\n"
           "\t-f FILE, --file=FILE\tFile to serve\n"
        //    "\t-i INTERFACE, --interface=INTERFACE\tInterface to listen on\n"
           "\n"
           "Requires the following certificates to be created and placed\n"
           "in the ./certs/ directory:\n"
           "\t- server-cert.pem\n"
           "\t- server-key.pem\n"
           "\t- ca-cert.pem\n\n"
           "You can generate these certificates using the following commands:\n"
           "\tmake test-certs\n");
}

void parse_arguments(Arguments *args, int argc, char *argv[]) {
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_help();
            exit(EXIT_SUCCESS);
        } 
        else if (strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "--interface") == 0) {
            if (i + 1 < argc) {
                printf("Interfaces not implemented yet...\n"
                        "Exiting...\n");
                exit(EXIT_FAILURE);
                // args->arg1 = argv[i + 1];
                // args->flags |= 1;
            } else {
                printf("Interfaces not implemented yet...\n"
                        "Exiting...\n");
                // fprintf(stderr, "[ERROR] No interface specified\n"
                //                 "Usage: ./" DEFAULT_BINNAME " -p <port> -f <file>\n");
                //                 // "Usage: ./" DEFAULT_BINNAME " -p <port> -f <file> [-i <interface>]\n");
                exit(EXIT_FAILURE);
            }
        } 
        else if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--port") == 0) {
            if (i + 1 < argc) {
                args->arg2 = atoi(argv[i + 1]);
                args->flags |= 2;
            } else {
                fprintf(stderr, "[ERROR] -p used, but no port specified\n"
                                "Usage: ./" DEFAULT_BINNAME " -p <port> -f <file>\n");
                                // "Usage: ./" DEFAULT_BINNAME " -p <port> -f <file> [-i <interface>]\n");
                exit(EXIT_FAILURE);
            }
        } else if (strcmp(argv[i], "-f") == 0 || strcmp(argv[i], "--file") == 0) {
            if (i + 1 < argc) {
                args->arg3 = argv[i + 1];
                args->flags |= 4;
            } else {
                fprintf(stderr, "[ERROR] -f used, but no file specified\n"
                                "Usage: ./" DEFAULT_BINNAME " -p <port> -f <file>\n");                  
                                // "Usage: ./" DEFAULT_BINNAME " -p <port> -f <file> [-i <interface>]\n");  
                exit(EXIT_FAILURE);
            }
        }
    }
}

void file_check() {
    if (access(file_to_serve, F_OK) == -1) {
        fprintf(stderr, "[ERROR] File %s does not exist\n", file_to_serve);
        exit(EXIT_FAILURE);
    } else if (access(file_to_serve, R_OK) == -1) {
        fprintf(stderr, "[ERROR] You do not have permission to read %s!\n", file_to_serve);
        exit(EXIT_FAILURE);
    }
}

// PLACEHOLDER LINE LOCATOR -- MAIN*MAIN*MAIN*MAIN*MAIN*MAIN
int main(int argc, char **argv) {
    int port = DEFAULT_PORT;
    const char *interface = NULL;
    Arguments args;
    parse_arguments(&args, argc, argv);
    
    if (args.flags & ARG_PORT) {
        printf("Starting server on port: %d\n", args.arg2);
        port = args.arg2;
    } else {
        printf("No port specified, using default port: %d\n", DEFAULT_PORT);
    }

    if (args.flags & ARG_FILE) {
        printf("Serving file: %s\n", args.arg3);
        file_to_serve = args.arg3;
        file_check();
    } else {
        printf("No file specified, serving default: %s\n", file_to_serve);
        file_check();
    }

    // Will be implemented later //
    // if (args.flags & ARG_INTERFACE) {
    //     printf("Listening on interface: %s\n", args.arg1);
    //     interface = args.arg1;
    // } else {
    //     printf("Listening on all interfaces\n");
    // }

    int sock;
    struct sockaddr_in addr;
    SSL_CTX *ctx;

    initialize_openssl();
    ctx = create_context();
    configure_context(ctx);

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Unable to bind");
        exit(EXIT_FAILURE);
    }

    if (listen(sock, 1) < 0) {
        fprintf(stderr, "Unable to listen on sock %d", sock);
        exit(EXIT_FAILURE);
    }

    while (1) {
        struct sockaddr_in addr;
        unsigned int len = sizeof(addr);
        SSL *ssl;

        int client = accept(sock, (struct sockaddr*)&addr, &len);
        if (client < 0) {
            perror("Unable to accept");
            exit(EXIT_FAILURE);
        }

        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client);

        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
        } else {
            serve_file(ssl);
        }

        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client);
    }

    close(sock);
    SSL_CTX_free(ctx);
    cleanup_openssl();
}