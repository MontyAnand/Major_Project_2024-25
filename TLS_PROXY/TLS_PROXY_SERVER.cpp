#include <iostream>
#include <cstring>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netinet/in.h>  // For sockaddr_in and SOL_IP
#include <linux/netfilter_ipv4.h>  // For SO_ORIGINAL_DST

#define PROXY_PORT 4433
#define BUFFER_SIZE 1024*1024

// Initialize OpenSSL
void initialize_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

// Cleanup OpenSSL
void cleanup_openssl() {
    EVP_cleanup();
}

// Create SSL context for proxy
SSL_CTX* create_ssl_context(const SSL_METHOD* method) {
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

// Configure SSL context with certificate and private key
void configure_ssl_context(SSL_CTX* ctx, const char* cert_file, const char* key_file) {
    if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

// Retrieve original destination using SO_ORIGINAL_DST
sockaddr_in get_original_destination(int client_sock) {
    sockaddr_in orig_dst{};
    socklen_t len = sizeof(orig_dst);

    if (getsockopt(client_sock, SOL_IP, SO_ORIGINAL_DST, &orig_dst, &len) < 0) {
        perror("getsockopt(SO_ORIGINAL_DST) failed");
        exit(EXIT_FAILURE);
    }
    return orig_dst;
}

// Connect to the original destination
int connect_to_target(const sockaddr_in& orig_dst) {
    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0) {
        perror("Socket creation failed");
        return -1;
    }

    if (connect(server_sock, (struct sockaddr*)&orig_dst, sizeof(orig_dst)) < 0) {
        perror("Connection to target server failed");
        close(server_sock);
        return -1;
    }

    return server_sock;
}

// Handle client connection
void handle_client_connection(int client_sock, SSL_CTX* client_ctx, SSL_CTX* server_ctx) {
    // SSL connection with the client
    SSL* client_ssl = SSL_new(client_ctx);
    SSL_set_fd(client_ssl, client_sock);
    if (SSL_accept(client_ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(client_ssl);
        close(client_sock);
        return;
    }

    // Retrieve the original destination
    sockaddr_in orig_dst = get_original_destination(client_sock);

    // Connect to the original destination
    int server_sock = connect_to_target(orig_dst);
    if (server_sock < 0) {
        SSL_free(client_ssl);
        close(client_sock);
        return;
    }

    // SSL connection with the original server
    SSL* server_ssl = SSL_new(server_ctx);
    SSL_set_fd(server_ssl, server_sock);
    if (SSL_connect(server_ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(client_ssl);
        SSL_free(server_ssl);
        close(client_sock);
        close(server_sock);
        return;
    }

    // Data forwarding between client and server
    char buffer[BUFFER_SIZE];
    int bytes_read = SSL_read(client_ssl, buffer, sizeof(buffer));
    while (true) {
        
        if (bytes_read <= 0) break;
        SSL_write(server_ssl, buffer, bytes_read);

        bytes_read = SSL_read(server_ssl, buffer, sizeof(buffer));
        if (bytes_read <= 0) break;
        std::cout<<buffer<<std::endl;
        SSL_write(client_ssl, buffer, bytes_read);
    }

    // Cleanup
    SSL_free(client_ssl);
    SSL_free(server_ssl);
    close(client_sock);
    close(server_sock);
}

int main() {
    initialize_openssl();

    // Create SSL contexts
    SSL_CTX* client_ctx = create_ssl_context(TLS_server_method());
    SSL_CTX* server_ctx = create_ssl_context(TLS_client_method());

    // Configure client context with certificate and private key
    configure_ssl_context(client_ctx, "www_google_com.crt", "www_google_com.key");

    // Create a listening socket
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(PROXY_PORT);

    if (bind(listener, (struct sockaddr*)&addr, sizeof(addr)) < 0 ||
        listen(listener, SOMAXCONN) < 0) {
        perror("Bind or listen failed");
        exit(EXIT_FAILURE);
    }

    std::cout << "Transparent TLS Proxy listening on port " << PROXY_PORT << std::endl;

    while (true) {
        int client_sock = accept(listener, nullptr, nullptr);
        if (client_sock < 0) {
            perror("Client accept failed");
            continue;
        }
        else std::cout<<"Request received from client\n";
        // Handle the client connection
        handle_client_connection(client_sock, client_ctx, server_ctx);
    }

    close(listener);
    SSL_CTX_free(client_ctx);
    SSL_CTX_free(server_ctx);
    cleanup_openssl();
    return 0;
}

