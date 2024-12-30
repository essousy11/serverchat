#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define PORT 4433

void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

SSL_CTX* create_context() {
    const SSL_METHOD *method = SSLv23_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

void configure_context(SSL_CTX *ctx) {
    if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

int main() {
    int sock;
    struct sockaddr_in addr;

    init_openssl();
    SSL_CTX *ctx = create_context();
    configure_context(ctx);

    sock = socket(AF_INET, SOCK_STREAM, 0);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    bind(sock, (struct sockaddr*)&addr, sizeof(addr));
    listen(sock, 1);

    printf("Server is listening on port %d...\n", PORT);

    int client = accept(sock, NULL, NULL);
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, client);
    SSL_accept(ssl);

    char buffer[1024] = {0};
    SSL_read(ssl, buffer, sizeof(buffer));
    printf("Client message: %s\n", buffer);

    SSL_write(ssl, "Hello from server!", strlen("Hello from server!"));

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client);
    close(sock);
    SSL_CTX_free(ctx);
    EVP_cleanup();

    return 0;
}
