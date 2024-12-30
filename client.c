#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define SERVER_IP "192.168.1.1"  // Remplacez par l'IP du serveur
#define PORT 4433

void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

SSL_CTX* create_context() {
    const SSL_METHOD *method = SSLv23_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

int main() {
    init_openssl();
    SSL_CTX *ctx = create_context();

    // Charger le certificat du serveur pour la vérification
    if (!SSL_CTX_load_verify_locations(ctx, "server.crt", NULL)) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    inet_pton(AF_INET, SERVER_IP, &addr.sin_addr);

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Connection failed");
        exit(EXIT_FAILURE);
    }

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);

    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    printf("Connected to the server successfully!\n");

    // Communication entre le client et le serveur
    char buffer[1024];
    while (1) {
        printf("Enter message to send to server: ");
        fgets(buffer, sizeof(buffer), stdin);
        buffer[strcspn(buffer, "\n")] = 0; // Supprimer le saut de ligne

        if (strcmp(buffer, "exit") == 0) {
            printf("Exiting...\n");
            break;
        }

        SSL_write(ssl, buffer, strlen(buffer));

        memset(buffer, 0, sizeof(buffer));
        SSL_read(ssl, buffer, sizeof(buffer));
        printf("Server: %s\n", buffer);
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);
    EVP_cleanup();

    return 0;
}
