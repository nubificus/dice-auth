#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define PORT 8000
#define BUFFER_SIZE 4096

int auth(const char *cert) {
	return 1;
}

const char *HTTP_200_OK =
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: application/json\r\n"
    "Content-Length: 28\r\n"
    "Connection: close\r\n"
    "\r\n"
    "{\"status\": \"Certificate OK\"}";

const char *HTTP_401_UNAUTHORIZED =
    "HTTP/1.1 401 Unauthorized\r\n"
    "Content-Type: application/json\r\n"
    "Content-Length: 36\r\n"
    "Connection: close\r\n"
    "\r\n"
    "{\"status\": \"Certificate Invalid\"}";

const char *HTTP_405_METHOD_NOT_ALLOWED =
    "HTTP/1.1 405 Method Not Allowed\r\n"
    "Content-Type: text/plain\r\n"
    "Content-Length: 24\r\n"
    "Allow: POST\r\n"
    "Connection: close\r\n"
    "\r\n"
    "Only POST method allowed";


char *extract_body(const char *request) {
    const char *body_start = strstr(request, "\r\n\r\n");
    if (body_start) {
        return strdup(body_start + 4); // Move past "\r\n\r\n"
    }
    return NULL;
}

int main() {
    int server_fd, client_fd;
    struct sockaddr_in address;
    socklen_t addr_len = sizeof(address);
    char buffer[BUFFER_SIZE];

    // Create socket
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == -1) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }

    int opt = 1;

    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    // Set address properties
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    // Bind socket
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 5) < 0) {
        perror("Listen failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    printf("Server listening on port %d...\n", PORT);

    while (1) {
        // Accept client connection
        client_fd = accept(server_fd, (struct sockaddr *)&address, &addr_len);
        if (client_fd < 0) {
            perror("Accept failed");
            continue;
        }

        memset(buffer, 0, BUFFER_SIZE);
	int received = 0;
        while (received < BUFFER_SIZE - 1) {
            int bytes_read = read(client_fd, buffer + received, BUFFER_SIZE - received - 1);
            if (bytes_read <= 0)
		    break;
            received += bytes_read;
        }
        buffer[received] = '\0';

        //read(client_fd, buffer, BUFFER_SIZE - 1);

	char method[16] = { 0 };
	sscanf(buffer, "%s", method);
        printf("Received request: %s\n", method);

        if (strcmp(method, "POST") != 0) {
            write(client_fd, HTTP_405_METHOD_NOT_ALLOWED, strlen(HTTP_405_METHOD_NOT_ALLOWED));
            close(client_fd);
            continue;
        }

        char *cert_body = extract_body(buffer);
        if (cert_body) {
            printf("Received Certificate:\n%s\n", cert_body);

            int result = auth(cert_body);

            if (result) {
                write(client_fd, HTTP_200_OK, strlen(HTTP_200_OK));
            } else {
                write(client_fd, HTTP_401_UNAUTHORIZED, strlen(HTTP_401_UNAUTHORIZED));
            }

            free(cert_body);
        } else {
            write(client_fd, HTTP_401_UNAUTHORIZED, strlen(HTTP_401_UNAUTHORIZED));
        }

        // Close connection
        close(client_fd);
    }

    close(server_fd);
    return 0;
}

