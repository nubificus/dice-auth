#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <dice_auth.h>
#include <redis_query.h>
#include <http.h>

#define PORT 8000
#define BUFFER_SIZE 4096
#define UWAIT_MAX 2500000 /* "2.5 sec" */
#define USEC_SLEEP 100000 /* "100 ms" */

int main() {
	int server_fd, client_fd, i;
	struct sockaddr_in address;
	socklen_t addr_len = sizeof(address);
	char buffer[BUFFER_SIZE];

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

	address.sin_family = AF_INET;
	address.sin_addr.s_addr = INADDR_ANY;
	address.sin_port = htons(PORT);

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

	int nr_reqs = 0;
	while (1) {
		client_fd = accept(server_fd, (struct sockaddr *)&address, &addr_len);
		if (client_fd < 0) {
			perror("Accept failed");
			continue;
		}

		printf("[dice-auth]: New request - %d\n", ++nr_reqs);
		bool authorized = false;

		int flags = fcntl(client_fd, F_GETFL, 0);
		fcntl(client_fd, F_SETFL, flags | O_NONBLOCK);

		memset(buffer, 0, BUFFER_SIZE);
		int received = 0;
		int usec_wait = 0;
		while (received < BUFFER_SIZE - 1) {
			int bytes_read = read(client_fd, buffer + received, BUFFER_SIZE - received - 1);
			if (bytes_read > 0) {
				received += bytes_read;
				continue;
			}

			if (usec_wait >= UWAIT_MAX)
				break;
			usleep(USEC_SLEEP);
			usec_wait += USEC_SLEEP;
		}
		buffer[received] = '\0';

		char method[16] = { 0 };
		sscanf(buffer, "%s", method);
		if (strcmp(method, "POST") != 0) {
			http_resp_405_not_allowed(client_fd);
			close(client_fd);
			printf("  Wrong method - GET\n");
			printf("  Status: Not authorized\n");
			continue;
		}

		char *cert_body = http_post_extract_body(buffer);
		if (cert_body == NULL) {
			http_resp_401_unauthorized(client_fd);
			goto next;
		}

		#if DEBUG
		printf("Received Certificate:\n%s\n", cert_body);
		#endif

		int nr_roots;
		char **roots = redis_get_all_roots(&nr_roots);
		if (roots == NULL || nr_roots == 0) {
			http_resp_401_unauthorized(client_fd);
			free(cert_body);
			goto next;
		}

		for (i = 0; i < nr_roots; ++i) {
			if (dice_auth(roots[i], cert_body) == 0) {
				authorized = true;
				break;
			}
			#if DEBUG
			printf("  Root %d/%d does not verify client\n", i + 1, nr_roots);
			#endif
		}

		if (!authorized) {
			http_resp_401_unauthorized(client_fd);
			printf("  Status: Not authorized\n");
		} else {
			http_resp_200_ok(client_fd);
			printf("  Root %d/%d verifies client\n", i + 1, nr_roots);
			printf("  Status: Authorized!\n");
		}

		/* Cleanup */
		free(cert_body);
		for (int i = 0; i < nr_roots; ++i)
			free(roots[i]);
		free(roots);
next:
		close(client_fd);
	}

	close(server_fd);
	return 0;
}
