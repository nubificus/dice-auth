#include <unistd.h>
#include <string.h>
#include <http.h>

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
	"Content-Length: 33\r\n"
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

void http_resp_405_not_allowed(int client_fd) {
	write(client_fd, HTTP_405_METHOD_NOT_ALLOWED,
	      strlen(HTTP_405_METHOD_NOT_ALLOWED));
}

void http_resp_401_unauthorized(int client_fd) {
	write(client_fd, HTTP_401_UNAUTHORIZED,
	      strlen(HTTP_401_UNAUTHORIZED));
}

void http_resp_200_ok(int client_fd) {
	write(client_fd, HTTP_200_OK, strlen(HTTP_200_OK));
}

char *http_post_extract_body(const char *request) {
	const char *body_start = strstr(request, "\r\n\r\n");
	if (body_start) {
		/* Move past "\r\n\r\n" */
		return strdup(body_start + 4);
	}
	return NULL;
}
