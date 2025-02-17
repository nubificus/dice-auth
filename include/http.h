#pragma once

void http_resp_405_not_allowed(int client_fd);
void http_resp_401_unauthorized(int client_fd);
void http_resp_200_ok(int client_fd);
char *http_post_extract_body(const char *request);
