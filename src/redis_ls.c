#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

#include <openssl/pem.h>
#include <openssl/err.h>
#include <hiredis/hiredis.h>

const int port = 6379;
const char *localhost = "127.0.0.1";

int main(int argc, char *argv[]) {
	if (argc != 1 && argc != 2) {
		fprintf(stderr, "Usage: %s [redis_ip]\n", argv[0]);
		return 1;
	}

	const char *redis_ip = (argc == 2) ? argv[1] : localhost;
	if (argc == 1)
		printf("Redis IP not provided.. Assuming localhost\n");

	redisContext *context = redisConnect(redis_ip, port);
	if (context == NULL || context->err) {
		if (context) {
			fprintf(stderr, "Connection error: %s\n", context->errstr);
			redisFree(context);
		} else {
			fprintf(stderr, "Connection error: can't allocate redis context\n");
		}
		return 1;
	}

	redisReply *reply = redisCommand(context, "KEYS *");

	if (reply == NULL) {
		fprintf(stderr, "Error executing KEYS command.\n");
		redisFree(context);
		return 1;
	}

	if (reply->type == REDIS_REPLY_ARRAY) {
		for (size_t i = 0; i < reply->elements; i++)
			printf("Key %zu: %s\n", i + 1, reply->element[i]->str);
	} else {
		printf("Unexpected reply type: %d\n", reply->type);
	}

	freeReplyObject(reply);
	redisFree(context);
	return 0;
}
