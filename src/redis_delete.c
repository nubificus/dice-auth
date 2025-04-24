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
	if (argc != 2 && argc != 3) {
		fprintf(stderr, "Usage: %s unique_device_secret [redis_ip]\n", argv[0]);
		return 1;
	}

	const char *mac_uds  = argv[1];
	const char *redis_ip = (argc == 3) ? argv[2] : localhost;
	if (argc == 2)
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

	/* Use DEL to delete the device entry */
	redisReply *reply = redisCommand(context, "DEL %s", mac_uds);

	if (reply == NULL) {
		fprintf(stderr, "Error executing DEL command.\n");
		redisFree(context);
		return 1;
	}

	if (reply->type == REDIS_REPLY_INTEGER && reply->integer == 1) {
		printf("Key deleted successfully.\n");
	} else {
		printf("Key did not exist.\n");
	}

	freeReplyObject(reply);
	redisFree(context);
	return 0;
}

