#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <hiredis/hiredis.h>
#include <redis_query.h>

#define ENV_REDIS_IP   "REDIS_HOST"
#define ENV_REDIS_IP_2 "REDIS_SERVICE_SERVICE_HOST"

const char *localhost = "127.0.0.1";

char* get_redis_ip() {
	static char *redis_ip = NULL;

	if (redis_ip == NULL) {
		redis_ip = getenv(ENV_REDIS_IP);
		if (redis_ip != NULL) {
			printf("Using Redis IP from %s: %s\n", ENV_REDIS_IP, redis_ip);
			goto out;
		}

		redis_ip = getenv(ENV_REDIS_IP_2);
		if (redis_ip != NULL) {
			printf("Using Redis IP from %s: %s\n", ENV_REDIS_IP_2, redis_ip);
			goto out;
		}

		printf("Could not read Redis IP address from"
		       " environment\n(%s or %s)\nUsing localhost"
		       " instead.\n", ENV_REDIS_IP, ENV_REDIS_IP_2);
		redis_ip = (char *)localhost;
	}
out:
	return redis_ip;
}

char** redis_get_all_roots(int *nr_certs) {
	redisContext *context = redisConnect(get_redis_ip(), 6379);
	if (context == NULL || context->err) {
		if (context) {
			fprintf(stderr, "Redis connection error: %s\n", context->errstr);
			redisFree(context);
		} else {
			fprintf(stderr, "Redis connection error: cannot allocate context\n");
		}
	*nr_certs = 0;
	return NULL;
	}

	/* Retrieve all keys */
	redisReply *keysReply = redisCommand(context, "KEYS *");
	if (keysReply == NULL || keysReply->type != REDIS_REPLY_ARRAY) {
		fprintf(stderr, "Error retrieving device keys.\n");
		if(keysReply)
			freeReplyObject(keysReply);
		redisFree(context);
		*nr_certs = 0;
		return NULL;
	}

	int numKeys = keysReply->elements;

	char **certs = malloc(numKeys * sizeof(char *));
	if (!certs) {
		perror("malloc");
		freeReplyObject(keysReply);
		redisFree(context);
		*nr_certs = 0;
		return NULL;
	}

	int count = 0;
	for (size_t i = 0; i < keysReply->elements; i++) {
		/* For each device key, retrieve the root_cert field */
		redisReply *certReply = redisCommand(context, "HGET %s root_cert", keysReply->element[i]->str);
		if (certReply && certReply->type == REDIS_REPLY_STRING) {
			certs[count] = strdup(certReply->str);
			if (!certs[count]) {
				perror("strdup");
				/* Free previous entries on error */
				for (int j = 0; j < count; j++)
					free(certs[j]);
				free(certs);
				freeReplyObject(certReply);
				freeReplyObject(keysReply);
				redisFree(context);
				*nr_certs = 0;
				return NULL;
			}
			count++;
		}
		if (certReply)
			freeReplyObject(certReply);
	}

	freeReplyObject(keysReply);
	redisFree(context);

	*nr_certs = count;
	return certs;
}
