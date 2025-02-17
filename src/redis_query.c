#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <hiredis/hiredis.h>
#include <redis_query.h>

char** redis_get_all_roots(int *nr_certs) {
	redisContext *context = redisConnect("127.0.0.1", 6379);
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

	/* Retrieve all keys matching "device:*" */
	redisReply *keysReply = redisCommand(context, "KEYS device:*");
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
