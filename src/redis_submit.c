#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <hiredis/hiredis.h>

char *read_file(const char *filename, size_t *out_len) {
	FILE *fp = fopen(filename, "rb");
	if (!fp) {
		perror("fopen");
		return NULL;
	}

	if (fseek(fp, 0, SEEK_END) != 0) {
		perror("fseek");
		fclose(fp);
		return NULL;
	}
	long size = ftell(fp);
	if (size < 0) {
		perror("ftell");
		fclose(fp);
		return NULL;
	}
	rewind(fp);

	char *buffer = malloc(size + 1);
	if (!buffer) {
		perror("malloc");
		fclose(fp);
		return NULL;
	}

	size_t read_size = fread(buffer, 1, size, fp);
	if (read_size != (size_t)size) {
		perror("fread");
		free(buffer);
		fclose(fp);
		return NULL;
	}
	buffer[size] = '\0';
	fclose(fp);

	if (out_len)
		*out_len = size;

	return buffer;
}

int main(int argc, char *argv[]) {
	if (argc != 7) {
		fprintf(stderr, "Usage: %s device_uuid path/to/root.pem "
				"device_type firmware_version firmware_type "
				"redis_ip\n", argv[0]);
		return 1;
	}

	const char *device_uuid      = argv[1];
	const char *pem_file_path    = argv[2];
	const char *device_type      = argv[3];
	const char *firmware_version = argv[4];
	const char *firmware_type    = argv[5];
	const char *redis_ip         = argv[6];

	size_t cert_len = 0;
	char *root_cert_value = read_file(pem_file_path, &cert_len);
	if (!root_cert_value) {
		fprintf(stderr, "Failed to read certificate file: %s\n", pem_file_path);
		return 1;
	}

	int port = 6379;
	redisContext *context = redisConnect(redis_ip, port);
	if (context == NULL || context->err) {
		if (context) {
			fprintf(stderr, "Connection error: %s\n", context->errstr);
			redisFree(context);
		} else {
			fprintf(stderr, "Connection error: can't allocate redis context\n");
		}
		free(root_cert_value);
		return 1;
	}

	/* Build the Redis key (e.g., "device:<device-uuid>") */
	char device_key[256];
	snprintf(device_key, sizeof(device_key), "device:%s", device_uuid);

	/* Use HSET to add the device entry */
	redisReply *reply = redisCommand(context,
		"HSET %s uuid %s root_cert %b device_type %s firmware_version %s firmware_type %s",
		device_key,
		device_uuid,
		root_cert_value, cert_len,
		device_type,
		firmware_version,
		firmware_type);

	if (reply == NULL) {
		fprintf(stderr, "Error executing HSET command.\n");
		redisFree(context);
		free(root_cert_value);
		return 1;
	}

	printf("HSET command executed: %s\n", reply->str ? reply->str : "OK");
	freeReplyObject(reply);

	/* Retrieve and print the stored root_cert to verify it was saved correctly */
	reply = redisCommand(context, "HGET %s root_cert", device_key);
	if (reply && reply->type == REDIS_REPLY_STRING) {
		printf("Retrieved root_cert:\n%s\n", reply->str);
	} else {
		printf("Error retrieving root_cert.\n");
	}
	freeReplyObject(reply);

	redisFree(context);
	free(root_cert_value);

	return 0;
}

