C_FLAGS = -c -Wall

INCLUDE = -Isrc/include

MBEDTLS_INCLUDE = -Imbedtls/include
MBEDTLS_LD = -Lmbedtls/library/ -lmbedtls -lmbedx509 -lmbedcrypto

OPENSSL_LD = -lssl -lcrypto
REDIS_LD = -lhiredis

AUTH_SRC = src/http.c src/dice_auth.c src/redis_query.c src/main.c
AUTH_OBJ = main.o dice_auth.o redis_query.o http.o
AUTH_OUT = auth

DICE_SRC = src/clear_memory.c src/dice.c src/mbedtls_ops.c src/utils.c
DICE_OBJ = clear_memory.o dice.o mbedtls_ops.o utils.o

SUBMIT_SRC = $(DICE_SRC) src/redis_submit.c
SUBMIT_OBJ = $(DICE_OBJ) redis_submit.o
SUBMIT_OUT = submit

CLEAN = $(AUTH_OUT) $(SUBMIT_OUT) *.o

dice_auth:
	$(CC) $(C_FLAGS) $(AUTH_SRC) $(INCLUDE)
	$(CC) -o $(AUTH_OUT) $(AUTH_OBJ) $(OPENSSL_LD) $(REDIS_LD)
	rm -f *.o

run:
	./auth 2>/dev/null

submit:
	$(CC) $(C_FLAGS) $(SUBMIT_SRC) $(INCLUDE) $(MBEDTLS_INCLUDE)
	$(CC) -o $(SUBMIT_OUT) $(SUBMIT_OBJ) $(MBEDTLS_LD) $(REDIS_LD) $(OPENSSL_LD)
	rm -f *.o

clean:
	rm -f $(CLEAN)
