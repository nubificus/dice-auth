C_FLAGS = -c -Wall -DDEBUG

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

GEN_SRC = $(DICE_SRC) src/gen_cert.c
GEN_OBJ = $(DICE_OBJ) gen_cert.o
GEN_OUT = gen_cert

SUBMIT_SRC = $(DICE_SRC) src/redis_submit.c
SUBMIT_OBJ = $(DICE_OBJ) redis_submit.o
SUBMIT_OUT = submit

DEL_SRC = src/redis_delete.c
DEL_OBJ = redis_delete.o
DEL_OUT = del

LS_SRC = src/redis_ls.c
LS_OBJ = redis_ls.o
LS_OUT = list

CLEAN = $(AUTH_OUT) $(SUBMIT_OUT) $(DEL_OUT) $(LS_OUT) *.o

MBEDTLS_LIBS = mbedtls/library/libmbedtls.a mbedtls/library/libmbedx509.a mbedtls/library/libmbedcrypto.a

.PHONY: all clean dice_auth submit delete ls mbedtls run

all: dice_auth submit delete ls gen_cert

all_static: submit_static delete_static ls_static gen_cert_static

mbedtls: $(MBEDTLS_LIBS)

JOBS := $(shell nproc)

$(MBEDTLS_LIBS):
	@if [ ! -f mbedtls/library/libmbedtls.a ]; then \
		echo "Initializing submodules..."; \
		git submodule update --init --recursive; \
	fi
	@echo "Building mbedtls..."
	$(MAKE) -C mbedtls -j$(JOBS)

dice_auth:
	$(CC) $(C_FLAGS) $(AUTH_SRC) $(INCLUDE)
	$(CC) -o $(AUTH_OUT) $(AUTH_OBJ) $(OPENSSL_LD) $(REDIS_LD)
	rm -f *.o

gen_cert: mbedtls
	$(CC) $(C_FLAGS) $(GEN_SRC) $(INCLUDE) $(MBEDTLS_INCLUDE)
	$(CC) -o $(GEN_OUT) $(GEN_OBJ) $(MBEDTLS_LD) $(OPENSSL_LD)
	rm -f *.o

submit: mbedtls
	$(CC) $(C_FLAGS) $(SUBMIT_SRC) $(INCLUDE) $(MBEDTLS_INCLUDE)
	$(CC) -o $(SUBMIT_OUT) $(SUBMIT_OBJ) $(MBEDTLS_LD) $(REDIS_LD) $(OPENSSL_LD)
	rm -f *.o

delete:
	$(CC) $(C_FLAGS) $(DEL_SRC)
	$(CC) -o $(DEL_OUT) $(DEL_OBJ) $(REDIS_LD)
	rm -f *.o

ls:
	$(CC) $(C_FLAGS) $(LS_SRC)
	$(CC) -o $(LS_OUT) $(LS_OBJ) $(REDIS_LD)
	rm -f *.o

submit_static: mbedtls
	$(CC) $(C_FLAGS) $(SUBMIT_SRC) $(INCLUDE) $(MBEDTLS_INCLUDE)
	$(CC) -o $(SUBMIT_OUT) $(SUBMIT_OBJ) $(MBEDTLS_LD) $(REDIS_LD) $(OPENSSL_LD) -static
	rm -f *.o

delete_static:
	$(CC) $(C_FLAGS) $(DEL_SRC)
	$(CC) -o $(DEL_OUT) $(DEL_OBJ) $(REDIS_LD) -static
	rm -f *.o

ls_static:
	$(CC) $(C_FLAGS) $(LS_SRC)
	$(CC) -o $(LS_OUT) $(LS_OBJ) $(REDIS_LD) -static
	rm -f *.o

gen_cert_static:
	$(CC) $(C_FLAGS) $(GEN_SRC) $(INCLUDE) $(MBEDTLS_INCLUDE)
	$(CC) -o $(GEN_OUT) $(GEN_OBJ) $(MBEDTLS_LD) $(OPENSSL_LD)  -static
	rm -f *.o

run:
	./auth 2>/dev/null

clean:
	rm -f $(CLEAN)

