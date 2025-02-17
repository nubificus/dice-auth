dice_auth:
	gcc -c src/http.c -Iinclude
	gcc -c src/dice_auth.c -Iinclude
	gcc -c src/redis_query.c -Iinclude
	gcc -c src/main.c -Iinclude
	gcc -o auth main.o dice_auth.o redis_query.o http.o -lssl -lcrypto -lhiredis
	rm -f *.o

run:
	./auth 2>/dev/null

submit:
	gcc -o submit src/redis_submit.c -lhiredis

clean:
	rm -f auth submit
	rm -f *.o
