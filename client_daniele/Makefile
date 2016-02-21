CC = gcc
CFLAGS = -Wall -Werror -lcrypto

client: client.c
	$(CC) -o client client.c client_function.c client_hdr.h $(CFLAGS) 

.PHONY: clean
clean:
	-rm -f client client.o *~
