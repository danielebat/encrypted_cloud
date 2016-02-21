CC = gcc
CFLAGS = -Wall -Werror -lcrypto

server: server.c
	$(CC) -o server server.c server_functions.c server_hdr.h $(CFLAGS)

.PHONY: clean
clean:
	-rm -f server server.o *~
