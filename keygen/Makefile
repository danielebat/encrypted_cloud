CC = gcc
CFLAGS = -Wall -Werror -lcrypto

keygen: keygen.c
	$(CC) -o keygen keygen.c  $(CFLAGS) 

.PHONY: clean
clean:
	-rm -f keygen keygen.o *~
