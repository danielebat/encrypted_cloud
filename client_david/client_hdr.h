#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/des.h>
#include <openssl/pem.h>
#include <fcntl.h>
#include <errno.h>
#define path_usr_file "file/"
#define SA struct sockaddr
#define DIM_CMD 32
#define flushStdIN while ((getchar()) != '\n')
#define KEY_SIZE EVP_CIPHER_key_length(EVP_des_ecb())
#define PATH_FOR_KEY "./key/"

int readKey (unsigned char * key, int maxlength, const char * fk);
int send_file_crypt( const char* file_name, int sk, unsigned char* session_key, int session_key_len );
int ask_for_the_list(int sk, unsigned char* session_key, int session_key_len);
int recv_file_crypt( const char* file_name, int sk, unsigned char* session_key, int session_key_len );
int rmv_file(const char* file_name, int sk, unsigned char* session_key, int session_key_len);
int send_message(unsigned char* mex, int sk, unsigned char* session_key, int session_key_len);
int start_protocol(int sk, unsigned char** session_key, int * session_key_len, char*argv[]);
