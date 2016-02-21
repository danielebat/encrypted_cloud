#include <stdio.h>
#include <stdlib.h>
#include <stdlib.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/des.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <errno.h>
#define SA struct sockaddr
#define BACKLOG_SIZE 64
#define SRV_ADDR "127.0.0.1" 
#define PROTOCOL_START 1
#define PROTOCOL_END 0
#define KEY_SIZE EVP_CIPHER_key_length(EVP_des_ecb())		/* The key length for both session and long term key */

/* Struct client to preserve informations*/  
struct client_info{
    	int socket_fd; 					/* socket descriptor of the user */
    	char* Name; 					/* Name of the user */
    	char* usr_dir; 					/* initially empty */
    	unsigned char* session_key; 		/* session key Kab' */
    	unsigned char* Nb; 			/* Nonce generated by the server */ 
   	unsigned char* Na; 			/* Nonce generated by the user*/
    	EVP_CIPHER_CTX* session_ctx;  	/* Context CTX for the session */
    	EVP_CIPHER_CTX* ctx;          		/* Context CTX with long-term key */
    	int statusHandshake; 			/* tells if the Protocol Handshake phase is over(0) or not(1) */
    	int M1, M2, M3; 				/* during the Protocol phase they specify which message we are waiting or - if they are equal to 1, we are in that phase and we can send/receive */
  };

/* List of the clients */
struct client_list{
	struct client_info client;
    	struct client_list* next;
};

/* Some useful typedefs */
typedef struct client_info client_info;
typedef struct client_list client_list;

/* functions declaration */
int remove_client(int socket);
client_info* find_client(int socket);
client_info* add_client(int socketfd, struct sockaddr_in clientAddr);
int find_client_by_name(char* name);
void close_connection(int * maxFD, fd_set* readSet, fd_set* writeSet, int i);
int doHandshakeProtocol(client_info* client, int phase);
int manageOperation(int listening, fd_set* readSet, fd_set* writeSet, fd_set* readSetTmp, fd_set* writeSetTmp, int *maxFD);
int saveRecivingFile(client_info* client);
int sendFile(client_info* client);
int manage_request(client_info* client);
int send_list(client_info* client);
int removeFile(client_info* client);
int getKeyFromFile(unsigned char* long_term_key, client_info* client);
  
/* Global Variable that storse the list of clients */
client_list* list;
