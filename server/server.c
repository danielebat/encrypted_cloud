#include "server_hdr.h"

/* Server Main - after some checks enter in a loop to serve client's requests */

int main(int argc, char*argv[]){
    
    	int sk=-1;						/* Passive socket */
    	int optval;						/* Socket options */
    	struct sockaddr_in my_addr;			/* Server and client addressed */
    	struct sockaddr_in srv_addr;			/* Server address */
    	int ret,n;
    	int srv_port;						/* Server port number */
    	int endServer=0;					/* Shutdown server process */
    	int maxFD;						/* MAX socket descriptor at the beginning is sk(listening)  */
    	fd_set readSet;					/* set of descriptors for reading */
    	fd_set writeSet;					/* set of descriptors for writing */
    	fd_set readSetTmp;					/* temporary set of descriptors for reading */
    	fd_set writeSetTmp;				/* temporary set of descriptors for writing */
    
    	FD_ZERO(&readSet);				/* Clear readSet */
    	FD_ZERO(&writeSet);				/* Clear writeSet */
    
    	/* Init list of clients */
    	list = NULL;
	
    	/* Command line arguments check */
    	if (argc!=2) {
		printf ("Error inserting parameters. Usage: \n\t %s (port) \n\n", argv[0]);
		return 1;
    	}

    	/* Port number validity check */
    	if (atoi(argv[1]) <= 0 || atoi(argv[1]) > 65535) {
		printf ("Port number is not valid\n");
		return 1;
    	}

    	/* get the port for the bind function */
    	srv_port = atoi(argv[1]);
    	printf ("Server Port for incoming request will be: %d \n",srv_port);
	
    	memset(&srv_addr, 0, sizeof(srv_addr)); 
    	srv_addr.sin_family = AF_INET; 
    	srv_addr.sin_port = htons(srv_port); 
    	ret = inet_pton(AF_INET, SRV_ADDR, &srv_addr.sin_addr);
    
    	if(ret <= 0) {
        	printf("Wrong server address\n");
        	return 1;
    	}
 
    	/* New socket creation */
    	sk = socket(AF_INET, SOCK_STREAM, 0);
    	if(sk == -1){
        	printf("Error creating the socket\n");
        	return 1;
    	}

    	optval = 1;
    	ret = setsockopt(sk, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));		/* Setting Socket options */
    	if(ret == -1) {
        	printf("Error setting SO_REUSEADDR\n");
        	return 1;
    	}
    
    	/* The socket is binded with the IP address and the port number */
    	memset(&my_addr, 0, sizeof(my_addr)); 
    	my_addr.sin_family = AF_INET;
    	my_addr.sin_addr.s_addr = htonl(INADDR_ANY); 
   	my_addr.sin_port = htons(srv_port);
    
    	ret = bind(sk, (SA *) &my_addr, sizeof(my_addr));
    	if(ret == -1) {
        	printf("Error binding the socket\n");
        	return 1;
   	}
    
   	/* Creation of backlog queue of lenght BACKLOG_SIZE */
    	ret = listen(sk, BACKLOG_SIZE);
    	if(ret == -1) {
        	printf("Error creating the backlog queue, size %d\n", BACKLOG_SIZE);
        	return 1;
    	}	
    
    	ret = fcntl(sk, F_SETFD, O_NONBLOCK);			/* Sets the socket as Non - blocking */			
    	if(ret == -1) {
        	printf("Error using fcntl\n");
        	return 1;
    	}
    
    	/* Server ready */
    	printf("Server up. Waiting for new connections\n");
    
    	/* set MAX socket descriptor */
    	maxFD = sk;
    
    	/* enable sk reading mode */
    	FD_SET(sk, &readSet);
    
    	while(!endServer) {	/* till endServer is equal to zero */
      
		readSetTmp = readSet;
		writeSetTmp = writeSet;

		n = select(maxFD + 1, &readSetTmp, &writeSetTmp, NULL, NULL); /* waiting for I/O operations */
		
		/* handle select errors */
		if(n < 0){
		  	printf("Error while waiting for new I/O operations (i.e. select). Closing server...\n");
		  	printf("Exiting...\n");
		  	break;
		}

		/* manage operation */
		endServer = manageOperation(sk, &readSet, &writeSet, &readSetTmp, &writeSetTmp, &maxFD); 
			
	}
	
    	/* Checking all soskets and removing clients */
   	for (n = 0; n < maxFD; n++)
	if (FD_ISSET(n, &readSet) || FD_ISSET(n, &writeSet)){
		remove_client(n);
		close(n);
	}
    
    	/* free up memory */
    	free(list);
    
    	return 0;
}
