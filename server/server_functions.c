#include "server_hdr.h"

/* get key from a file - reads and stores the long term key from a file */
int getKeyFromFile(unsigned char* long_term_key, client_info* client){
      
    	unsigned char* long_term_key_name;
    	FILE * file;
    	int err;
  
    	long_term_key_name = malloc(strlen("./key/") + strlen(client->Name) + 1); 	/* let's try to find the long term key */
    	strcpy((char*)long_term_key_name, "./key/");
    	strcat((char*)long_term_key_name, client->Name);

    	file=fopen((char*)long_term_key_name,"r");					/* try to open the file that holds the key */

    	if(file==NULL){								/* if no file available... */
    		printf("No user directory/key are available for user %s\n", client->Name);
    		return -1;	
    	}

    	/* key reading */
    	err = fread(long_term_key, 1, KEY_SIZE, file);
    	if(err < 0) {
    		printf("Error reading the file with the long-term key of the user %s\n", client->Name);
    		return -1;
   	}
    
    	free(long_term_key_name);
    	return 0;
}

/* Add_client - adds a new client to the list of those connected */
client_info* add_client(int socketfd, struct sockaddr_in clientAddr){

    	client_list* new_client = (client_list*)malloc(sizeof(client_list));	
    	if(new_client == NULL){
      		printf("Is not possibile to create a new client\n");
      		return NULL;
   	}
    	new_client->next = list;
    	list=new_client;
    	new_client->client.Name = malloc(INET_ADDRSTRLEN);		/* saving actual IP address as name */
    	inet_ntop(AF_INET, &(clientAddr.sin_addr), new_client->client.Name, INET_ADDRSTRLEN);
    
    	/*initialize parameters */
    	new_client->client.socket_fd = socketfd;			/* saving socked fd */
    	new_client->client.statusHandshake = PROTOCOL_START;		/* start with the protocol */
    	new_client->client.M1 = 1;					/* start with the phase 1 */
    	new_client->client.M2 = 0;
    	new_client->client.M3 = 0;
    	new_client->client.ctx = NULL;
    	new_client->client.session_ctx = NULL;
    	return &(new_client->client);		
}

  /* Remove_client - removes a client from the list */
  int remove_client(int socket){
	  
	printf("User %s is disconnected.\n", find_client(socket)->Name);
    
    	if(list==NULL) 						/* no elements in the list */
      		return 0;
    
    	client_list * tmp=list;					/* parse the list */
    	client_list * prev=NULL;
    
   	while(tmp!=NULL){
      		if(tmp->client.socket_fd==socket){
	    		if(prev==NULL)
		    		list=tmp->next;
	    		else
	    			prev->next=tmp->next;
	    		if (tmp->client.ctx!=NULL)
	      			EVP_CIPHER_CTX_cleanup(tmp->client.ctx);	/* clean up contexts */
	    		if (tmp->client.session_ctx!=NULL)
	    			EVP_CIPHER_CTX_cleanup(tmp->client.session_ctx);
	    		free(tmp);
	    		return 0;
	    	}
		else{
	    		prev=tmp;
	    		tmp=tmp->next;
		}
		return -1;
    	}
  	return -1;	
}

  /* find_client - find a client into the list */
client_info* find_client(int socket){

	client_list* l = list;   
    	while (l != NULL){
		if (l->client.socket_fd == socket){
	    		return &(l->client);
	  	}
		else
	    		l = l->next;
    	}	

	return NULL;
}

/* Find user - finds a user into the list given the name */
int find_client_by_name(char* name){

	client_list* l = list;   
   	while (l != NULL){
		if (!strcmp(l->client.Name,name)){
	    		return 1;
	  	}
		else
	    		l = l->next;
    	}
    	return -1;
}

/* close connection - closes a connection set with a client in past */
void close_connection(int * maxFD, fd_set* readSet, fd_set* writeSet, int i){

    	FD_CLR(i,readSet);		/* delete from readSet */
    	FD_CLR(i,writeSet);		/* delete from writeSet */

    	remove_client(i);		/* remove from the list */
    	close(i);				/* close it's socket	*/

    	if (i == *maxFD){		/* updating MAXFD value */
      		while(FD_ISSET(*maxFD, readSet) == 0 && FD_ISSET(*maxFD, writeSet) == 0)
	    		(*maxFD)--;
    	}
}

/* doHandshakeProtocol - manages all messages needed to establish a session key between client and server */
int doHandshakeProtocol(client_info* client, int phase){

  	/* other useful variables */	
  	unsigned char* long_term_key;			/* symmetric key*/
 	unsigned char* enc_buf;					/* for encrypted buffer */
  	unsigned char* enc_buf_2;				/* for encrypted buffer */
  	unsigned char* buffer;					/* temporary buffer */
  	unsigned char* total_enc_buffer;			/* total encrypted buffer */
  	unsigned char* tmp;					/* temporary buffer */
  	int recived_mex_len;					/* useful int variables */
  	int loutU,loutF;	
  	int a_name_len;
  	int plaintext_len;
  	int enc_buf_len;
  	int tmpNb, recivedNb;
  	int err;
  	int b_name_len;
  	int bsize;
  	int old_len;

	/* Protocol: Phase 1 */
  	if(phase == 1){
      		/* 
     	 	Protocol starting
      		M1: A --> B A, B, Na
      		A: nome utente 
      		B: server name (IP in our case)
      		Na: Nonce <-- RAND_bytes() 4 byte long;
      		*/
      
      		client->Na = malloc(sizeof(int));							/* Nonce from A */
      		client->Nb = malloc(sizeof(int));							/* B's nonce 	*/
      
      		printf("Starting Handshake Protocol for new session key with %s.\n", client->Name);
	
      		/* NOTE: the strings are without eof char */
      		err = recv(client->socket_fd, &recived_mex_len, sizeof(int), MSG_WAITALL);	/* reciving A,B,Na message length */
      		if(err != sizeof(int)) {
	  		printf("Error receiving M1 size\n");
	  		return -1;
      		}
      
     	 	buffer = malloc(recived_mex_len);							/* reciving A,B,Na message */
      		err = recv(client->socket_fd, buffer, recived_mex_len, MSG_WAITALL);
      		if(err != recived_mex_len) {
	  		printf("Error receiving M1\n");
	  		return -1;
      		}
      
      		/* get from buffer : A, B, and Na */
      		b_name_len = strlen(SRV_ADDR);
      		a_name_len = recived_mex_len - sizeof(int) - b_name_len; 				/* Na is a 32 bit number */
      		tmp = malloc(a_name_len + 1);							/* Now we should test if there is already an user with that name */
      		memcpy(tmp, buffer, a_name_len);						
      		tmp[a_name_len]='\0';
      
      		err = find_client_by_name((char*)tmp);						/* find it */
      		if(err == 1){
	  		printf("User with name %s is already connected.\n", tmp);
	  		return -1;
       		}	
      
      		/* otherwise, we can add the user */
      		free(tmp);										/* just used */
      		free(client->Name);									/* free actual name */
      		client->Name = malloc(a_name_len + 1);							/* A name */
      		memcpy(client->Name, buffer, a_name_len);							/* updating name */
      		client->Name[a_name_len]='\0';								/* adding eof symbol */
      		client->usr_dir = malloc(strlen("./usr/") + strlen(client->Name) + strlen("/") + 1);	/* updating user directory */
      		strcpy(client->usr_dir,"./usr/");
      		strcat(client->usr_dir,client->Name);							
      		strcat(client->usr_dir,"/");

      		err = strncmp((char*)buffer + a_name_len, SRV_ADDR , b_name_len);				/* compare B's name*/	      
      		if(err != 0){
	  		printf("No user directory/key are available for user %s\n", client->Name);
	  		return -1;
     	 	}
      
      		memcpy(client->Na, buffer + a_name_len + b_name_len, sizeof(int)); 			/* save A's nonce */
      
      		/* preparing things for next phase of the protocol */
      		client->M1 = 0;
      		client->M2 = 1;
      		free(buffer);
      		return 0;
  
  	}
	/* Protocol: Phase 2 */
	else if(phase == 2){

      		/* Start message M2
		 
     		Sending M2
     		M2: B --> A {B, Na, Kab'}Kab, {Nb}Kab'
     		B: server Name
     		Na: Nonce recived in phase 1
     		Kab' = session key
     		Nb =  Server nonce
      		*/  
      
      		client->ctx = malloc(sizeof(EVP_CIPHER_CTX));				/* context for the first part of M2 */
      		EVP_CIPHER_CTX_init(client->ctx);
      		EVP_EncryptInit(client->ctx, EVP_des_ecb(), NULL, NULL);
      
      		long_term_key=malloc(KEY_SIZE);						/* try to acquire long-term key */
      		err = getKeyFromFile(long_term_key, client);				/* Retrieving long term key */
      		if(err < 0){
	  		printf("It's not possible to retrieve long term key from the file\n");
	  		return -1;
      		}
      
      		EVP_EncryptInit(client->ctx, NULL, long_term_key, NULL);			/* set it as long term key for ctx context */
      		EVP_CIPHER_CTX_set_key_length(client->ctx, KEY_SIZE);
      
      		bsize= EVP_CIPHER_CTX_block_size(client->ctx);
      		RAND_bytes(client->Nb, sizeof(int));					/* generate B's nonce */
      		client->session_key = malloc(KEY_SIZE);					/* generate session key */
     		RAND_bytes(client->session_key, KEY_SIZE);
      
      		/* encrypt the first part of M2 */
      		plaintext_len = strlen(SRV_ADDR) + sizeof(int) + KEY_SIZE;
      		buffer = malloc(plaintext_len);
     	 	memcpy(buffer, SRV_ADDR, strlen(SRV_ADDR));
      		memcpy(buffer + strlen(SRV_ADDR), client->Na, sizeof(int));
      		memcpy(buffer + strlen(SRV_ADDR) + sizeof(int), client->session_key, KEY_SIZE);
      
      		enc_buf = malloc(plaintext_len + bsize);					/* encrypt first block with long-term key*/
      		loutU = 0;
      		loutF = 0;
      		EVP_EncryptUpdate(client->ctx, enc_buf, &loutU, buffer, plaintext_len);
      		EVP_EncryptFinal(client->ctx, &enc_buf[loutU], &loutF);
      		enc_buf_len = loutU + loutF;
      
      		err = send(client->socket_fd, &enc_buf_len , sizeof(int), 0); 		/* sending length of {B, Na, Kab'}Kab */
      		if(err != sizeof(int)){
			printf("Error trasmitting size of encrypt M2\n ");
			return -1;
      		}
      
      		/* Encrypting Server Nonce - Allocating Context */
      		client->session_ctx = malloc(sizeof(EVP_CIPHER_CTX));
      		EVP_CIPHER_CTX_init(client->session_ctx);
      		EVP_EncryptInit(client->session_ctx, EVP_des_ecb(), NULL, NULL);
      		EVP_EncryptInit(client->session_ctx, NULL, client->session_key, NULL);
      		EVP_CIPHER_CTX_set_key_length(client->session_ctx, KEY_SIZE);
      
      		enc_buf_2 = malloc(sizeof(int) + bsize);
      
      		EVP_EncryptUpdate(client->session_ctx, enc_buf_2, &loutU, client->Nb, sizeof(int));	/* {B}Kab' encryption */
      		EVP_EncryptFinal(client->session_ctx, &enc_buf_2[loutU], &loutF);
      
      		old_len= enc_buf_len;
      		enc_buf_len = loutU + loutF;
      
      		err = send(client->socket_fd, &enc_buf_len , sizeof(int), 0); 		/* sending lenght of {B}Kab' */
      		if(err != sizeof(int)){
			printf("Error transmitting size of encrypt M2\n");
			return -1;
      		}
      
      		total_enc_buffer = malloc(enc_buf_len + old_len); 			/* it will contain {B, Na, Kab'}Kab, {Nb}Kab' */	      
      		memcpy(total_enc_buffer, enc_buf, old_len);
      		memcpy(total_enc_buffer + old_len, enc_buf_2, enc_buf_len); 		/* M2 is now completed, sending it */
      
      		err = send(client->socket_fd, total_enc_buffer , enc_buf_len + old_len, 0); 
      		if(err != (enc_buf_len + old_len )){					/* sending all M2 */
			printf("Error transmitting encrypt M2\n");
			return -1;
      		}
      
      		/* End Message M2 */ 
      		client->M2 = 0;
      		client->M3 = 1;
      		free(buffer);
      		free(long_term_key);
      		free(enc_buf);
      		free(enc_buf_2);
      		free(total_enc_buffer);
      		return 0;
  	}
  	/* Protocol: Phase 3 */
  	else{	
 
 		/* Receiving Message M3 */      
      		err = recv(client->socket_fd, &recived_mex_len, sizeof(int),MSG_WAITALL);		/* waiting for the length {Nb-1}Kab' sent by the user */
      		if(err != sizeof(int)) {
	  		printf("Error receiving M3 size\n");
	  		return -1;
      		}
      
      		enc_buf = malloc(recived_mex_len);						

      		err = recv(client->socket_fd, enc_buf, recived_mex_len, MSG_WAITALL);		/* waiting for {Nb-1}Kab' sent by the user */		
      
      		if(err != recived_mex_len) {
	 		printf("Error receiving M3\n");
	  		return -1;
      		}
      
      		/* Let's check if the decrypted message is equal to client->Nb -1 */
      
      		/* NOTE: Nb has a 32 bits size without '\0' char */
      		tmp = malloc(sizeof(int));
      		memcpy(tmp, client->Nb, sizeof(int));
      		tmpNb = *tmp - 1;									/* This should be the correct Nb - 1, calculated by the server itself */ 
      
      		/* Enable ctx-session context to decrypt */
      		EVP_DecryptInit(client->session_ctx, EVP_des_ecb(), NULL, NULL);
      		EVP_DecryptInit(client->session_ctx, NULL, client->session_key, NULL);
      		EVP_CIPHER_CTX_set_key_length(client->session_ctx, KEY_SIZE);
      		bsize= EVP_CIPHER_CTX_block_size(client->session_ctx);
      
      		enc_buf_len = recived_mex_len + bsize;
      		buffer = malloc(enc_buf_len);
      
      		EVP_DecryptUpdate(client->session_ctx, buffer, &loutU,enc_buf, recived_mex_len);	/* decrypting message {Nb - 1}Kab' */
      		EVP_DecryptFinal(client->session_ctx, &buffer[loutU], &loutF);
      
      		recivedNb = (int)*buffer;								/* converting to int the received Nb - 1 */
      		if(recivedNb != tmpNb){
			printf("The Nonce received by the client isn't the one that has been sent. Closing connection with client %s.\n", client->Name);
			return -1;
	  	} 
      		// End protocol
      		printf("Message 3 received by %s. Protocol terminated correctly.\n\n", client->Name);
      		client->statusHandshake = PROTOCOL_END;
      		client->M3 = 0;
      		free(buffer);
      		free(enc_buf);
      		free(tmp);
      		return 0;
  	}
 	return 0;
}

/* manageOperation function - manages the following operation to perform */
int manageOperation(int listening, fd_set* readSet, fd_set* writeSet, fd_set* readSetTmp, fd_set* writeSetTmp, int *maxFD){
 
  	int err=0;
  	int i; 						/* loop index */
  	struct sockaddr_in clientAddr;			/* Ip + port of the client in this structure */
  	client_info* client=NULL;				/* client field */
  	unsigned int addrLen = sizeof(struct sockaddr_in);	/* sockAddrIn length */
  	int newClient=0;					/* new socket descriptor   */
  
  	/* scanning descriptors */
	for(i=0; i<= *maxFD;i++){
	    	if(FD_ISSET(i, readSetTmp)){
			if(i==listening){	/* handle a new connection */
				while(newClient != -1){
			    		newClient = accept(listening, (struct sockaddr*)&clientAddr, &addrLen);
			    		if(newClient<0){
						if(errno != EWOULDBLOCK || errno != EAGAIN){
				    			printf("An error occurred while accepting new clients.\n");
				    			return -1; 				/* Server will be shut down */
						}
						break;
			    		}
			    		client = add_client(newClient, clientAddr);	/* at the beginning the name is the IP address */
			    		printf("Client %s  is now connected\n", client->Name);
			    		if (newClient > *maxFD)
						*maxFD = newClient;
					FD_SET(newClient, readSet);		/* prepare the readSet to waiting for messages of the client itself */
					FD_CLR(newClient, writeSet);
					break;
				}
			}
			else{							/* a new message is arrived from one of the clients */
		    		client = find_client(i);				/* find the client */
		    		if(client->statusHandshake == PROTOCOL_START){	/* begin handshake protocol with the client */
					if(client->M1 == 1){
			    			err = doHandshakeProtocol(client,1); 	/*start protocol phase 1 */
						if(err<0){
				    			printf("The handshake with user %s went wrong. Closing.\n", client->Name);
				    			close_connection(maxFD, readSet, writeSet, i);
				    			return 0;
						}
						FD_SET(client->socket_fd, writeSet);	/* prepare the socket for writing M2 */
						FD_CLR(client->socket_fd, readSet);
					}
					if(client->M3 == 1){
			    			err = doHandshakeProtocol(client,3); 	/*start protocol phase 3 and terminate with the protocol  */
			    			if(err<0){
							printf("The handshake with user %s went wrong. Closing.\n", client->Name);
							close_connection(maxFD, readSet, writeSet, i);
							return 0;
			    			}
			    			FD_SET(client->socket_fd, readSet);	/* prepare the socket for reading new messages */
			    			FD_CLR(client->socket_fd, writeSet);
					}
		    		}
				else{						/* receiving data from an already connected client */
		    			err = manage_request(client);
		    			if(err == -1){				/* problems for saving the user's file or creating the list */
						printf("Request from the user %s cannot be satisfied\n", client->Name);
						close_connection(maxFD, readSet, writeSet, i);
						return 0;
		    			}
		    			FD_SET(client->socket_fd, readSet);
				}

	      		}
	  	}
	  	if(FD_ISSET(i, writeSetTmp)){				/* write operations have to be performs */
	      		client = find_client(i);				/* find the client */
	      		if(client->statusHandshake == PROTOCOL_START){	/* begin handshake protocol with the client */
		  		if(client->M2 == 1){
		      			err = doHandshakeProtocol(client,2); /*start protocol phase 2 */
		      			if(err<0){
			  			printf("The handshake with user %s went wrong. Closing.\n", client->Name);
			  			close_connection(maxFD, readSet, writeSet, i);
			  			return 0;
		     	 		}
		      			FD_SET(client->socket_fd, readSet);	/* prepare the socket for reading M3 */
		      			FD_CLR(client->socket_fd, writeSet);
		  		}
			}
	 	}
    	}
  	return 0;
}

/* manage_request - tries to perform one of the actions the client could ask for */
int manage_request(client_info* client){

	/* we have to start decrypting */
	
	/* Prepare the context session of the client for decrypting */
	EVP_DecryptInit(client->session_ctx, EVP_des_ecb(), NULL, NULL);
	EVP_DecryptInit(client->session_ctx, NULL, client->session_key, NULL);
	EVP_CIPHER_CTX_set_key_length(client->session_ctx, KEY_SIZE);
	int bsize = EVP_CIPHER_CTX_block_size(client->session_ctx);
	
	int ret, loutU, loutF, err;
	int size;				/* size of the buffer for the plaintext  */
	unsigned char* buffer;			/* plaintext buffer */
	unsigned char* enc_buffer;		/* encrypted buffer */
	
	/* receiving the message length */
	ret = recv(client->socket_fd, &size, sizeof(int), MSG_WAITALL);
	if (ret != sizeof(int)) {
	    	printf("Error receiving the length of the message from user %s\n", client->Name);
	    	return -1;
	}
	
	/* receiving the message  */
	enc_buffer = malloc(size);
	if(enc_buffer == NULL){
	    	printf("No memory available\n");
	    	return -1;
	}
	
	ret = recv(client->socket_fd, enc_buffer, size, MSG_WAITALL);
	if (ret != size) {
	    	printf("Error receiving the message from user %s\n", client->Name);
	    	return -1;
	}
	
	
	/* decrypting message... */
	buffer = malloc(size + bsize);
	if(buffer == NULL){
		printf("No memory available\n");
		return -1;
	}
	
	EVP_DecryptUpdate(client->session_ctx, buffer, &loutU, enc_buffer, size);
	EVP_DecryptFinal(client->session_ctx, &buffer[loutU], &loutF);
	
	/* choosing case ... */
	if(strcmp((char*)buffer, "list") == 0)
		err = send_list(client);
	else if(strcmp((char*)buffer, "file") == 0)
		err = saveRecivingFile(client);
	else if(strcmp((char*)buffer, "down") == 0)
		err = sendFile(client);
	else if(strcmp((char*)buffer, "remv") == 0)
		err = removeFile(client);
	else
		return -1;	/* an error occurred */
	
	free(buffer);
	free(enc_buffer);
	return err;
}

/* saveRecivingFile - receives the file from the client, decrypt it (the content) and saves it in user's directory */
int saveRecivingFile(client_info* client){
	  
	printf("Receiving file from user %s.\n", client->Name);
	  
	/* Prepare the context session of the client for decrypting */
	EVP_DecryptInit(client->session_ctx, EVP_des_ecb(), NULL, NULL);
 	EVP_DecryptInit(client->session_ctx, NULL, client->session_key, NULL);
	EVP_CIPHER_CTX_set_key_length(client->session_ctx, KEY_SIZE);
	int bsize = EVP_CIPHER_CTX_block_size(client->session_ctx);
	  
	int ret, loutU, loutF;
	int name_size;			/* length of the name of the received file */
	int size;				/* size of the buffer for the plaintext  */
	unsigned char* filename;		/* name of the received file */
	unsigned char* buffer;		/* plaintext buffer */
	unsigned char* path_file;		/* given by the concatenation of user directory and name of the file */	
	unsigned char* enc_buf;		/* used to decrypt the incoming file */
	FILE* file;				/* pointer to the file where the received message will be saved */

	/* Reception of the length of the file name */
	ret = recv(client->socket_fd, &name_size, sizeof(int), MSG_WAITALL);
	if (ret != sizeof(int)) {
		printf("%d \n Error receiving the length of the file name from user %s\n", ret, client->Name);
		return -1;
	  }

	/* Memory allocation for filename */
	filename = malloc(name_size);
	if(filename == NULL) {
		printf("Error allocating memory\n");
	    	return -1;
	}

	/* Reception of the file name */
	ret = recv(client->socket_fd, filename, name_size, MSG_WAITALL);   
	if(ret != name_size){
		printf("Error receiving the file name\n");
	    	return -1;
	}
	  
	/* Reception of the file size */
	ret = recv(client->socket_fd, &size, sizeof(int), MSG_WAITALL);
	if(ret != sizeof(int)) {
	    	printf("Error receiving the file size\n");
	    	return -1;
	}

	/* Memory allocation */
	enc_buf = malloc(size);
	if(enc_buf == NULL){
	    	printf("Error allocating memory for a file of user %s\n", client->Name);
	    	return -1;
	}
	 
	/* Reception of the file */
	ret = recv(client->socket_fd, enc_buf, size, MSG_WAITALL);
	if(ret != size) {
	    	printf("Error receiving the file\n");
	    	return -1;
	}
	  
	/* preparing creation of the file */
	path_file = malloc(strlen(client->usr_dir) + strlen((char*)filename) + 1);
	strcpy((char*)path_file, client->usr_dir);
	strcat((char*)path_file, (char*)filename);
	  
	/* decrypting incoming file */
	buffer = malloc(size + bsize);
	EVP_DecryptUpdate(client->session_ctx, buffer, &loutU, enc_buf, size);
	EVP_DecryptFinal(client->session_ctx, &buffer[loutU], &loutF);
	  
	/* Open the file to save the received message */
	file = fopen((char*)path_file, "wb");
	if(file == NULL) {
		printf("File not written for %s\n", client->Name);
	      	return -1;
	}
	  
	/* Write the received message in the local file */
	ret = fwrite(buffer, sizeof(char), (loutU + loutF) , file);
	if(ret != (loutU + loutF)) {
		printf("Error writing the file for user %s \n", client->Name);
	      	return -1;
	}    
	  
	printf("Received file %s with size %d bytes from user %s\n", filename, loutU + loutF , client->Name);
	  
	fclose(file);
	free(path_file);
	free(filename);
	free(buffer);
	free(enc_buf);
	      
	return 0;
}

/* sendFile - receives a file name, encrypt it and send it to the client */
int sendFile(client_info* client){

	printf("Sending file to user %s.\n", client->Name);
	  
	/* Prepare the context session of the client for decrypting */
	EVP_EncryptInit(client->session_ctx, EVP_des_ecb(), NULL, NULL);
	EVP_EncryptInit(client->session_ctx, NULL, client->session_key, NULL);
	EVP_CIPHER_CTX_set_key_length(client->session_ctx, KEY_SIZE);
	int bsize = EVP_CIPHER_CTX_block_size(client->session_ctx);
	  
	int name_size;			/* length of the name of the received file */
	int size;				/* size of the buffer for the plaintext  */
	unsigned char* file_name;		/* name of the received file */
	unsigned char* buffer;		/* plaintext buffer */
	unsigned char* buf_res; 	/* response to know if the file is present or not */	
	FILE* file;				/* pointer to the file where the received message will be saved */	
	unsigned char* out;	
	char* path;
	int loutU, loutF;   
	struct stat informazioni;   
	int out_len, ret;

	buf_res = malloc(sizeof(int));
	*(int*)buf_res = 1;				/* File present */

	/* Reception of the length of the file name */
	ret = recv(client->socket_fd, &name_size, sizeof(int), MSG_WAITALL);
	if (ret != sizeof(int)) {
		printf("%d \n Error receiving the length of the file name from user %s\n", ret, client->Name);
		return -1;
	}

	/* Memory allocation for filename */
	file_name = malloc(name_size);
	if(file_name == NULL) {
	    	printf("Error allocating memory\n");
	    	return -1;
	}

	/* Reception of the file name */
	ret = recv(client->socket_fd, file_name, name_size, MSG_WAITALL);   
	if(ret != name_size){
	    	printf("Error receiving the file name\n");
	    	return -1;
	}
    
	/* Setting path file */
	path = malloc(strlen(client->usr_dir) + name_size);
	strcpy((char*)path, client->usr_dir);
	strcat((char*)path, (char*)file_name);

    	/* Open the file to be sent */
    	file = fopen(path,"rb");
    	if(file == NULL) {
        	printf("Error opening the file %s or File not present!\n", file_name);
		*(int*)buf_res = 0;			/* File not present */
    	}
	
   	/* The response is sent to the client */
   	ret = send(client->socket_fd, buf_res, sizeof(int), 0);
    	if(ret != sizeof(int)){
        	printf("Error transmitting the response\n ");
        	return -1;
    	}
  
    	if(*(int*)buf_res == 0){
		free(buf_res); 
		free(path);
    		free(file_name);
		return 0;
    	}
    	else{
 
		/* Retrieve the size of the file to be sent */
    		stat(path, &informazioni);
    		size = informazioni.st_size; /* in byte */ 
    
    		/* Memory allocation for the file to be sent */
    		buffer = malloc(size);
    
    		/* File reading */
    		ret = fread(buffer, sizeof(char), size, file);
    		if(ret != size) {
        		printf("Error reading the file \n");
        		return -1;
    		}
    
    		fclose(file);
    
    		/* Pay attention: only the content of the file is encrypted */
    
    		out = malloc(size + bsize);
    		if(out == NULL){
        		printf("No space available\n");
        		return -1;
    		}
    
    		EVP_EncryptUpdate(client->session_ctx, out, &loutU, buffer, size);
    		EVP_EncryptFinal(client->session_ctx, &out[loutU], &loutF);
    		out_len = loutU + loutF;						/* size of the encrypted file */ 
    
    		/* The file size is sent */
    		ret = send(client->socket_fd, &out_len, sizeof(int), 0);
    		if(ret != sizeof(int)){
        		printf("Error transmitting the encrypt file size\n ");
        		return -1;
    		}
    
    		/* The file is sent */
    		ret = send(client->socket_fd, out, out_len, 0);
    		if(ret != out_len){
        		printf("Error transmitting the encrypt file\n");
        		return -1;
    		}
    
    		printf("File %s with size %d bytes has been sent to %s\n", file_name, size, client->Name);
    		free(buffer);	
    		free(out);
	}
	free(buf_res);
    	free(path);
    	free(file_name);
    
    	return 0;
	
}

/* send_list - sends a list of files that are present in usesr's directory */
int send_list(client_info* client){

	int err, size, ret;
	FILE* f;
	unsigned char* buffer;
	unsigned char* enc_buffer;
	int loutU, loutF;
	char* path;
	struct stat informazioni;  
	
	/* Prepare the context session of the client for encrypting */
	EVP_CIPHER_CTX_cleanup(client->session_ctx);
	EVP_CIPHER_CTX_init(client->session_ctx);
	EVP_EncryptInit(client->session_ctx, EVP_des_ecb(), NULL, NULL);
	EVP_EncryptInit(client->session_ctx, NULL, client->session_key, NULL);
	EVP_CIPHER_CTX_set_key_length(client->session_ctx, KEY_SIZE);
	int bsize = EVP_CIPHER_CTX_block_size(client->session_ctx);
	
	printf("User %s has request a list of his own files.\n", client->Name);
	
	/* invoke the system call to create a file with the actual clients file: ls client_dir > list.txt */
	char* cmd = malloc(strlen("ls ") + strlen(client->usr_dir) + strlen(" > list.txt") + 1 );
	strcpy(cmd, "ls ");
	strcat(cmd, client->usr_dir);
	strcat(cmd, " > list.txt");

	system(cmd);			/* Please note, the file is saved in the main server directory */
	
	/* now we read this list.txt file and send it to the client */
	path = malloc(strlen("list.txt") + 1);
	strcpy(path, "list.txt");
	
	f = fopen(path, "rb");
	if(f == NULL){
		printf("Error: no file list created.\n");
		return -1;
	}
	
	/* Retrieve the size of the file to be sent */
	stat(path, &informazioni);
	size = informazioni.st_size; /* in byte */ 
	
	/* Memory allocation for the file to be sent */
	buffer = malloc(size);
	if(buffer == NULL){
		printf("Error: no memory available.\n");
		return -1;
	}
	
	/* File reading */
	err = fread(buffer, sizeof(char), size, f);
	if(err != size) {
	  	printf("Error reading the file list\n");
	  	return -1;
	}
	
	fclose(f);
	
	/* encrypting list... */
	enc_buffer = malloc(size + bsize);
	EVP_EncryptUpdate(client->session_ctx, enc_buffer, &loutU, buffer, size);
	EVP_EncryptFinal(client->session_ctx, &enc_buffer[loutU], &loutF);
	
	size = loutU + loutF;								/* updating size value */
	
	/* The length of the file is sent */
	ret = send(client->socket_fd, &size, sizeof(int), 0); 
	if(ret != sizeof(int)){
	  	printf("Error transmitting the length of the file list\n ");
	  	return -1;
	}
	
	/* sending encrypted list */
	ret = send(client->socket_fd, enc_buffer, size, 0); 
	if(ret != size){
	    	printf("Error transmitting the encrytped file list\n ");
	   	return -1;
	}
	
	/* remove list.txt file from user directory */
	free(cmd);
	cmd = malloc(strlen("rm -f ") + strlen("list.txt") + 1);
	strcpy(cmd, "rm -f ");
	strcat(cmd, "list.txt");
	
	system(cmd);
	
	/* free memory */
	free(cmd);
	free(buffer);
	free(enc_buffer);
	
	return 0;
}

/* removeFile - receives the name of the file and removes it from user's directory */
int removeFile(client_info* client){

	int name_size, ret;
	char *filename, *path;
	void* buf;
	FILE *file;

	buf = malloc(sizeof(int));
	*(int*)buf = 1;			/* Buffer initialized with "ok response" */

	/* Reception of the length of the file name */
	ret = recv(client->socket_fd, &name_size, sizeof(int), MSG_WAITALL);
	if (ret != sizeof(int)) {
		printf("%d \n Error receiving the length of the file name from user %s\n", ret, client->Name);
		return -1;
	}

	/* Memory allocation for filename */
	filename = malloc(name_size);
	if(filename == NULL) {
	    	printf("Error allocating memory\n");
	    	return -1;
	}

	/* Reception of the file name */
	ret = recv(client->socket_fd, filename, name_size, MSG_WAITALL);   
	if(ret != name_size){
	    	printf("Error receiving the file name\n");
	    	return -1;
	}

	printf("User %s has request to remove the file %s.\n", client->Name, filename);

	
	path = malloc(strlen(client->usr_dir) + strlen(filename) + 1);
	strcpy(path, client->usr_dir);
	strcat(path, filename);

	/* Let's check if the file is present, otherwise we cannot delete it */
	file = fopen(path, "rb");
	if(file == NULL){
		*(int*)buf = 0;
		printf("File not found\n");
	}
	else fclose(file);
	
	/* invoke the system call to remove a file: rm -f filename */
	char* cmd = malloc(strlen("rm -f ") + strlen(client->usr_dir) + strlen(filename) + 1 );
	strcpy(cmd, "rm -f ");
	strcat(cmd, client->usr_dir);
	strcat(cmd, filename);
	
	system(cmd);
		
	ret = send(client->socket_fd, buf, sizeof(int), 0); 
	if(ret != sizeof(int)){
	    	printf("Error transmitting the delete response.\n ");
	    	return -1;
	}

	free(filename);
	free(cmd);
	free(buf);

	return 0;
}
