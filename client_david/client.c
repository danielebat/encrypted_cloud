#include "./client_hdr.h"


int main(int argc, char*argv[]) {   
  
    	int ret;                               	/* function returns */
    	int err;					/* for error handle*/
    	int sk;            				/* server communication socket */
    	int cl_port;       	    		/* port number */
    	int session_key_len;           	/* len of session key: Kab' */
    	int filename_len;                  	/* len of the name of file */
    	unsigned char * session_key;  	/* buffer for session key: Kab' */
    	char *cmd;                         	/* command inserted by the client */
    	char *filename;                   	/* Name of the inserted file */
    
    	struct sockaddr_in srv_addr;                    /* server address */
    
    	/* Command line arguments check */
    	if (argc!=4) {
		printf ("Error inserting parameters. Usage: \n\t %s (IP) (port) (username)\n\n", argv[0]);
		return 1;
    	}
    
    	/* Port number validity check */
    	if ( atoi(argv[2]) <= 0 ||  atoi(argv[2]) > 65535 ) {
		printf ("Port number is not valid\n");
		return 1;
    	}

    	cl_port = atoi(argv[2]);
	
    	memset(&srv_addr, 0, sizeof(srv_addr)); 
    	srv_addr.sin_family = AF_INET; 
    	srv_addr.sin_port = htons(cl_port); 
    	ret = inet_pton(AF_INET, argv[1], &srv_addr.sin_addr);
    
    	if(ret <= 0) {
        	printf("Wrong server address\n");
        	return 1;
    	}
	  
    	/* New socket creation */
    	sk = socket(AF_INET, SOCK_STREAM, 0);
    
    	if(sk == -1) {
        	printf("Error creating the socket\n");
        	return 1;
    	}
    
    	/* TCP connection setup */
    	ret = connect(sk, (SA *) &srv_addr, sizeof(srv_addr));
    
    	if(ret == -1) {
        	printf("Error establishing a connection with the server\n");
        	return 1;
    	}
   
    	printf("Connection with server %s established on port %d.\n", argv[1], cl_port);
    
    	/* Let's call the start protocol function to establish the session key */
    	session_key = NULL;
    	err = start_protocol(sk, &session_key, &session_key_len, argv);
    	if(err < 0){
		printf("The protocol with the server was aborted.\n");
		close(sk);
        	return -1;	
    	}
    
    	/* till client dies, do... */

    	cmd = malloc(DIM_CMD);
   	while(1){

        /* Commands available */
        printf("\nInsert the command:\n");
        printf("1) Send file to server\t(Usage: 1 [file_name])\n");
	printf("2) Retrieve a list of your current files\t(Usage: 2)\n");
	printf("3) Download file from the server\t(Usage: 3 [file_name])\n");
	printf("4) Remove file from the server\t(Usage: 4 [file_name])\n");	
        printf("5) Close connection to server\t(Usage: 5)\n\n");
	printf("> ");
    
        cmd = fgets(cmd, DIM_CMD, stdin);
        
        if (cmd == NULL){
        	perror("SETTING CLIENT ERROR - Function 'fgets' error");
            	printf("EXITING...\n");
            	close(sk);
           	break;
        }
        
        if (cmd[strlen(cmd)-1] != '\n')
            	flushStdIN;                         /* clears the input stream in case it has not been pressed 'send'. */
        
        else
            	cmd[strlen(cmd)-1] = '\0';          /* otherwise it replaces the caratter f 'newline' with the end of string. */


        if (!(atoi(&cmd[0]) == 1 || atoi(&cmd[0]) == 2 || atoi(&cmd[0]) == 3 ||atoi(&cmd[0]) == 4 || atoi(&cmd[0]) == 5 )){    /* verify the current command */
            	printf("\n\n");
	    	continue;
        }
        
	switch (atoi(&cmd[0])) {
            
      		case 1:	/* Command to send a file to server */
             		filename_len = strlen(cmd);
                    
                        if (filename_len<=2){
                            	printf("Insert file name\n");
                            	continue;
                        }
                
                        filename = malloc(filename_len + 1);
                
                        if(filename == NULL){
                            	printf("Error in allocating memory\n");
                            	return -1;
                        }
                
                        strcpy(filename, cmd + 2);
                
                        /* Function that perform what requested */  
                 	if( send_file_crypt(filename, sk, session_key, session_key_len) < 0 ) 
                            	printf("Error sending the file to the server.\n");
			
			free(filename);
                        break;
                
            case 2:     	/* Command to ask for a list of files contained */
			if(ask_for_the_list(sk, session_key, session_key_len) < 0)
			    	printf("Error asking the file list to the server.\n");
				break;  

	    case 3:	/* Command to download a file from the server, if present */
			
                        filename_len = strlen(cmd);

  			if (filename_len<=2){
                            	printf("Insert file name\n");
                            	continue;
                        }

			filename = malloc(filename_len + 1);
                
                        if(filename == NULL){
                            	printf("Error in allocating memory\n");
                            	return -1;
                        }
                
                        strcpy(filename, cmd + 2);

			/* Function that perform what requested */
			if( recv_file_crypt(filename, sk, session_key, session_key_len) < 0 )
				printf("Error receiving the file from the server.\n");

			free(filename);
			break;

	    case 4:	/* Command to remove a file from the server */

                        filename_len = strlen(cmd);

			if (filename_len<=2){
                            	printf("Insert file name\n");
                            	continue;
                        }

			filename = malloc(filename_len + 1);
                
                        if(filename == NULL){
                            	printf("Error in allocating memory\n");
                            	return -1;
                        }
                
                        strcpy(filename, cmd + 2);

			/* Function that perform what requested */
			if( rmv_file(filename, sk, session_key, session_key_len) < 0 )
				printf("Error in deleting file from the server.\n");

			free(filename);
			break;

	
            case 5:	/* Command to disconnect the client */   
                        printf("Exiting...\n");
			free(cmd);			
                        close(sk);
                        return 0; 
	   
            default:    
                        break;
		}
    	}
    
    	free(cmd);
    	close(sk);
    	return 0;
}
