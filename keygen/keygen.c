#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define EVP_DES_ECB EVP_CIPHER_key_length(EVP_des_ecb())
#define EVP_DES_CBC EVP_CIPHER_key_length(EVP_des_cbc())


// Funzione per stampare byte
void printbyte(char b) {
  char c;
  c = b;
  c = c >> 4;
  c = c & 15;
  printf("%X", c);
  c = b;
  c = c & 15;
  printf("%X:", c);
}


void select_random_key(unsigned char *k, int b) {
  int i;
  RAND_bytes(k, b);
  for (i = 0; i < b - 1; i++)
    printbyte(k[i]);
  printbyte(k[b-1]);
  printf("\n");
}

int main(int argc, char* argv[]) {
  int ret;
  int key_size;
  unsigned char* key;
  FILE* file;
    
    // Command line arguments check
    if (argc!=2) {
        printf ("Error inserting user name. Usage: %s (username)\n", argv[0]);
        return 1;
    }
    
  
  key_size = EVP_DES_ECB;
  key = malloc(key_size);
  select_random_key(key, key_size);
  
  file = fopen(argv[1], "w");
  if (!file) {
      printf("Errore apertura file\n");
      return 1;
  }
  
  ret = fwrite(key, 1, key_size, file);
  if (ret < key_size) {
      printf("Errore scrittura file\n");
      return 1;
  }
  
  fclose(file);
  free(key);
  
  return 0;
}
