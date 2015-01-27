#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <pthread.h>
void encrypt_it(int *encrypt_len,RSA *keypair,char *msg,char *encrypt)
{
  *encrypt_len = RSA_public_encrypt(strlen(msg)+1, (unsigned char*)msg, (unsigned char*)encrypt,keypair, RSA_PKCS1_OAEP_PADDING);
}
void decrypt_it(int *encrypt_len,RSA *keypair,char *encrypt,char *decrypt)
{
  RSA_private_decrypt(*encrypt_len, (unsigned char*)encrypt, (unsigned char*)decrypt,keypair, RSA_PKCS1_OAEP_PADDING);
}
RSA* put_public_key(int sock)
{
    
    char  *pub_key;//полученый публичный ключ
    BIO *keybio ;
    size_t pub_len=0; 
    recv(sock, &pub_len, sizeof(pub_len), 0);
    pub_key=malloc(pub_len);
    recv(sock, pub_key, pub_len, 0);
    keybio = BIO_new_mem_buf(pub_key,pub_len);
    RSA *rsa = PEM_read_bio_RSAPublicKey(keybio,NULL,NULL, NULL);
    free(keybio);
    return rsa;
}
char* get_public_key(size_t* pub_len,RSA *keypair)
{
  BIO *pub = BIO_new(BIO_s_mem());
  PEM_write_bio_RSAPublicKey(pub, keypair);
  *pub_len = BIO_pending(pub);
  char *pub_key = malloc(*pub_len);
  BIO_read(pub, pub_key, *pub_len);
  return pub_key;
}