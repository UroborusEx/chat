#include <stdio_ext.h>
#include "you_need_it_man.h"
#define PORT 5555
#define KEY_LENGTH  2048
#define PUB_EXP     3
typedef struct for_thread //струтура для передачи аргументов в поток
{
	int sock;
	char* rec;
	char* decrypt;
	int encrypt_len;
	RSA* keypair;
	int *flag;
}For_Thread; 
int try_connect()
{
    int sock;
    struct sockaddr_in addr;
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock < 0)
    {
        perror("socket");
        return -1;
    }
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT); // или любой другой порт...
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);//127.0.0.1
    if(connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        perror("connect");
        return -1;
    }
    return sock;
}
RSA*  prepare_socket(int sock,RSA *keypair)
{
  RSA *temp=put_public_key(sock);
  size_t pub_len;//размер ключа
  char *pub_key=get_public_key(&pub_len,keypair);//массив в котором записан публичный ключ
  send(sock, &pub_len,sizeof(pub_len) , 0);
  send(sock, pub_key, pub_len, 0);
  return temp;
}
void* thread_func(void* arg)
{
  For_Thread* ukaz=(For_Thread*)arg;
  int sock=ukaz->sock;
  char *rec=ukaz->rec;
  char *decrypt=ukaz->decrypt;
  int encrypt_len=ukaz->encrypt_len;
  RSA *keypair=ukaz->keypair;
  int *flag=ukaz->flag;
  int rec_bytes;
  do
  {
    memset(rec, 0, sizeof(rec));
    memset(decrypt, 0, sizeof(decrypt));
    rec_bytes=recv(sock, rec, encrypt_len, 0);
    if(rec_bytes==0||rec_bytes==-1) break;
    decrypt_it(&encrypt_len,keypair,rec,decrypt);
    printf(decrypt);
    fflush(stdout);
  }while(!(strcmp(decrypt ,"quit\n") == 0 ));
  *flag=1;
  printf("Связь сервером потеряна.Нажмите ВВОД для закрытия клиента.");
  fflush(stdout);
}
int main(int argc,char *argv[])
{
    int sock;//сокет для связи
    int encrypt_len=KEY_LENGTH/8;//размер сообщения
    char *buf= malloc(encrypt_len); //буфер для отправляемого текста
    char *encrypt= malloc(encrypt_len); //буфер для шифрования текста
    char *rec= malloc(encrypt_len);//массив для полученного зашифрованного сообщения
    char *decrypt= malloc(encrypt_len);//массив для полученного расшифрованного сообщения
    RSA *rsa= NULL;//структура с публичным ключом сервеера
    char name[17];//имя пользователя
    printf("Введите ваше имя.Не более 16 символов\n");
    fgets(name, 16, stdin);
    *(name+strlen(name)-1)=':';
    *(name+strlen(name))=0;
    __fpurge(stdin);//на случай если пользователь ввел больше 16 символов
    RSA *keypair = RSA_generate_key(KEY_LENGTH, PUB_EXP, NULL, NULL);//генерация пары ключей
    pthread_t thread_write;//указатель на поток для приема сообщений
    sock=try_connect();
    if(sock==-1)
    {
      perror("Не удалось соедениться");
      return -1;
    }
    rsa=prepare_socket(sock,keypair);
    printf("Соединение установлено\n");
    int flag=0;
    For_Thread thread_wr;
    thread_wr.sock=sock;
    thread_wr.rec=rec;
    thread_wr.decrypt=decrypt;
    thread_wr.encrypt_len=encrypt_len;
    thread_wr.keypair=keypair;
    thread_wr.flag=&flag;
    pthread_create(&thread_write, NULL, thread_func,(void*)&thread_wr);
    do
    {
      memset(buf, 0, strlen(buf));
      memset(encrypt, 0, strlen(encrypt));  
      strcpy(buf, name);
      fgets(buf+strlen(name),KEY_LENGTH/8, stdin);
      encrypt_it(&encrypt_len,rsa,buf,encrypt);
      send(sock, encrypt, KEY_LENGTH/8, 0);
      if(flag==1)break;
    }while(!(strcmp(buf+strlen(name) ,"q\n") == 0 || strcmp(buf+strlen(name) ,"Q\n") == 0));
    if(pthread_kill(thread_write,0)==0)pthread_cancel(thread_write);
    close(sock);
    free(buf);
    free(encrypt);
    free(rsa);
    free(decrypt);
    free(rec);
    return 0;
} 
