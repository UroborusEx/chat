#include "you_need_it_man.h"
#define PORT 5555
#define KEY_LENGTH  2048
#define PUB_EXP     3
#define MAX_CLIENTS 10
typedef struct for_server_thread //струтура для передачи аргументов в поток
{
	int sock;
	int* sockets;
	RSA* keypair;
	RSA** all_keys;
	size_t number;
}For_server_Thread; 
void try_connect(int* listener)
{
  struct sockaddr_in addr;//структура адреса сокета
  *listener=socket(AF_INET,SOCK_STREAM,0);
  if(*listener<0)
  {
    perror("socket");
  }
  memset(&addr, '0', sizeof(addr));
  addr.sin_family=AF_INET;
  addr.sin_port=htons(PORT);
  addr.sin_addr.s_addr=htonl(INADDR_ANY);
  if(bind(*listener,(struct sockaddr *)&addr,sizeof(addr))<0)
  {
    perror("blind");
  }
}

RSA*  prepare_socket(int sock,RSA *keypair)
{
  size_t pub_len=0;//размер ключа
  char *pub_key=get_public_key(&pub_len,keypair);//массив в котором записан публичный ключ
  send(sock, &pub_len,sizeof(pub_len) , 0);
  send(sock, pub_key, pub_len, 0);
  return put_public_key(sock);
}

void* thread_accept(void* arg)
{
  int encrypt_len=KEY_LENGTH/8;//длина сообщений
  For_server_Thread* ukaz=(For_server_Thread*)arg;
  char *rec= malloc(encrypt_len);//массив для полученного зашифрованного сообщения
  char *decrypt= malloc(encrypt_len);//массив для полученного расшифрованного сообщения
  int sock=ukaz->sock;
  int *sockets=ukaz->sockets;
  RSA *keypair=ukaz->keypair;
  RSA **all_keys=ukaz->all_keys;
  size_t number=ukaz->number;
  all_keys[number]=prepare_socket(sock,keypair);
  printf("Соединение установлено\n");
  fflush(stdout);
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
    send_all(number,sockets,decrypt,encrypt_len,all_keys);
  }while(!(strcmp(decrypt ,"quit\n") == 0 ));
  close(sockets[number]);
  sockets[number]=0;
  printf("Соединение разорвано\n");
  free(decrypt);
  free(rec);
}
int send_all(int number,int *sockets,char *decrypt,int encrypt_len,RSA** all_keys)
{
  char *buf= decrypt; //буфер для отправляемого текста
  char *encrypt= malloc(encrypt_len); //буфер для шифрования текста
  size_t i;
  for(i=0;i<MAX_CLIENTS;i++)
  {
    fflush(stdout);
    if((sockets[i]!=0)&&(i!=number))
    {
      encrypt_it(&encrypt_len,all_keys[i],buf,encrypt);
      send(sockets[i], encrypt, KEY_LENGTH/8, 0);
    }
  }
  free(encrypt);
}


int add_socket(For_server_Thread thread_wr,pthread_t *thread_write)
{
  size_t i; 
  for(i=0;i<MAX_CLIENTS;i++)
  {
    if(thread_wr.sockets[i]==0)
    {
      thread_wr.sockets[i]=thread_wr.sock;
      break;
    }
  }
  if(i==MAX_CLIENTS)return -1;
  thread_wr.number=i;
  pthread_create(&thread_write[i], NULL, thread_accept,(void*)&thread_wr);
  return 0;
}

int main()
{
  RSA *keypair = RSA_generate_key(KEY_LENGTH, PUB_EXP, NULL, NULL);//генерация пары ключей
  int listener; 
  int *sockets=calloc(MAX_CLIENTS,sizeof(int));
  pthread_t thread_write[MAX_CLIENTS];
  RSA *all_keys[MAX_CLIENTS];
  int sock=-1;
  try_connect(&listener);
  listen(listener,MAX_CLIENTS);
  while(1)
  {
    
    sock=accept(listener,NULL,NULL);
    if(sock<0)
    {
      perror("Не удалось принять соединение");
      return 3;
    }
    For_server_Thread thread_wr;
    thread_wr.sock=sock;
    thread_wr.sockets=sockets;
    thread_wr.keypair=keypair;
    thread_wr.all_keys=all_keys;
    int result=add_socket(thread_wr,thread_write);
    if(result==-1)
    {
      perror("Слишком много соединений");
    }
  }
}