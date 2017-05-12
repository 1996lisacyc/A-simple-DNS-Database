#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include <pthread.h>
#include <ctype.h>
#include "status.h"
#define PORT "12345" 
#define BACKLOG 10 //connections queue
#define SIZE_OF_BUFFER 128
#define flags 0

typedef struct DNS_data dns_record_t;

struct DNS_data{
    char domain[SIZE_OF_BUFFER];
    char ip[SIZE_OF_BUFFER];
}data[100];

int data_counter;
int thread_counter;
char msg[SIZE_OF_BUFFER];//msg to send
pthread_mutex_t mutex;
pthread_t thread[10];
void lock_section(int new_fd);
//////////////////////////////////////////////////////////////

int check_ip(char *str){
    if (str == NULL || *str == '\0')  
      return 1;  
  
   union  
   {  
      struct sockaddr addr;  
      struct sockaddr_in6 addr6;  
      struct sockaddr_in addr4;  
   } a; 
 
   memset (&a, 0, sizeof (a));  

   if (1 == inet_pton (AF_INET, str, &a.addr4.sin_addr))  
      return 0;  
   else if (1 == inet_pton (AF_INET6, str, &a.addr6.sin6_addr))  
      return 0;  
   return 1;  
} // check ip 

void sigchld_handler(int s){
  while(waitpid(-1, NULL, WNOHANG) > 0);
}

void *get_in_addr(struct sockaddr *sa){
  if (sa->sa_family == AF_INET) {
    return &(((struct sockaddr_in*)sa)->sin_addr);
  }
  return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

static inline int server_send(int fd){

    int byte_sent=0;
    char buf[SIZE_OF_BUFFER];
    bzero(buf,SIZE_OF_BUFFER);
    size_t size =strlen(msg);

    if (write(fd, &size, sizeof(size_t)) == -1)
                return -1;

    if (write(fd, msg, size) == -1)
                return -1;

    pthread_mutex_unlock(&mutex);
    lock_section(fd);

    return 0;
}

static inline void server_recv(int fd){

    int len=0, counter=0, exist=-1,i,n;
    char buf[SIZE_OF_BUFFER];
    char tem_name[SIZE_OF_BUFFER];
    char tem_ip[SIZE_OF_BUFFER];
    
    bzero(buf,SIZE_OF_BUFFER);
    bzero(tem_name,SIZE_OF_BUFFER);
    bzero(tem_ip,SIZE_OF_BUFFER);
    bzero(msg,SIZE_OF_BUFFER);

    recv(fd, buf, 4, 0);
    read(fd, buf, SIZE_OF_BUFFER);
    len=strlen(buf);
    pthread_mutex_lock(&mutex);  

    if(buf[0]<65||buf[0]>90||buf[1]<65||buf[1]>90||buf[2]<65||buf[2]>90){

        printf("%d \"%s\"\n",status_code[3], status_str[3]);
        sprintf(msg,"%d \"%s\"\n",status_code[3], status_str[3]);
        //method not allowed

    }else if(!strcmp(buf,"INFO")){

        printf("%d \"%s\" %d\n",status_code[0], status_str[0], data_counter);
        sprintf(msg,"%d \"%s\" %d\n",status_code[0], status_str[0], data_counter);
        //ok, info of data

    }else if(strstr(buf,"SET")){

        for(i=0; i<len; i++){
            if(buf[i]==' '){
                counter++;
            }//count the space
        }        

        if(counter<2){

            printf("%d \"%s\"\n",status_code[1], status_str[1]);
            sprintf(msg, "%d \"%s\"\n",status_code[1], status_str[1]);
            //bad request 

        }else{

            char *test = strtok(buf, " ");
            strcpy(tem_name,test);
            test = strtok(NULL, " ");
            strcpy(tem_name,test);
            test = strtok(NULL, " ");
            strcpy(tem_ip,test);
            test = strtok(NULL, " ");

            bzero(buf,SIZE_OF_BUFFER);;
            strcpy(buf, tem_ip);        
            bzero(tem_ip,SIZE_OF_BUFFER);   
            len=0;

            for(i=0; i<strlen(buf); ){
                if(i<strlen(buf)-1&&buf[i]=='0'&&buf[i+1]=='0'){
                    i++;    
                }else{
                    tem_ip[len]=buf[i];
                    len++;
                    i++;
                }   
            }//check continuous 0

            bzero(buf,SIZE_OF_BUFFER);;
            strcpy(buf, tem_ip);        
            bzero(tem_ip,SIZE_OF_BUFFER);   
            len=0;
            
            for(i=0; i<strlen(buf); ){
                if(i>0&&i<strlen(buf)-1&&buf[i-1]=='.'&&buf[i]=='0'&&buf[i+1]!='0'&&buf[i+1]!='.'){
                    i++;    
                }else{
                    tem_ip[len]=buf[i];
                    len++;
                    i++;
                }   
            }//check 0 behind "." , and before number

            counter=0;
            for(i=0;i<strlen(tem_name); i++){
                if(tem_name[i]=='.'){
                    counter++;
                }
                else{
                    tem_name[i]=tolower(tem_name[i]);
                }
            }//count the . in domain name, always lower case

            if(counter==0||(!strstr(tem_name,"com")&&!strstr(tem_name,"org")&&!strstr(tem_name,"net")&&!strstr(tem_name,"int")&&!strstr(tem_name,"gov")&&!strstr(tem_name,"edu"))){

                printf("%d \"%s\"\n",status_code[1], status_str[1]);
                sprintf(msg, "%d \"%s\"\n",status_code[1], status_str[1]);
                //bad request (domain only have a word) 

            }else if((check_ip(tem_ip) == 0)){

                for(i=0; i<data_counter; i++){
                    if(strstr(data[i].domain, tem_name)){
                        exist=i;
                        strcpy(data[i].ip, tem_ip);
                    }
                }//domain exist in dns data

                if(exist==-1){
                    strcpy(data[data_counter].domain, tem_name);
	                strcpy(data[data_counter].ip, tem_ip);
                    data_counter++;
                }//not exist, update the data

                

                printf("%d \"%s\"\n",status_code[0], status_str[0]);
                sprintf(msg, "%d \"%s\"\n",status_code[0], status_str[0]);
                //ok

            }else{

                printf("%d \"%s\"\n",status_code[1], status_str[1]);
                sprintf(msg, "%d \"%s\"\n",status_code[1], status_str[1]);
                //bad request , invalid ip 

            }
            
        }
        //set domain
    }else if(strstr(buf,"GET")){

        for(i=0; i<len; i++){

            if(buf[i]==' '){
                counter++;
            }//count space
        }        

        if(counter>1){

            printf("%d \"%s\"\n",status_code[1], status_str[1]);
            sprintf(msg, "%d \"%s\"\n",status_code[1], status_str[1]);
            //bad request 

        }else{

            char *test = strtok(buf, " ");
            strcpy(tem_name,test);
            test = strtok(NULL, " ");
            strcpy(tem_name,test);
            test = strtok(NULL, " ");

            counter=0;
            for(i=0;i<strlen(tem_name); i++){
                if(tem_name[i]=='.'){
                    counter++;
                }
                else{
                    tem_name[i]=tolower(tem_name[i]);
                }
            }//count the . in domain name

            for(i=0; i<data_counter; i++){
                    if(strstr(data[i].domain, tem_name)){
                        exist=i;
                    }
            }//domain exist in dns data

            if((counter==0)||(!strstr(tem_name,"com")&&!strstr(tem_name,"org")&&!strstr(tem_name,"net")&&!strstr(tem_name,"int")&&!strstr(tem_name,"gov")&&!strstr(tem_name,"edu"))){

                printf("%d \"%s\"\n",status_code[1], status_str[1]);
                sprintf(msg, "%d \"%s\"\n",status_code[1], status_str[1]);
                //bad request 

            }else if(exist==-1){

                printf("%d \"%s\"\n",status_code[2], status_str[2]);
                sprintf(msg, "%d \"%s\"\n",status_code[2], status_str[2]);
                //not found

            }else{

                printf("%d \"%s\" %s\n",status_code[0], status_str[0],data[exist].ip);
                sprintf(msg, "%d \"%s\" %s\n",status_code[0], status_str[0],data[exist].ip);
                //ok
            }
        }
    }else{

        printf("%d \"%s\"\n",status_code[3], status_str[3]);
        sprintf(msg, "%d \"%s\"\n",status_code[3], status_str[3]);

    }//method not allowed
}

void lock_section(int new_fd){

   server_recv(new_fd);
   server_send(new_fd);
     
} //critical section 

int main(void){

    data_counter=0;

    int sockfd, new_fd, rv;
    int yes=1;
    int check=0;
    char s[INET6_ADDRSTRLEN];
    thread_counter=0;
    struct addrinfo hints, *servinfo, *p;
    struct sockaddr_storage their_addr;
    socklen_t sin_size;
    struct sigaction sa;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE; 

    pthread_mutex_init(&mutex, NULL);//mutex init

    if ((rv = getaddrinfo(NULL, PORT, &hints, &servinfo)) != 0){
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }
    
    for(p = servinfo; p != NULL; p = p->ai_next){
        if ((sockfd = socket(p->ai_family, p->ai_socktype,p->ai_protocol)) == -1){
          perror("server: socket");
          continue;
    }//bind

    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes,sizeof(int)) == -1){
       perror("setsockopt");
       exit(1);
    }

    if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
        close(sockfd);
        perror("server: bind");
        continue;
    }

    break;
  }

  if (p == NULL) {
    fprintf(stderr, "server: failed to bind\n");
    return 2;
  }

  freeaddrinfo(servinfo);

  if (listen(sockfd, BACKLOG) == -1) {
    perror("listen");
    exit(1);
  }

  sa.sa_handler = sigchld_handler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_RESTART;

  if (sigaction(SIGCHLD, &sa, NULL) == -1) {
    perror("sigaction");
    exit(1);
  }

  printf("server: waiting for connections...\n");

  while(1) { //accept
    sin_size = sizeof their_addr;

    if(new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size)){

        inet_ntop(their_addr.ss_family,get_in_addr((struct sockaddr *)&their_addr),s, sizeof s);
        printf("server: got connection from %s\n", s);

        int i=new_fd;
        pthread_create(&thread[thread_counter], NULL, (void*)lock_section, (void*)i);
        thread_counter++;
        //printf("thread counter = %d\n",thread_counter);
    }

  }

  return 0;
}

