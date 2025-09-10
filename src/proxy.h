#include <stdio.h>

#include <unistd.h>
#include <regex.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <libgen.h>
#include <errno.h>
#include <signal.h>
#include <netdb.h>

#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/err.h>

#define MAXLINE 10000
#define HEADER 9
#define MAX_TIMEOUT 4
#define MAX_CLIENTS 10

#define TIMEOUT 60  
#define MAX_REQUESTS 100  



struct Client
{
    char* client_ip;

    char* domain;
    char* method;
    char* path;
    char* version;
    int connection_port;
    int kill;

    char* flag;
    char* versionflag;

    SSL *ssl;
    SSL_CTX *ssl_ctx; 
};

