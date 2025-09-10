#include "myproxy.h"

void free_client_resources(struct Client*);
struct Client* init_client(char[]);
void accessLog(struct Client*, int, unsigned long, char*);
void resolve_blocked_file(char*);
char* resolve_hostname(char*);
int check_method(char*);
int connect_to_host(struct Client*);
void resolve_hostnames(char*);
int check_blocklist(char*);
char* create_request(struct Client*, char[], char*);
void err(char*, int);
int sanInt(char*);
char* sanFilename(char*);
void handle_shutdown(int);
void handle_interupt(int);
void clear_blocked_logs();
void handle_client(int, char*, char*, int);
void reap_child_processes(int);
int verify_certificate(SSL*, int);

char* forbidden = NULL;

int main(int argc, char** argv)
{
    if(argc > 8)
        err("Usage: ./myserver <-p listen_port> <-a forbidden_sites_file> <-l access_log_file> <-u>", 1);

    int opt = 0;

    int port = 9090;
    char* forbidden_file = NULL;
    char* access_file = NULL;
    int untrusted = 0;

    while ((opt = getopt(argc, argv, "p:a:l:u")) != -1)
    {
        switch (opt)
        {
        case 'p':
            port = sanInt(optarg);
            break;
        case 'a':
            forbidden_file = sanFilename(optarg);
	    forbidden = sanFilename(optarg);

            if(!forbidden_file)
                err("Issue with Forbidden File naming.", 1);

            break;
        case 'l':
            access_file = sanFilename(optarg);

            if(!access_file)
                err("Issue with Access File naming.", 1);

            break;

	case 'u':
	    untrusted = 1;
	    break;

        default:
            err("Invalid argument", 1);
        }
    }

    if(port < 0)
    {
	err("Incorrect port naming", 1);
	return 1;
    }

    signal(SIGTERM, handle_shutdown);
    signal(SIGINT, handle_interupt);
    signal(SIGCHLD, reap_child_processes);
    signal(SIGTSTP, handle_shutdown);

    printf("listening on port: %d\n", port);

    if (forbidden_file) 
        resolve_blocked_file(forbidden_file);
    

    int server_fd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t server_len = sizeof(server_addr);
    socklen_t client_len = sizeof(client_addr);

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        err("Issue Creating Socket", 1);

    int reuse = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0)
        err("setsockopt failed", 1);

    bzero(&server_addr, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    server_addr.sin_port = htons(port);

    if (bind(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        close(server_fd);
        err("Error binding to port", 1);
    }

    if (listen(server_fd, 10) < 0) {
        close(server_fd);
        err("Error listening for connections", 1);
    }

    if (getsockname(server_fd, (struct sockaddr*)&server_addr, &server_len) == -1) {
        close(server_fd);
        err("getsockname Error", 1);
    }

    char *s_addr = inet_ntoa(server_addr.sin_addr);  

    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    printf("Proxy server listening on port %d\n", port);

    while (1) {
        client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);
        if (client_fd < 0) {
            perror("Accept failed");
            continue;
        }

        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
        printf("Connection accepted from %s\n", client_ip);

        pid_t pid = fork();

        if (pid < 0) {
            perror("Fork failed");
            close(client_fd);
            continue;
        }

        if (pid == 0) {
            close(server_fd);
            handle_client(client_fd, s_addr, access_file, untrusted);
            close(client_fd);
            exit(0);
        } else {
            close(client_fd);
        }
    }

    return 0;
}

void handle_client(int client_fd, char* s_addr, char* access_file, int accept_untrusted) 
{
    char buffer[MAXLINE];
    ssize_t recv_len;
    bool keep_connection = true;
    int request_count = 0;

    struct timeval timeout;
    timeout.tv_sec = TIMEOUT;
    timeout.tv_usec = 0;

    if (setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        err("setsock failed", 1);
    }

    while(keep_connection && request_count < MAX_REQUESTS)
    {
        request_count++;
        memset(buffer, 0, MAXLINE);
        recv_len = recv(client_fd, buffer, MAXLINE-1, 0);

        if (recv_len < 0)
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                printf("Connection timed out\n");
	    else   
                printf("Error receiving data from client\n");
            break;
        }
        else if(recv_len == 0)
        {
            printf("Client disconnected\n");
            break;
        }

        char client_ip[INET_ADDRSTRLEN];
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        getpeername(client_fd, (struct sockaddr*)&client_addr, &client_len);
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);

        struct Client* client = init_client(buffer);
        if (!client) 
	{
            char *error_resp = "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n";
            send(client_fd, error_resp, strlen(error_resp), 0);
            accessLog(NULL, 400, strlen(error_resp), access_file);
            break;
        }

        client->client_ip = strdup(client_ip);

        if (client->kill == 1) 	
            keep_connection = false; 
        

        if(client->flag == NULL)
        {
            char* error_resp = "HTTP/1.1 501 Not Implemented\r\nConnection: close\r\n\r\n";
            send(client_fd, error_resp, strlen(error_resp), 0);
            accessLog(client, 501, strlen(error_resp), access_file);
            free_client_resources(client);
            break;
        }

	if(client->versionflag == NULL)
	{
	    char* error_resp = "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n";
	    send(client_fd, error_resp, strlen(error_resp), 0);
	    accessLog(client, 400, strlen(error_resp), access_file);
	    free_client_resources(client);
	    break;
	}

	if(client->method == NULL || client->path == NULL || client->domain == NULL || client->version == NULL)
	{
	    char* error_resp = "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n";
	    send(client_fd, error_resp, strlen(error_resp), 0);
	    accessLog(client, 400, strlen(error_resp), access_file);
	    free_client_resources(client);
	    break;
	}

        printf("Resolving: %s\n", client->domain);
        char* resolved_ip = resolve_hostname(client->domain);
        printf("Resolved to: %s\n", resolved_ip);

        if(strcmp(resolved_ip, "0.0.0.0") == 0)
        {
            char* error_resp = "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n";
            send(client_fd, error_resp, strlen(error_resp), 0);
            accessLog(client, 502, strlen(error_resp), access_file);
            free(resolved_ip);
            free_client_resources(client);
            break;
        }

        if(check_blocklist(resolved_ip) == 0 || check_blocklist(client->domain) == 0)
        {
            char* error_resp = "HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n";
            send(client_fd, error_resp, strlen(error_resp), 0);
            accessLog(client, 403, strlen(error_resp), access_file);
            free(resolved_ip);
            free_client_resources(client);
            break;
        }

        int target_fd = connect_to_host(client);

        if (target_fd <= 0)
        {
            char *error_resp = "HTTP/1.1 504 Gateway Timeout\r\nConnection: close\r\n\r\n";
            send(client_fd, error_resp, strlen(error_resp), 0);
            accessLog(client, 504, strlen(error_resp), access_file);
            free(resolved_ip);
            free_client_resources(client);
            break;
        }

        SSL_CTX *ctx = SSL_CTX_new(SSLv23_client_method());
        if (!ctx)
        {
            char *error_resp = "HTTP/1.1 504 Gateway Timeout\r\nConnection: close\r\n\r\n";
            send(client_fd, error_resp, strlen(error_resp), 0);
            accessLog(client, 504, strlen(error_resp), access_file);
            close(target_fd);
            free(resolved_ip);
            free_client_resources(client);
            break;
        }

        const char *cert_data = 
	"jwiQuo0W+/CYrw73zjBN9ZwWTqy2PP4YyGJUnYNbcORyK6Htw7jma73KW+f8rns5\n"
	"MdGQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7nlNfGxL/wnQFzY8\n"
	"zGYgahRZoiHAYULfHXMebe/F04arwukTvjDiNQRUqqTY6dqv0J3O0twEwtpmL9pz\n";

	const char *key_data = 
	"MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQC9zHAt6j5wuvCU\n"
	"PZyt3BVwUhpXV9T8OR/EXm5unH87u5wH4PCOAXv20ZpHnakk2aEJj93w88K9xI+8\n";

	BIO *cert_bio = BIO_new_mem_buf(cert_data, -1);
        X509 *cert = PEM_read_bio_X509(cert_bio, NULL, NULL, NULL);
	SSL_CTX_use_certificate(ctx, cert);

	BIO *key_bio = BIO_new_mem_buf(key_data, -1);
	EVP_PKEY *key = PEM_read_bio_PrivateKey(key_bio, NULL, NULL, NULL);
	SSL_CTX_use_PrivateKey(ctx, key);

        if (!accept_untrusted) 
            SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
        else 
            SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
        

        if (!SSL_CTX_load_verify_locations(ctx, "/etc/ssl/certs/ca-bundle.crt", NULL)) 
	{
            if (!accept_untrusted) 
	    {
                char *error_resp = "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n";
                send(client_fd, error_resp, strlen(error_resp), 0);
                accessLog(client, 502, strlen(error_resp), access_file);
                SSL_CTX_free(ctx);
                close(target_fd);
                free(resolved_ip);
                free_client_resources(client);
                break;
            }
        }

        SSL *ssl = SSL_new(ctx);
        if (!ssl)
        {
            char *error_resp = "HTTP/1.1 504 Gateway Timeout\r\nConnection: close\r\n\r\n";
            send(client_fd, error_resp, strlen(error_resp), 0);
            accessLog(client, 504, strlen(error_resp), access_file);
            SSL_CTX_free(ctx);
            close(target_fd);
            free(resolved_ip);
            free_client_resources(client);
            break;
        }

        SSL_set_fd(ssl, target_fd);

        if (SSL_connect(ssl) != 1)
        {
            char *error_resp = "HTTP/1.1 504 Gateway Timeout\r\nConnection: close\r\n\r\n";
            send(client_fd, error_resp, strlen(error_resp), 0);
            accessLog(client, 504, strlen(error_resp), access_file);
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            close(target_fd);
            free(resolved_ip);
            free_client_resources(client);
            break;
        }

        if (!verify_certificate(ssl, accept_untrusted)) 
	{
            char *error_resp = "HTTP/1.1 403 Bad Gateway\r\nConnection: close\r\n\r\n";
            send(client_fd, error_resp, strlen(error_resp), 0);
            accessLog(client, 403, strlen(error_resp), access_file);
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            close(target_fd);
            free(resolved_ip);
            free_client_resources(client);
            break;
        }

        char *request = create_request(client, buffer, s_addr);
        if(!request)
        {
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            close(target_fd);
            free(resolved_ip);
            free_client_resources(client);
            break;
        }

        printf("Forwarding request: \n%s\n", request);

        if (SSL_write(ssl, request, strlen(request)) < 0)
        {
            char *error_resp = "HTTP/1.1 504 Gateway Timeout\r\nConnection: close\r\n\r\n";
            send(client_fd, error_resp, strlen(error_resp), 0);
            accessLog(client, 504, strlen(error_resp), access_file);
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            close(target_fd);
            free(request);
            free(resolved_ip);
            free_client_resources(client);
            break;
        }

        char recv_buffer[4096];
        ssize_t bytes_received;
        unsigned long result = 0;
        int code = 404;
        bool found_connection_close = false;

        while ((bytes_received = SSL_read(ssl, recv_buffer, sizeof(recv_buffer) - 1)) > 0)
        {
            recv_buffer[bytes_received] = '\0';

            if (result == 0 && strncmp(recv_buffer, "HTTP/1.1", 8) == 0)
            {
                char temp_buffer[4096];
                strncpy(temp_buffer, recv_buffer, bytes_received);
                temp_buffer[bytes_received] = '\0';

                char* status_line = strtok(temp_buffer, "\r\n");
                if (status_line) {
                    char* code_ptr = status_line + 9;
                    code = strtol(code_ptr, NULL, 10);
                }
            }

            if (strstr(recv_buffer, "Connection: close") != NULL) {
                found_connection_close = true;
                keep_connection = false;
            }

            result += bytes_received;
            send(client_fd, recv_buffer, bytes_received, 0);
        }

        accessLog(client, code, result, access_file);

        if (found_connection_close || request_count >= MAX_REQUESTS) {
            keep_connection = false;
        }

        SSL_shutdown(ssl);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(target_fd);
        free(request);
        free(resolved_ip);
        free_client_resources(client);

        if (keep_connection) {
            timeout.tv_sec = TIMEOUT;
            timeout.tv_usec = 0;
            setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        }
    }

    printf("Connection closed after %d requests\n", request_count);
}

void free_client_resources(struct Client* client)
{
    if (!client) 
	return;
   
    if(client->method) 
         free(client->method);
    
    if(client->domain)
        free(client->domain);
    
    if(client->path)
        free(client->path);
    
    if(client->version)
         free(client->version);
    
    if (client->client_ip) 
        free(client->client_ip);
    
    if(client) 
         free(client);
}

void reap_child_processes(int signum)
{
    (void)signum;
    while (waitpid(-1, NULL, WNOHANG) > 0);
}

struct Client* init_client(char buffer[MAXLINE])
{
    struct Client *client = malloc(sizeof(struct Client));

    char* tokptr;

    int cli_port = -1;

    char *line = NULL;
    char *buf_cpy = strdup(buffer);    

    line = strtok_r(buf_cpy, "\r\n", &tokptr);
    printf("%s\n", line);

    char* header_cpy = malloc(strlen(line) + 1);
    strcpy(header_cpy, line);

    while((line = strtok_r(NULL, "\r\n", &tokptr)) != NULL)
    {
	printf("%s\n", line);

	if((strncmp("Host:", line, 5)) == 0)
	{
	    line += 5;
	    
	    if((strncmp(" ", line, 1)) == 0)
		line += 1;

	    char *domain = line;
	    
	    char* result;
	    if((result = strchr(domain, ':')) != NULL)
	    {
		result += 1;
		ssize_t domain_size = result - domain - 1;

		char* res = malloc(MAXLINE);
		strncpy(res, domain, domain_size);
		
		res[domain_size] = '\0';
		domain = res;

		cli_port = strtol(result, NULL, 10);
	    }
	   

	   if((result = strchr(domain, ':')) != NULL)
	   {
		client->path = strdup(domain);
	   } 

	    client->connection_port = cli_port;
	    client->domain = strdup(domain);
	}
	else if((strncmp("Connection:", line, 11)) == 0)
	{
	    line += 11;
	    
	    if((strncmp(" ", line, 1)) == 0)
		line += 1;

	    char *kill = line;

	    if((strncmp(kill, "close", 5)) == 0)
	    {
		client->kill = 1;
	    }
	    else if((strncmp(kill, "keep-alive", 10)) == 0)
	    {
		client->kill = 0;
	    }
	    else
	    {
		client->kill = -1;
	    }
	}
	else if((strncmp("Proxy-Connection:", line, 16)) == 0)
	{
	    line += 16;
	    
	    if((strncmp(" ", line, 1)) == 0)
		line += 1;

	    char *kill = line;

	    if((strncmp(kill, "close", 5)) == 0)
	    {
		client->kill = 1;
	    }
	    else if((strncmp(kill, "Keep-Alive", 10)) == 0)
	    {
		client->kill = 0;
	    }
	    else
	    {
		client->kill = -1;
	    }
	}
    }

    char* headertok;

    char* method = strtok_r(header_cpy, " ", &headertok);
    if(check_method(method) < 0)
    {
	client->flag = NULL;
	client->method = method;
    }
    else
    {

        client->flag = "NOT NULL";
        client->method = strdup(method);
    }

    char* path = strtok_r(NULL, " ", &headertok);
    if(!path)
	return NULL;

    char* version = strtok_r(NULL, " ", &headertok);
    if(!version)
	return NULL;

    if(strcmp(version,"HTTP/1.1"))
	client->versionflag = NULL;
    else
	client->versionflag = "NOT NULL";

    client->path = strdup(path);
    client->version = strdup(version);

    if(cli_port < 0)
        client->connection_port = 443;

    return client;
}

void accessLog(struct Client* client, int code, unsigned long bytes, char* access_file) 
{
    struct timeval tv;
    struct tm *timeinfo;
    char buffer[80];

    gettimeofday(&tv, NULL);
    timeinfo = gmtime(&tv.tv_sec);

    strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%S", timeinfo);

    char* domain;
    char* method;
    char* client_ip;
    char* version;

    if(!client)
    {
	domain = "undefined";
	method = "GET";
	client_ip = "0.0.0.0";
	version = "HTTP/1.1";
    }
    else
    {
	domain = client->domain;
	method = client->method;
	client_ip = client->client_ip;
	version = client->version;
    }

    int logfd = open(access_file, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if(logfd < 0)
    {
	printf("unable to log\n");
	return;
    }

    char* entry = malloc(MAXLINE);
    sprintf(entry, "%s.%03ldZ %s \"%s %s %s\" %d %ld\n", buffer, tv.tv_usec / 1000, client_ip, method, domain, version, code, bytes);

    printf("%s\n", entry);

    if(write(logfd, entry, strlen(entry)) < 0)
    {
	close(logfd);
	printf("unable to log1\n");
	return;
    }

    close(logfd);
}

void resolve_blocked_file(char* forbidden_file) 
{
    int fd_in = open(forbidden_file, O_RDONLY);
    if (fd_in < 0) {
        err("Can't open forbidden file", 1);
    }

    int fd_out = open("blocked.txt", O_CREAT | O_TRUNC | O_WRONLY, 0644);
    if (fd_out < 0) {
        close(fd_in);
        err("Can't open output file", 1);
    }

    char file_buffer[MAXLINE];
    int n;
    while ((n = read(fd_in, file_buffer, sizeof(file_buffer) - 1)) > 0) 
    {
        char* tokptr;
	file_buffer[n] = '\0';
        char* line = strtok_r(file_buffer, "\n", &tokptr);

        int entries = 0;
        while (line != NULL) 
	{
	    if(strncmp(line, ":", 1) == 0)
	        continue;

            char* ipstr = resolve_hostname(line);
            if (ipstr) 
	    {
                write(fd_out, ipstr, strlen(ipstr));
                write(fd_out, "\n", 1);

		write(fd_out, line, strlen(line));
		write(fd_out, "\n", 1);

                free(ipstr);
		entries++;
            }
            line = strtok_r(NULL, "\n", &tokptr);
        }
	if(entries > 1000)
	    break;
    }

    close(fd_in);
    close(fd_out);
}

char* resolve_hostname(char* domain)
{
    struct addrinfo hints, *res, *p;
    char ipstr[INET6_ADDRSTRLEN];

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(domain, NULL, &hints, &res) == 0) 
    {
        p = res;
    } 
    else 
    {
        hints.ai_family = AF_INET6;
        if (getaddrinfo(domain, NULL, &hints, &res) != 0)
       	{
            return strdup("0.0.0.0");
        }
        p = res;
    }

    void *addr;
    if (p->ai_family == AF_INET)
    {
        struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
        addr = &(ipv4->sin_addr);
    }
    else 
    {
        struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)p->ai_addr;
        addr = &(ipv6->sin6_addr);
    }

    inet_ntop(p->ai_family, addr, ipstr, sizeof(ipstr));
    freeaddrinfo(res);

    return strdup(ipstr);
}

int check_method(char* method)
{
    if (strcmp(method, "GET") == 0 || strcmp(method, "HEAD") == 0)
        return 0;
    return -1;
}

int connect_to_host(struct Client* client) {
    int sockfd;
    struct sockaddr_in server_addr;
    char* ip_addr = resolve_hostname(client->domain);

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        free(ip_addr);
        return 0;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(client->connection_port);

    if (inet_pton(AF_INET, ip_addr, &server_addr.sin_addr) <= 0) {
        close(sockfd);
        free(ip_addr);
        return 0;
    }

    struct timeval timeout;
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;

    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        perror("setsockopt failed");
    }

    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        close(sockfd);
        free(ip_addr);
        return 0;
    }

    free(ip_addr);
    return sockfd;
}

int check_blocklist(char* ip)
{
    int fd_in = open("blocked.txt", O_RDONLY);
    if(fd_in < 0)
        return 1;  

    char file_buffer[MAXLINE];
    int n;
    while ((n = read(fd_in, file_buffer, sizeof(file_buffer) - 1)) > 0)
    {
        file_buffer[n] = '\0';
        char* line = strtok(file_buffer, "\n");
        while (line != NULL)
        {
            if(strcmp(line, ip) == 0) 
	    {
                close(fd_in);
                return 0; 
            }
            line = strtok(NULL, "\n");
        }
    }

    close(fd_in);
    return 1;  
}

char* create_request(struct Client* client, char buffer[MAXLINE], char* s_addr)
{
    char* buffer_copy = strdup(buffer);
    if (!buffer_copy) 
        return NULL;
    
    char* response = malloc(MAXLINE * 2);
    if (!response) 
    {
        free(buffer_copy);
        return NULL;
    }
    
    char* saveptr;
    char* first_line = strtok_r(buffer_copy, "\r\n", &saveptr);
    if (!first_line) 
    {
        free(buffer_copy);
        free(response);
        return NULL;
    }
    
    int len = snprintf(response, MAXLINE * 2, "%s %s %s\r\n", client->method, client->path, client->version);
    
    char* next_line;
    while ((next_line = strtok_r(NULL, "\r\n", &saveptr)) != NULL)
    {
	if((strncmp("Proxy-Connection", next_line, 16)) == 0)
	{
	    char* req = "Connection: keep-alive";
	    len += snprintf(response + len, (MAXLINE * 2) - len, "%s\r\n", req);
	}
	else
	{
            len += snprintf(response + len, (MAXLINE * 2) - len, "%s\r\n", next_line);
	}
    }
    
    char* forward = "X-Forwarded-For:";
    len += snprintf(response + len, (MAXLINE * 2) - len, "%s %s, %s\r\n", forward, client->client_ip, s_addr);

    len += snprintf(response + len, (MAXLINE * 2) - len, "\r\n");
    
    free(buffer_copy);
    return response;
}
void err(char* msg, int code) {
    fprintf(stderr, "%s\n", msg);
    exit(code);
}

int sanInt(char* char_port) {
    regex_t regex;
    const char* pattern = "^[0-9]+$";

    if (regcomp(&regex, pattern, REG_EXTENDED) != 0) {
        regfree(&regex);
        return -1;
    }

    int exec = regexec(&regex, char_port, 0, NULL, 0);
    regfree(&regex);

    if (exec != 0) {
        return -1;
    }

    int port = strtol(char_port, NULL, 10);
    return (port > 0 && port < 65536) ? port : -1;
}

char* sanFilename(char* url) {
    regex_t regex;
    const char* pattern = "^[a-zA-Z0-9$-_.+!*'(),]+$";

    if (regcomp(&regex, pattern, REG_EXTENDED) != 0) {
        return NULL;
    }

    int exec = regexec(&regex, url, 0, NULL, 0);
    regfree(&regex);

    if (exec == 0)
        return url;
    else
        return NULL;
}

void handle_shutdown(int signum) {
    (void) signum;
    printf("Shutting down gracefully...\n");
    while (waitpid(-1, NULL, WNOHANG) > 0);

    if(unlink("blocked.txt") == 0)
    {
	printf("Successfully deleted blocked.txt\n");
    }

    exit(0);
}

void handle_interupt(int signum) 
{
    (void) signum;
    printf("Interrupt received, reloaded file\n");
    clear_blocked_logs();
}

void clear_blocked_logs()
{
    if(unlink("blocked.txt") == 0)
    {
	printf("Successfully deleted blocked.txt\n");
    }
 
    resolve_blocked_file(forbidden); 
}

int verify_certificate(SSL *ssl, int accept_untrusted) 
{
    X509 *cert = SSL_get_peer_certificate(ssl);
    if (!cert) {
        printf("No certificate provided\n");
        return 0;
    }

    if (accept_untrusted) {
        printf("Warning: Certificate verification bypassed with -untrusted flag\n");
        X509_free(cert);
        return 1;
    }

    long verify_result = SSL_get_verify_result(ssl);
    if (verify_result != X509_V_OK) {
        printf("Certificate verification failed: %s\n",
               X509_verify_cert_error_string(verify_result));
        X509_free(cert);
        return 0;
    }

    printf("Certificate verification successful\n");
    X509_free(cert);
    return 1;
}
