#include "abrtapi.h"

int init_n_socket(char *address, char *port)
{
    int sockfd;
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));

    hints.ai_family     = PF_UNSPEC;
    hints.ai_socktype   = SOCK_STREAM;
    hints.ai_flags     |= AI_CANONNAME;

    if ( getaddrinfo(address, port, &hints, &res) != 0 ) {
        error_msg_and_die("Couldn't get info for connection from \
                            \"%s\" on port \"%s\"\n",address,port);
    }

    /* create socket */
    sockfd = socket(res->ai_family,res->ai_socktype,0);
    if ( sockfd < 0 ) {
        perror_msg_and_die("Creating socket failed\n");
    }
    
    if ( bind(sockfd, (struct sockaddr*)res->ai_addr, res->ai_addrlen) == -1 ) {
        perror_msg_and_die("Bind failed\n");
    }

    return sockfd;
}



int init_u_socket(char *sock_name)
{
    int sockfd, len;
    struct sockaddr_un u_socket;

    sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if ( sockfd < 0 ) {
        perror_msg_and_die("Creating socket failed\n");
    }

    /* create named unix socket */
    strcpy(u_socket.sun_path, sock_name);

    u_socket.sun_family = AF_UNIX;
    //unlink(u_socket.sun_path);
    len = strlen(u_socket.sun_path) + sizeof(u_socket.sun_family);
    if ( bind(sockfd, (struct sockaddr*)&u_socket,len) == -1 ) {
        perror_msg_and_die("Bind failed\n");
    }

    return sockfd;
}



SSL_CTX* init_ssl_context(void)
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    SSL_library_init();
    SSL_load_error_strings();
    method = SSLv23_server_method();
    ctx = SSL_CTX_new(method);
    if ( ctx == NULL ) {
        ERR_print_errors_fp(stderr); //debug?
        exit(55);
    }

    return ctx;
}


/* lala */
void usage_and_exit()
{
    error_msg_and_die("usage");
}

void sigchld_handler(int sig)
{
    waitpid(0, NULL, WNOHANG);
}


/* use only for opts parsing (as it exits) */
bool safe_strcpy(char* dest, char* src, int max_len)
{
    if ( strlen(src) > max_len ) {
        error_msg_and_die("\"%.8s...\" could not fit into memory\n",src);
    }
    strcpy(dest, src);

    return 0;
}


/* function assumes valid input. if it's not, getaddrinfo will fail */
int parse_addr_input(char* input, char* addr, char* port)
{
    int rt=OPT_ADDR;
    int len;

    if ( input[0]=='/' || input[0]=='.' || input[0]=='~' ) {
        //unix path
        safe_strcpy(addr, input, INPUT_LEN);
        rt |= OPT_SOCK;
    } else {
        //network address
        char *p = strrchr(input, ':');
        if ( p == NULL ) {
            //address4 || hostname
            safe_strcpy(addr, input, INPUT_LEN);
            rt |= OPT_IP;
        } else if ( input[0] == '[' ) {
            //[address6]:port
            len = strcspn(input+1,"]");
            safe_strcpy(port, p+1, PORT_LEN);
            len<INPUT_LEN ? strncpy(addr, input+1, len):
                error_msg_and_die("\"%.8s...\" could not fit into memory\n",input);
            addr[len] = '\0';
            rt |= OPT_IP|OPT_PORT;
        } else if ( strchr(input, ':') == p ) {
            //address4:port || hostname:port
            len = strcspn(input,":");
            safe_strcpy(port, p+1, PORT_LEN);
            len<INPUT_LEN ? strncpy(addr, input, len):
                error_msg_and_die("\"%.8s...\" could not fit into memory\n",input);
            addr[len] = '\0';
            rt |= OPT_IP|OPT_PORT;
        } else {
            //address6
            safe_strcpy(addr, input, INPUT_LEN);
            rt |= OPT_IP;
        }
        
    }

    return rt;
}



/* universal server function */
void serve(void* sock, int flags)
{
    int err,i=0;
    bool ignore_next=FALSE;
    gchar buffer[READ_BUF];
    GString *mem = g_string_sized_new(READ_BUF);
    
    while (1) {
        err = (flags & OPT_SSL) ? SSL_read(sock, buffer, READ_BUF-1 ):
                                  read(*(int*)sock, buffer, READ_BUF-1);
        if ( err < 0 ) {
            //TODO handle errno ||  SSL_get_error(ssl,err);
            break;
        }
        buffer[err] = '\0';
        printf ("Received %d chars.\n", err);
        g_string_append(mem,buffer);
        
        if ( !ignore_next && (!g_strcmp0(buffer,"\n") || !g_strcmp0(buffer,"\r\n") || i>16 ) ) break;
        ignore_next = (buffer[err-1] != '\n');
        i++;
    }
    
    printf("%s",mem->str);
    //send this to someone else
    //"he" will decide if we want to wait on the same socket
    //or we will die
    g_free(mem);

    if ( flags & OPT_SSL ) {
        err = SSL_shutdown(sock);
        SSL_free(sock);
    }
    
}



/*
 * 1. read request to buffer
 * 2. ssl
 * 3. http
 * 4. respond
 * 5. wait and iterate
 */
void servex(int sockfd_in)
{
    int err, i=0;
    bool ignore_next=FALSE;
    gchar buffer[READ_BUF];
    GString *mem = g_string_sized_new(READ_BUF);
    printf("well...\n");

    while (1) {
        err = read(sockfd_in, buffer, READ_BUF-1);
        if ( err < 0 ) {
            //TODO handle errno 
            printf("gotcha!\n");
            break;
        }
        buffer[err] = '\0';
        printf ("Received %d chars.\n", err);
        g_string_append(mem,buffer);
        
        if ( !ignore_next && (!g_strcmp0(buffer,"\n") || !g_strcmp0(buffer,"\r\n") || i>16 ) ) break;
        ignore_next = (buffer[err-1] != '\n');
        i++;        
    }

    printf("%s",mem->str);
    g_free(mem);
}



void serve_ssl(SSL* ssl)
{
    int err,i=0;
    bool ignore_next=FALSE;
    gchar buffer[READ_BUF];
    GString *mem = g_string_sized_new(READ_BUF);
    
    while (1) {
        err = SSL_read(ssl, buffer, READ_BUF-1 );
        if ( err < 0 ) {
            //TODO handle SSL_get_error(ssl,err);
            break;
        }
        buffer[err] = '\0';
        printf ("Received %d chars.\n", err);
        g_string_append(mem,buffer);

        if ( !ignore_next && (!g_strcmp0(buffer,"\n") || !g_strcmp0(buffer,"\r\n") || i>16 ) ) break;
        ignore_next = (buffer[err-1] != '\n');
        i++;
    }

    printf("%s",mem->str);
    g_free(mem);

    err = SSL_shutdown(ssl);
    SSL_free(ssl);
}
