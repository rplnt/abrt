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
        fprintf(stderr, "Couldn't get info for \"%s\" on port \"%s\"\n",address,port);
        exit(200);
    }

    /* create socket */
    sockfd = socket(res->ai_family,res->ai_socktype,0);
    if ( sockfd < 0 ) {
        fprintf(stderr,"err: %s\n",strerror(errno));
        exit(6);
    }
    
    /* fill in port and bind */
//     switch ( res->ai_family ) {
//         case AF_INET:
//             ((struct sockaddr_in*)res->ai_addr)->sin_port = htons(port);
//             break;
//         case AF_INET6:
//             ((struct sockaddr_in6*)res->ai_addr)->sin6_port = htons(port);
//             break;
//         default:
//             exit(20);
//     }
    if ( bind(sockfd, (struct sockaddr*)res->ai_addr, res->ai_addrlen) == -1 ) {
        fprintf(stderr,"err: %s\n",strerror(errno));
        exit(7);
    }

    return sockfd;
}



int init_u_socket(char *sock_name)
{
    int sockfd, len;
    struct sockaddr_un u_socket;

    sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if ( sockfd < 0 ) {
        fprintf(stderr,"err: %s\n",strerror(errno));
        exit(6);
    }

    /* create named unix socket */
    strcpy(u_socket.sun_path, sock_name);

    u_socket.sun_family = AF_UNIX;
    //unlink(u_socket.sun_path);
    len = strlen(u_socket.sun_path) + sizeof(u_socket.sun_family);
    if ( bind(sockfd, (struct sockaddr*)&u_socket,len) == -1 ) {
        fprintf(stderr,"err: %s\n",strerror(errno));
        exit(7);
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
void usage_and_exit(int err)
{
    fprintf(stderr,"usage\n");
    
    exit(err%255);
}

void sigchld_handler(int sig)
{
    waitpid(0, NULL, WNOHANG);
}


int parse_addr_input(char* input, char* addr, char* port)
{
    int rt=OPT_ADDR;

    // unix path has to be in form of "/*" or "./*"
    if ( input[0]=='/' || input[0]=='.' ) {
        strcpy(addr,input);
        rt |= OPT_SOCK;
    } else {
        //ip address
        strcpy(addr,input);
        strcpy(port,"8008");

        rt |= OPT_IP;
    }

    return rt;
}



/*
 * 1. read request to buffer
 * 2. ssl
 * 3. http
 * 4. respond
 * 5. wait and iterate
 */
void serve(int sockfd_in)
{
    send(sockfd_in,"Hai",4,0);
    exit(1);
}

void serve_ssl(SSL* ssl)
{
    char buf[100];
    int err = SSL_read(ssl, buf, sizeof(buf) - 1);
    buf[err] = '\0';
    printf ("Received %d chars:'%s'\n", err, buf);
    err = SSL_write(ssl, "This message is from the SSL server",
                    strlen("This message is from the SSL server"));
    err = SSL_shutdown(ssl);
    

}
