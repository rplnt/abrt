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
            if ( len<INPUT_LEN ){
                strncpy(addr, input+1, len);
            } else {
                error_msg_and_die("\"%.8s...\" could not fit into memory\n",input);
            }
            addr[len] = '\0';
            rt |= OPT_IP|OPT_PORT;
        } else if ( strchr(input, ':') == p ) {
            //address4:port || hostname:port
            len = strcspn(input,":");
            safe_strcpy(port, p+1, PORT_LEN);
            if ( len<INPUT_LEN ){
                strncpy(addr, input, len);
            } else {
                error_msg_and_die("\"%.8s...\" could not fit into memory\n",input);
            }
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
    int err, i=0;
    bool ignore_next=TRUE; //rfc2616 4.1
    bool head=FALSE;
    gchar buffer[READ_BUF];
    GString *headers = g_string_sized_new(READ_BUF);
    GString *body = NULL;
    struct http_req request = { UNDEFINED, NULL, NULL, NULL };
    
    while ( i < MAX_LINES ) {
        err = (flags & OPT_SSL) ? SSL_read(sock, buffer, READ_BUF-1):
                                  read(*(int*)sock, buffer, READ_BUF-1);
        if ( err < 0 ) {
            //TODO handle errno ||  SSL_get_error(ssl,err);
            break;
        }
        if ( err == 0 ) break;
        buffer[err] = '\0';
        delete_cr(buffer); //CR should be present, but who cares?
        printf ("Received %d chars.\n", (int)strlen(buffer));
        g_string_append(head?body:headers, buffer);

        /* checking for end of header section - useless? */
        if ( head == FALSE && !ignore_next && buffer[0] == '\n' ) {
            parse_head(&request, headers);
            head = TRUE;
            //allocate memory for body or break
            break;
        } else if ( head == FALSE ) {
            ignore_next = (buffer[strlen(buffer)-1] != '\n');
        } else {
            //body
            //stop according to content-length
        }

        i++;
    }


    g_free(headers);
    g_free(body);
    //pass http_req, recieve http_resp
    //send http_resp
    //return wheter close socket or continue listening
    //unallocate shitload of memory
    
}





void parse_head(struct http_req* request, GString* headers)
{
    gchar *p;
    gchar **s_head;
    gchar **s_request = NULL;

//     G_URI_RESERVED_CHARS_ALLOWED_IN_PATH // +/
//     G_URI_RESERVED_CHARS_ALLOWED_IN_PATH_ELEMENT

    /* rfc2616 4.1 */
    if ( headers->str[0] == '\n' ) {
        p = headers->str+1;
    } else {
        p = headers->str;
    }

    /* split by new lines */
    s_head = g_strsplit(p, "\n", -1);

    /* request line */
    s_request = g_strsplit_set(s_head[0], " \t",3);
    request->method = is_valid_method(s_request[0])?hash_method(s_request[0]):UNDEFINED;

    /* rfc2616 something */
    if ( request->method == UNDEFINED ) {
        //TODO 
        /* compatibility with pre-http/1.0 clients allows
         * to have  at firstline url only and assume GET */
    }
    
    
    g_strfreev(s_head);
    g_strfreev(s_request);

}


/* remove CR in place */
void delete_cr(gchar *in)
{
    int index_l=0, index_r=0;
    
    while ( in[index_r] != '\0' ) {
        if ( in[index_r] != '\r' ) {
            in[index_l] = in[index_r];
            index_l++;
        }
        index_r++;
    }
    
    in[index_l] = '\0';
    
}

/* create hash of http method to store in request */
int hash_method(gchar *methodstr)
{
    int rt=0;
    int i=0;

    while ( methodstr[i] != '\0' && rt < 1000 ) {
        rt += (int)g_ascii_tolower(methodstr[i]);
        i++;
    }

    return rt;
}

/* check if method is valid http method */
bool is_valid_method(gchar *m)
{
    return !(g_ascii_strcasecmp(m,"GET") && g_ascii_strcasecmp(m,"POST") &&
           g_ascii_strcasecmp(m,"HEAD") && g_ascii_strcasecmp(m,"DELETE") &&
           g_ascii_strcasecmp(m,"PUT") && g_ascii_strcasecmp(m,"OPTIONS") &&
           g_ascii_strcasecmp(m,"TRACE") && g_ascii_strcasecmp(m,"CONNECT"));
}

