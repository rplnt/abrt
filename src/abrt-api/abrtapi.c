#include "abrtapi.h"


/* universal "serve" function */
int serve(void* sock, int flags)
{
    int rt, err, len=0;
    bool clean; //clean cut - last read character was '\n'
    bool head=FALSE;
    gchar buffer[READ_BUF];
    GString *headers = g_string_sized_new(READ_BUF);
    GString *body = NULL;
    struct http_req request = { UNDEFINED, NULL, NULL, NULL, NULL };
    struct http_resp response = { 0, NULL, NULL, NULL, -1, 0 };

    while ( true ) {
        err = (flags & OPT_SSL) ? SSL_read(sock, buffer, READ_BUF-1):
                                  read(*(int*)sock, buffer, READ_BUF-1);

        if ( err < 0 ) {
            //TODO handle errno ||  SSL_get_error(ssl,err);
            break;
        }

        if ( err == 0 ) break;
        buffer[err] = '\0';
        clean = delete_cr(buffer);
        g_string_append(head?body:headers, buffer);

        /* end of header sextion? */
        if ( head == FALSE && (g_strstr_len(buffer, -1, "\n\n") != NULL ||
                                        ( clean && buffer[0] == '\n' )) ) {
            parse_head(&request, headers);
            /* TODO
             * check method (GET, UNDEFINED, ..etc.. doesn't have body)
             * if method has body section
             *   read content-len
             *   allcate memory for body (or break)
             * or break
             */
            body = g_string_sized_new(100); /* TEMP -- read above */
            head = TRUE;
            break;
        } else if ( head == TRUE ) {
            /* TODO
             * read body, check content-len
             * save body to request
             */
            break;
        } else {
            // count header size (make it nicer?)
            len += err;
            if ( len > MAX_HEADER_SIZE ) {
                //TODO header is too long
                break;
            }
        }

    }

    g_string_free(headers, true); //because we allocated it
    if ( head ) {
        request.body = body; //save body
    }

    //FIXME just a test
    gchar *keep = NULL;
    if (request.header_options != NULL ) {
        keep = g_hash_table_lookup(request.header_options, "connection");
    }
    if ( keep != NULL ) {
        http_add_header(&response,"Connection: Keep-Alive");
        rt = 1;
    } else {
        rt = 0;
    }
    //FIXME /just a test

    generate_response(&request, &response);

    /* write headers */
    if ( flags & OPT_SSL ) {
        //TODO err
        err = SSL_write(sock, response.response_line, strlen(response.response_line));
        err = SSL_write(sock, response.head->str , strlen(response.head->str));
    } else {
        //TODO err
        err = write(*(int*)sock, response.response_line, strlen(response.response_line));
        err = write(*(int*)sock, response.head->str , strlen(response.head->str));
    }

    write(*(int*)sock, "\r\n", 2);

    /* message body */
    if        ( request.method != HEAD && response.body != NULL ) {
        err = (flags & OPT_SSL) ? SSL_write(sock, response.body, strlen(response.body)):
                                    write(*(int*)sock, response.body, strlen(response.body));

    } else if ( request.method != HEAD && response.fd != -1 ) {
        while ( (len = read(response.fd, buffer, READ_BUF-1)) > 0 ) {
            err = (flags & OPT_SSL) ? SSL_write(sock, buffer, len):
                                      write(*(int*)sock, buffer, len);
        }
    }

    free_http_request(&request);
    free_http_response(&response);

    return rt;
}

int init_n_socket(char *address, char *port)
{
    int sockfd;
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));

    hints.ai_family     = PF_UNSPEC;
    hints.ai_socktype   = SOCK_STREAM;
    hints.ai_flags     |= AI_CANONNAME;

    if ( getaddrinfo(address, port, &hints, &res) != 0 ) {
        error_msg_and_die(
        "Couldn't get info for connection from \"%s\" on port \"%s\"\n",
        address,port);
    }

    /* create socket */
    sockfd = socket(res->ai_family,res->ai_socktype,0);
    if ( sockfd < 0 ) {
        error_msg_and_die("Creating socket failed: ");
    }

    if ( bind(sockfd, (struct sockaddr*)res->ai_addr, res->ai_addrlen) == -1 ) {
        error_msg_and_die("Bind failed: ");
    }

    freeaddrinfo(res);
    return sockfd;
}


int init_u_socket(char *sock_name)
{
    int sockfd, len;
    struct sockaddr_un u_socket;

    sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if ( sockfd < 0 ) {
        error_msg_and_die("Creating socket failed\n");
    }

    /* create named unix socket */
    strcpy(u_socket.sun_path, sock_name);

    u_socket.sun_family = AF_UNIX;
    //unlink(u_socket.sun_path);
    len = strlen(u_socket.sun_path) + sizeof(u_socket.sun_family);
    if ( bind(sockfd, (struct sockaddr*)&u_socket,len) == -1 ) {
        error_msg_and_die("Bind failed\n");
    }

    return sockfd;
}



/* use only for opts parsing (as it exits) */
bool safe_strcpy(char* dest, const char* src, int max_len)
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
        error_msg_and_die("SSL Error\n");
    }

    return ctx;
}


/* TODO */
void usage_and_exit()
{
    error_msg_and_die("usage");
}

void sigchld_handler(int sig)
{
    waitpid(0, NULL, WNOHANG);
}

int main(int argc, char **argv)
{
    int flags=0; //config flags
    char port[PORT_LEN+1]; //getaddrinfo accepts "string"
    int sockfd; //listening socket
    int sockfd_in; //new connection
    char listen_addr[INPUT_LEN+1]; //used for both types of sockets
    char config_path[INPUT_LEN+1];
    pid_t pid;
    SSL_CTX *ctx;
    struct sigaction sa;
	
    const struct option longopts[] = {
        /* name,            has_arg,         flag, val */
        { "help",           no_argument,        0, '?' },
        { "address",        required_argument,  0, 'a' },
        { "config-file",    required_argument,  0, 'x' },
        { "debug",          no_argument,        0, 'd' },
        { "ssl",            required_argument,  0, 'e' },
        { 0, 0, 0, 0 }
    };


    /* parse command line options */
    while (1) {
        int opt;

        if ( (opt=getopt_long(argc, argv, "a:x:de:?", longopts, NULL)) == -1 ) {
            break;
        }

        switch(opt) {
            case 'e':
                flags |= OPT_SSL;
            case 'a':
                if ( flags & OPT_ADDR ) {
                    error_msg_and_die("Only one listening address is allowed.\n");
                }                
                //call function to check string - socket/ip/port etc
                flags |= parse_addr_input(optarg, listen_addr, port);
                break;
            case 'x':
                safe_strcpy(config_path, optarg, INPUT_LEN);
                flags |= OPT_CFG;
                break;
            case 'd':
                flags |= OPT_DBG;
                break;
            default: /* case: '?' */
                usage_and_exit();
        }
    }


    /* check and supply other settings */
    if ( flags & OPT_CFG ) {
        //TODO load configuration if needed
        /*
         * cert file
         * key file
         * sock name
         * listening address (INADDR_ANY)
         * listening port
         * mode unix/net
         */
    }


    /* prepare socket */
    if ( flags & OPT_SOCK ) {
        //if sock name flag is set use sock_name : otherwise NULL
        sockfd = init_u_socket(listen_addr);
    } else {
        sockfd = init_n_socket(listen_addr,port);
    }
    /* append ssl */
    if ( flags & OPT_SSL ) {
        ctx = init_ssl_context();
        if ( SSL_CTX_use_certificate_file(ctx, CERT_FILE, SSL_FILETYPE_PEM) <= 0 ||
            SSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, SSL_FILETYPE_PEM) <= 0 ) {
            ERR_print_errors_fp(stderr);
            error_msg_and_die("SSL certificates err\n");
        }
        if ( !SSL_CTX_check_private_key(ctx) ) {
            error_msg_and_die("Private key does not match public key\n");
        }
    } else {
        ctx = NULL;
    }
    

    /* listen */
    if ( listen(sockfd, BACKLOG) < 0 ) {
        error_msg_and_die("Listen failed\n");
    }

    /* daemonize */
    if ( !(flags & OPT_DBG) ) {
        pid = fork();
        if ( pid == 0 ) {
            umask(0);
            close(0); //stdin
            close(1); //stdout
            close(2); //stderr
            setsid();
            //syslog TODO
        } else if ( pid == -1 ) {
            error_msg_and_die("Failed to daemonize\n");
        } else {
            fprintf(stderr,"Process started with pid %d\n",pid);
            exit(0); //parent's successful exit
        }
    }


    /* zombie handler */
    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if ( sigaction(SIGCHLD, &sa, NULL) == -1 ) {
        error_msg_and_die("Sigaction fail\n");
    }
    //TODO handle more interrupts (close sockets, ...) ?
    
    
    /* main "server" loop */
    while (1) {
        struct addrinfo sock_in; //client info
        int sock_size = sizeof(struct sockaddr);
        SSL *ssl;
        
        sockfd_in = accept(sockfd, (struct sockaddr*)&sock_in, (socklen_t*)&sock_size);
        if ( sockfd_in < 0 ) {
            //TODO handle errors appropriately - man 2 accept -> Error Handling
            // jump?
            error_msg_and_die("Accept failed\n");
        }
        
        //TODO log according to sock_in family?
        fprintf(stderr,"Connection from %s:%d\n",
               inet_ntoa(((struct sockaddr_in*)&sock_in)->sin_addr),
               ntohs(((struct sockaddr_in*)&sock_in)->sin_port ));

		//gdb: set follow-fork-mode child
        pid = fork();

        /* decide if we're forked process */
        if ( pid == 0 ) {
            if ( close(sockfd) < 0 ) {
                //log errno
            }

            if ( flags & OPT_SSL ) {
                //TODO more errors?
                ssl = SSL_new(ctx);
                SSL_set_fd(ssl, sockfd_in);
                SSL_set_accept_state(ssl);
                if ( SSL_accept(ssl) == 1 ) {
                    //while whatever serve
                    while ( serve(ssl, flags) );
                    //TODO errors
                    SSL_shutdown(ssl);
                }
                SSL_free(ssl);
                SSL_CTX_free(ctx);
            } else {
                //while whatever serve
                while ( serve(&sockfd_in, flags) );
            }

            close(sockfd_in);
            //TODO log errno
            sleep(1); //debug
            exit(1); //!!!
        }
        //else
        if ( close(sockfd_in) < 0 ) {
            //TODO log errno
        }
        
    }

    return 0;
}



/* helper that will clean the problems list */
void free_list(problem_t *item)
{
    g_free(item->id);
    g_free(item->reason);
    g_free(item->time);
    g_free(item);
}


/* remove CR from buffer in-place */
bool delete_cr(gchar *in)
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

    return in[index_l-1]=='\n';
}


/* modified version of rm_trailing_slashes in dump_dir.c */
gchar *rm_slash(const gchar *path)
{
    int len = strlen(path);
    while (len != 0 && path[len-1] == '/') {
        len--;
    }

    return g_strndup(path, len);
}

