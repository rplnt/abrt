#include "abrtapi.h"

void test() {

//     gchar **str;
//     str = g_strsplit("/there is nothing here","/",-1);
//     printf("%d\n", switch_route("/problems"));
//     g_strfreev(str);

    struct http_resp response;
    struct http_req request;

    request.uri = (gchar*)"/problems";

    api_problems(&request, &response);
    
    printf("%s", response.body );
    
    g_free(response.body);
    int a = 1;
    a = fill_crash_details("/var/spool/abrt/ccpp-1302483669-1754aa", NULL);
    
    printf("rt: %d\n",a);

    exit(1);
}


int main(int argc, char **argv)
{
    test();
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
                    serve(ssl, flags);
                    //TODO errors
                    SSL_shutdown(ssl);
                }
                SSL_free(ssl);
                SSL_CTX_free(ctx);
            } else {
                //while whatever serve
                serve(&sockfd_in, flags);
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
