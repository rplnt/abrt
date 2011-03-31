#include "abrtapi.h"


int main(int argc, char **argv)
{
    int flags=0; //config flags
    char port[8]; //getaddrinfo accepts "string"
    int sockfd; //listening socket
    int sockfd_in; //new connection
    char listen_addr[100]; //used for both types of sockets
    char config_path[100];
    pid_t pid;
    SSL_CTX *ctx;
    struct sigaction sa;

  
    /* parse command line options */
    while (1) {
        int opt;

        if ( (opt=getopt_long(argc, argv, "ua:x:de:?", longopts, NULL)) == -1 ) {
            break;
        }

        switch(opt) {
            case 'e':
                flags |= OPT_SSL;
            case 'a':
                if ( flags & OPT_ADDR ) {
                    fprintf(stderr,"only one connection atm\n");
                    exit(19);
                }                
                //call function to check string - socket/ip/port etc
                flags |= parse_addr_input(optarg, listen_addr, port);
                break;
            case 'x':
                if ( strlen(optarg) > 99 ) {
                    fprintf(stderr,"err: Invalid parameter: config-file\n");
                }
                strcpy(config_path, optarg);
                flags |= OPT_CFG;
                break;
            case 'd':
                flags |= OPT_DBG;
                break;
            default: /* case: '?' */
                usage_and_exit(6);
        }
    }

//     if ( flags & OPT_ADDR && flags & OPT_SSL ) {
//         fprintf(stderr,"Only one listening socket is supported at the moment.\n");
//         usage_and_exit(20);
//     }

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
            exit(88);
        }
        if ( !SSL_CTX_check_private_key(ctx) ) {
            fprintf(stderr,"err: SSL: check key fail\n");
            exit(32);
        }
    }


    /* listen */
    if ( listen(sockfd, BACKLOG) < 0 ) {
        fprintf(stderr,"err: %s\n",strerror(errno));
        exit(8);
    }

    /* daemonize */
    if ( !(flags & OPT_DBG) ) {
        pid = fork();
        if ( pid == 0 ) {
            umask(0);
            close(0); //stdin
            close(1); //stdout
            close(2); //stderr
            if ( setsid() == -1 ) {
                fprintf(stderr,"daemon err 2\n");
            }
            //syslog
        } else if ( pid == -1 ){
            fprintf(stderr,"daemon err\n");
            exit(1);
        } else {
            exit(0);
        }
    }


    /* zombie handler */
    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if ( sigaction(SIGCHLD, &sa, NULL) == -1 ) {
        fprintf(stderr,"err: sigaction fail\n");
        exit(9);
    }
    //TODO handle more interrupts (close sockets, ...) ?
    
    
    /* main "server" loop */
    while (1) {
        struct addrinfo sock_in; //client info
        int sock_size = sizeof(struct sockaddr);
        SSL *ssl;
        
        sockfd_in = accept(sockfd, (struct sockaddr*)&sock_in, &sock_size);
        if ( sockfd_in < 0 ) {
            fprintf(stderr,"err: %s\n",strerror(errno));
            exit(10);
        }
        //log according to sock_in family ?
        fprintf(stderr,"Connection from %s:%d\n",
               inet_ntoa(((struct sockaddr_in*)&sock_in)->sin_addr),
               ntohs(((struct sockaddr_in*)&sock_in)->sin_port ));

        pid = fork();

        /* decide if we're forked process */
        if ( pid == 0 ) {
            if ( close(sockfd) < 0 ) {
                fprintf(stderr,"err: %s\n",strerror(errno));
                exit(11);
            }

            if ( flags & OPT_SSL ) {
                ssl = SSL_new(ctx);
                SSL_set_fd(ssl, sockfd_in);
                SSL_accept(ssl);
                serve_ssl(ssl);                
            } else {
                serve(sockfd_in);
            }

            close(sockfd_in);
            sleep(1); //debug
            exit(1); //!!!
        }
        //else
        if ( close(sockfd_in) < 0 ) {
            fprintf(stderr,"err: %s\n",strerror(errno));
            exit(13);
        }
        
    }

    return 0;
}
