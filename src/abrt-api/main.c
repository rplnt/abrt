#include "abrtapi.h"

void test() {
//     gchar **lala;
//     lala = g_strsplit("char\nby\none\n\n", "\n", -1);
// 	printf("lala: %d %s", g_strv_length(lala), lala[0]);

    const char dir_name[] = "/var/spool/abrt";
    int i;
    bool include_reported = true;

    vector_of_crash_data_t *crash_list = new_vector_of_crash_data();

    DIR *dir = opendir(dir_name);
    struct dirent *dent;
    while ((dent = readdir(dir)) != NULL)
    {
        if (dot_or_dotdot(dent->d_name))
            continue; /* skip "." and ".." */

        char *dump_dir_name = concat_path_file(dir_name, dent->d_name);

        struct stat statbuf;
        if (stat(dump_dir_name, &statbuf) == 0
            && S_ISDIR(statbuf.st_mode)
        ) {


            struct dump_dir *dd = dd_opendir(dump_dir_name, /*flags:*/ DD_OPEN_READONLY);

            if (!dd) {
                exit(3);
            }

            crash_data_t *crash_data = create_crash_data_from_dump_dir(dd);
            dd_close(dd);

            add_to_crash_data_ext(crash_data, CD_DUMPDIR, dump_dir_name, CD_FLAG_TXT + CD_FLAG_ISNOTEDITABLE);


            if (crash_data)
                g_ptr_array_add(crash_list, crash_data);
        }
        free(dump_dir_name);
    }
    closedir(dir);




    for (i = 0; i < crash_list->len; ++i)
    {
        crash_data_t *crash = get_crash_data(crash_list, i);
        if (!include_reported)
        {
            const char *msg = get_crash_item_content_or_NULL(crash, FILENAME_REPORTED_TO);
            if (msg)
                continue;
        }

        printf("%u.\n", i);

        GList *list = g_hash_table_get_keys(crash);
        GList *l = list = g_list_sort(list, (GCompareFunc)strcmp);

        while (l)
        {
            const char *key = l->data;
            if (strcmp(key, CD_DUMPDIR) != 0)
            {
                struct crash_item *item = g_hash_table_lookup(crash, key);
                if (item)
                {
                    printf("--------------------\n%s\n-----------------\n%s\n\n\n", key, item->content);
                }
            }
            l = l->next;
        }

        g_list_free(list);


        
    }

        


    

    
    free_vector_of_crash_data(crash_list);
    
	exit(5);
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
	
    struct option longopts[] = {
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
        perror_msg_and_die("Listen failed\n");
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
            perror_msg_and_die("Failed to daemonize\n");
        } else {
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
            perror_msg_and_die("Accept failed\n");
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
