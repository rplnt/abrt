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

    freeaddrinfo(res);
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


/* TODO - delete obviously */
void print_headers(const gchar *key, const gchar *value) {
    printf("> %s: %s\n",key, value);
}



/* universal server function */
void serve(void* sock, int flags)
{
    int err, len=0;
    bool clean; //clean cut - last read character was '\n'
    bool head=FALSE;
    gchar buffer[READ_BUF];
    GString *headers = g_string_sized_new(READ_BUF);
    GString *body = NULL;
    struct http_req request = { UNDEFINED, NULL, NULL, NULL, NULL };
    
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

    //pass http_req, recieve http_resp
    //send http_resp



    
    /* free memory */
    if ( request.method != UNDEFINED ) {
        /* check */
        printf("Requested path: %s\nOptions:\n", request.uri);
        g_hash_table_foreach(request.header_options, (GHFunc)print_headers, NULL);
        /* /check */
        g_free(request.uri);
        g_free(request.version);
        g_hash_table_unref(request.header_options);
        if ( head ) {
            g_string_free(request.body, true);
        }
    }

    return;
}




void parse_head(struct http_req* request, const GString* headers)
{
    int i,len;
    gchar *p;
    gchar *uri          = NULL;
    gchar *version      = NULL;
    gchar *prev_key     = NULL;
    gchar **s_temp      = NULL;
    gchar **s_head      = NULL;
    gchar **s_request   = NULL;
    GHashTable *h_opts  = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);

    static char allowed_uri_chars[] = "0123456789\
                                   abcdefghijklmnopqrstuvwxyz\
                                   ;/?:@=&.%";
    static char method_names[][8] = { "GET", "POST", "DELETE", "HEAD",
                                "PUT", "OPTIONS", "TRACE", "CONNECT"    
    };


    /* rfc2616 4.1 */
    if ( headers->str[0] == '\n' ) {
        p = headers->str+1;
    } else {
        p = headers->str;
    }

    /* split by new lines */
    s_head = g_strsplit(p, "\n", -1);
    len = g_strv_length(s_head) - 2; // because of \n\n at the end

    /* request line */
    s_request = g_strsplit_set(s_head[0], " \t",3);
	if ( g_strv_length(s_request) != 3 ) {
		goto stop;
	}

    /* request method */
    for (i=0; i<METHODS_CNT; i++ ) {
        if ( g_ascii_strcasecmp(s_request[0], method_names[i]) == 0 ) {
            request->method = i+1; // 0 = UNDEFINED
            break;
        }
    }

    /* get URL from the request
     * there is no particular limit in url (or any other option) length
     * maximum header size is given by MAX_HEADER_SIZE
     */
    if ( s_request[1][0] != '/' ) {
        if ( g_uri_parse_scheme(s_request[1]) == NULL ) {
            request->method = UNDEFINED;
            goto stop;
        }
        //url is in format xxx://hostname/rest .. we want the rest
        s_temp = g_strsplit(s_request[1],"/",4);
        uri = g_strjoin(NULL, "/", s_temp[3], NULL);
        g_strfreev(s_temp);
        //might be a good idea to save the hostname?
    } else {
        if ( strspn(s_request[1], allowed_uri_chars) == strlen(s_request[1]) ) {
            uri = g_strdup(s_request[1]);
        } else {
            request->method = UNDEFINED;
            goto stop;
        }
    }
    

    /* version and other stuff */
    version = strdup(s_request[2]);
    
    /* option headers */
    i = 1;
    while ( i < len ) {
        gchar *value, *key, *new_value, **key_value;

        if ( s_head[i][0] == '\t' || s_head[i][0] == ' ' ) {
            //continuation of previous header
            value = g_hash_table_lookup(h_opts, prev_key);
            if ( value == NULL ) {
                goto stop;
            }
            new_value = g_strjoin(NULL, value, g_strchomp(g_strchug(s_head[i])), NULL);
            //TODO check valid characters
            g_hash_table_replace(h_opts, g_strdup(prev_key), new_value);
        } else {
            //new key
            key_value = g_strsplit(s_head[i],": ",-1);
            if ( g_strv_length(key_value) != 2 ) {
                g_strfreev(key_value);
                key_value = g_strsplit(s_head[i],":\t",-1);
                if ( g_strv_length(key_value) != 2 ) {
                    g_strfreev(key_value);
                    goto stop;
                }
            }
            key = g_ascii_strdown(key_value[0], -1);
            new_value = g_strdup(g_strchomp(g_strchug(key_value[1])));
            //validate key/value
            
            value = g_hash_table_lookup(h_opts, key);
            if ( value != NULL ) {
                g_hash_table_replace(h_opts, key, g_strjoin(NULL, value, new_value, NULL));
                g_free(new_value);
            } else {
                g_hash_table_insert(h_opts, key, new_value);
            }

            g_free(prev_key);
            prev_key = g_strdup(key);

            g_strfreev(key_value);
        }
        fflush(stderr);
        i++;
    }
    g_hash_table_ref(h_opts);
    
    /* fill out request's fields */
    request->header_options = h_opts;
    request->version = strdup(version);
    request->uri = g_strdup(uri);

stop:
    fflush(stderr);
    g_free(uri);
    g_free(version);
    g_free(prev_key);
    g_strfreev(s_head);
    g_strfreev(s_request);
    g_hash_table_unref(h_opts);
    
}


void generate_response(const struct http_req *request, struct http_resp *response)
{
    // prepare XML tree and route
    /* route '/' - TODO
     * route '/problems' - list_problems();
     * route '/problems/id' - read_crash_details();
     */
}



/* will read whole dir and append all problems to XML tree */
void fill_crash_details(const char* dir_name /* TODO XML */)
{
    GList *keys, *p;
    crash_data_t *crash_data;
    struct crash_item *item;

    int sv_logmode = logmode;
    logmode = 0; /* suppress EPERM/EACCES errors in opendir */
    struct dump_dir *dd = dd_opendir(dir_name, /*flags:*/ DD_OPEN_READONLY);
    logmode = sv_logmode;

    crash_data = create_crash_data_from_dump_dir(dd);
    dd_close(dd);

    keys = g_hash_table_get_keys(crash_data);
    keys = p = g_list_sort(keys, (GCompareFunc)strcmp);

    while (p) {
        printf("*");
        item = g_hash_table_lookup(crash_data, p->data);
        if ( item && !strchr(item->content,'\n') ) {
            printf("[%s] ", (char*)p->data); //key
            printf("%s\n", item->content); //data
        }
        p = p->next;
    }

    g_list_free(keys);
    g_hash_table_destroy(crash_data);

    return;
}


/* this will fill out XML tree for response to /problems/ */
void list_problems(/*TODO xml*/)
{
    char *home;
    char *home_path;
    GList *list = NULL;

    home = getenv("HOME");
    if ( home ) {
        home_path = concat_path_file(home, ".abrt/spool");
        list = create_list(list, home_path);
        free(home_path);
    }
    list = create_list(list, (char*)DEBUG_DUMPS_DIR);

    /* now on each list item call add_problem (to prepared XML tree) */
    g_list_foreach(list, (GFunc)add_problem, (void*)"--------");

    
    // g_list_free_full(list, (GDestroyNotify)free_list); //since 2.28
    g_list_foreach(list, (GFunc)free_list, NULL);
    g_list_free(list);
}




/* add problems' summary from given direcotry to a list */
GList* create_list(GList *list, char* dir_name)
{
    char *dump_dir_name;
    DIR *dir;
    struct dump_dir *dd;
    char *reason = NULL, *time = NULL;
    int sv_logmode = logmode;

    /* open "root" report dir */
    logmode = 0;
    dir = opendir(dir_name);

    if ( dir != NULL ) {
        struct dirent *dent;
        while ( (dent = readdir(dir)) != NULL ) {
            if (dot_or_dotdot(dent->d_name)) {
                continue; /* skip "." and ".." */
            }
            dump_dir_name = concat_path_file(dir_name, dent->d_name);

            struct stat statbuf;
            if ( stat(dump_dir_name, &statbuf) == 0 && S_ISDIR(statbuf.st_mode ) ) {
                dd = dd_opendir(dump_dir_name, DD_OPEN_READONLY);
                if ( dd != NULL ) {
                    problem_t *problem;
                    reason = dd_load_text(dd, "reason");
                    time = dd_load_text(dd, "time");
                    problem = g_try_malloc(sizeof(problem_t));
                    if ( problem == NULL ) {
                        //break, clean and respond with error somehow
                        //return NULL; //can't - would lost list :/
                    }
                    problem->id = g_strdup(dent->d_name);
                    problem->reason = reason;
                    problem->time = time;

                    list = g_list_prepend(list, problem);

                    dd_close(dd);
                }

            }
            free(dump_dir_name);

        }
        closedir(dir);
    }

    /* back to normal logmode */
    logmode = sv_logmode;

    return list;
}


/* this will add <problem> to xml tree */
void add_problem(problem_t *problem /* TODO XML */)
{
    char *end;
    char time_str[256];
    time_t time;

    time = strtol(problem->time, &end, 10);
    if (!errno && !*end && end != problem->time) {
        if ( strftime(time_str, sizeof(time_str), "%c", localtime(&time)) ) {
            printf("%s\n\t%s\n\t%s\n", problem->id, problem->reason, time_str);
        }
    }
    //printf("%s\n\t%s\n\t%s\n", problem->id, problem->reason, problem->time);
}


/* helper that will clean the problems list */
void free_list(problem_t *item)
{
    g_free(item->id);
    g_free(item->reason);
    g_free(item->time);
    g_free(item);
}


/* remove CR in place and return last character */
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

