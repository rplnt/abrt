#include "abrtapi.h"
#include <libxml2/libxml/tree.h>


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
    struct http_resp response = { UNDECLARED, NULL, NULL, NULL/*, -1*/ };
    
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

    generate_response(&request, &response);

    if ( flags & OPT_SSL ) {
        //TODO err
        err = SSL_write(sock, response.response_line, strlen(response.response_line));
        printf("\n%d ", err);
        err = SSL_write(sock, "\r\n", 2);
        printf("%d ", err);
        err = SSL_write(sock, response.head->str , strlen(response.head->str));
        printf("%d\n", err);
    } else {
        //TODO err
        err = write(*(int*)sock, response.response_line, strlen(response.response_line));
        err = write(*(int*)sock, "\r\n", 2);
        err = write(*(int*)sock, response.head->str , strlen(response.head->str));
    }

    write(*(int*)sock, "\r\n", 2);

    if ( response.body != NULL ) {
        err = (flags & OPT_SSL) ? SSL_write(sock, response.body, strlen(response.body)):
                                    write(*(int*)sock, response.body, strlen(response.body));
    } else if ( response.fd != -1 ) {
        while ( (len = read(response.fd, buffer, READ_BUF-1)) > 0 ) {
            err = (flags & OPT_SSL) ? SSL_write(sock, buffer, len):
                                      write(*(int*)sock, buffer, len);
        }
    }


    /* free request's memory */
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

    const char allowed_uri_chars[] = "0123456789\
                                   abcdefghijklmnopqrstuvwxyz\
                                   ;/?:@=&.%-";
    const char *method_names[] = { "GET", "POST", "DELETE", "HEAD",
                                "PUT", "OPTIONS", "TRACE", "CONNECT", NULL    
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
    for (i=0;method_names[i]!=NULL;i++) {
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

    i = 1;
    /* option headers */
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


/* TODO */
int validate_request(const struct http_req *request)
{
    gchar **url;

    //TODO Host: ??

    /*  one or zero '?' in url */
    url = g_strsplit(request->uri,"?",-1);
    if ( g_strv_length(url) > 2 ) {
        return false;
    }
    g_strfreev(url);

    return true;
}


int switch_route(const gchar *url)
{
    gchar **significant;
    gchar **resources;
    int i, rt=-1;

    /* quick check for root */
    if ( strlen(url) == 1 ) {
        return 0;
    }

    /* we have to throw ?options part out (/route?option wouldn't work) */
    significant = g_strsplit(url,"?",2);

    const gchar *routes[] = { "\\root\\", "problems", NULL
    };

    resources = g_strsplit(significant[0], "/", -1);
    //resources[0] = ""
    for (i=1;routes[i]!=NULL;i++) {
        if ( g_strcmp0(resources[1],routes[i]) == 0 ) {
            rt = i;
            break;
        }
    }

    g_strfreev(significant);
    g_strfreev(resources);

    return rt;
}


int api_entry_point(const struct  http_req *request, struct http_resp *response)
{
    xmlDocPtr doc = NULL;
    xmlNodePtr root = NULL;
    xmlNodePtr node = NULL;
    int body_len;

    /* create xml response */
    doc = xmlNewDoc(BAD_CAST "1.0");
    root = xmlNewNode(NULL, BAD_CAST "api");
    xmlDocSetRootElement(doc, root);
    xmlNewProp(root, BAD_CAST "version", BAD_CAST API_VERSION);

    node = xmlNewNode(NULL, BAD_CAST "link");
    xmlNewProp(node, BAD_CAST "rel", BAD_CAST "problems");
    xmlNewProp(node, BAD_CAST "href", BAD_CAST "/problems/");
    xmlAddChild(root, node);

    /* copy it to http_resp */
    xmlDocDumpFormatMemory(doc, (xmlChar**)&response->body, &body_len, 1);

    response->response_line = g_strdup("HTTP/1.0 200 OK");
    response->code = 200;
    http_add_header(response, "Content-Length: %d", body_len);
    
    xmlFreeDoc(doc);
    xmlCleanupParser();

    return body_len;
}


/* this function is called on request to /api/problems/... */
int api_problems(const struct http_req* request, struct http_resp* response)
{
    gchar **url;
    gchar **options;
    gchar *path;
    gchar *full_path        = NULL;
    gchar *home             = getenv("HOME");
    xmlDocPtr doc           = NULL;
    xmlNodePtr root         = NULL;
    bool include_body;
    int body_len; //content-length
    int ret;

    doc = xmlNewDoc(BAD_CAST "1.0");

    options = g_strsplit(request->uri, "?", 2);
    path = rm_slash(options[0]);
    url = g_strsplit(path, "/", -1);

    // we know that 0 = "" and 1 = "problems"
    if ( g_strv_length(url) == 2 ) {
        // list problems
        root = xmlNewNode(NULL, BAD_CAST "problems");
        list_problems(root);
        include_body = TRUE;
        //it's ok to serve empty list
        
    } else if ( g_strv_length(url) == 3 ) {
        // assume correct id in url[2]
        root = xmlNewNode(NULL, BAD_CAST "problem");
        full_path = g_strjoin("/", DEBUG_DUMPS_DIR, url[2], NULL);
        ret = fill_crash_details(full_path, root);

        /* check home if nothing was found in dump dir */
        if ( !ret && home ) {
            g_free(full_path);
            full_path = g_strjoin("/", home, ".abrt/spool" , url[2], NULL);
            ret = fill_crash_details(full_path, root);
        }

        include_body = TRUE;
        if ( ret == 0 ) {
            http_error(response, 404);
            include_body = FALSE;
        }
        
    } else if ( g_strcmp0(url[3],"dump") == 0 ) {
        // serve memory dump
        include_body = FALSE;
        full_path = g_strjoin("/", DEBUG_DUMPS_DIR, url[2], "coredump", NULL);
        ret = open(full_path, O_RDONLY);
        if ( ret == -1 ) {
            g_free(full_path);
            full_path = g_strjoin("/", home, ".abrt/spool" , url[2], NULL);
            ret = open(full_path, O_RDONLY);
        }

        if ( ret == -1 ) {
            http_error(response, 404);
        } else {
            struct stat buf;
            fstat(ret, &buf);
            body_len = buf.st_size; //bytes
            response->fd = ret;
        }
        
    } else {
        http_error(response, 404);
        include_body = FALSE;
    }

    if (include_body) {
        xmlDocSetRootElement(doc, root);
        xmlDocDumpFormatMemory(doc, (xmlChar**)&response->body, &body_len, 1);
    }

    if ( response->code == UNDECLARED ) {
        response->response_line = g_strdup("HTTP/1.0 200 OK");
        response->code = 200;
        http_add_header(response, "Content-Length: %d", body_len);
    }

    xmlFreeDoc(doc);
    xmlCleanupParser();
    g_free(path);
    g_free(full_path);
    g_strfreev(url);
    g_strfreev(options);

    return body_len;
    
}


/* do basic authentification against PAM and lower privileges */
bool http_authentize(const struct http_req *request)
{
    return true;
}


/*
 * DO NOT add headers any other way
 * 
 * add given line to response's headers and terminate with CR-LF
 */
struct http_resp* http_add_header(struct http_resp* response, const gchar* header_line, ...)
{
    va_list arguments;
    va_start (arguments, header_line);

    if ( response->head == NULL ) {
        response->head = g_string_sized_new(256);
    }
    g_string_append_vprintf(response->head, header_line, arguments);
    response->head = g_string_append(response->head, "\r\n");

    va_end ( arguments );
    
    return response;
}


/*
 * fill out complete(?) response according to error
 * previous contents will be cleared
 */
struct http_resp* http_error(struct http_resp* resp, int error)
{
    g_free(resp->body);
    g_free(resp->response_line);
    if (resp->head != NULL ) {
        g_string_free(resp->head, TRUE);
        resp->head = NULL;
    }
    resp->fd = -1;

    resp->code = error;

    xmlDocPtr doc   = NULL;
    xmlNodePtr root = NULL;
    xmlNodePtr text = NULL;
    int body_len;

    doc = xmlNewDoc(BAD_CAST "1.0");
    root = xmlNewNode(NULL, BAD_CAST "error");
    
    switch (error) {
        case 400:
            resp->response_line = g_strdup("HTTP/1.0 400 Bad Request");
            xmlNewProp(root, BAD_CAST "code", BAD_CAST "400");
            text = xmlNewText(BAD_CAST "Bad Request");
            break;
        case 401:
            resp->response_line = g_strdup("HTTP/1.0 401 Authorization Required");
            xmlNewProp(root, BAD_CAST "code", BAD_CAST "401");
            text = xmlNewText(BAD_CAST "Authorization Required");
            http_add_header(resp, "WWW-Authenticate: Basic");
            break;
        case 404:
            resp->response_line = g_strdup("HTTP/1.0 404 Not Found");
            xmlNewProp(root, BAD_CAST "code", BAD_CAST "404");
            text = xmlNewText(BAD_CAST "Not Found");
            break;
        case 501:
            resp->response_line = g_strdup("HTTP/1.0 501 Not Implemented");
            xmlNewProp(root, BAD_CAST "code", BAD_CAST "501");
            text = xmlNewText(BAD_CAST "Not Implemented");
            break;
        
    }
    xmlAddChild(root, text);

    //TODO copy xml to response + add len
    xmlDocSetRootElement(doc, root);
    xmlDocDumpFormatMemory(doc, (xmlChar**)&resp->body, &body_len, 1);
    xmlFreeDoc(doc);
    xmlCleanupParser();

    http_add_header(resp, "Content-Length: %d",body_len);
    http_add_header(resp, "Connection: close");
    
    return resp;
}


/*
 * prepare ready-to-send http response
 */
void generate_response(const struct http_req *request, struct http_resp *response)
{
    
    if ( !http_authentize(request) ) {
        http_error(response, 401);
        return;
    }

    switch ( request->method ) {
        case UNDEFINED:
            http_error(response, 400);
            break;
        case GET:
            break;
        case HEAD:
            break;
        case POST:
        case DELETE:
        case PUT:
        case OPTIONS:
        case TRACE:
        case CONNECT:
            http_error(response, 501);
    }

    if ( response->code != UNDECLARED ) {
        return;
    }

    /* switch "first level" */
    switch ( switch_route(request->uri) ) {
        case 0: //root node
            api_entry_point(request,response);
            break;
        case 1: //problems
            api_problems(request,response);
            break;
        case -1: //unknown
        default: //broken
            http_error(response, 404);
            break;
    }


}


/* will read whole dir and append all problems to XML tree */
int fill_crash_details(const char* dir_name, xmlNodePtr root)
{
    GList *keys, *p;
    int rt=0;
    crash_data_t *crash_data;
    struct crash_item *item;
    xmlNodePtr node = NULL;
    xmlNodePtr text = NULL;

    DIR *dir = opendir(dir_name);
    
    if (dir != NULL) {
        int sv_logmode = logmode;
        logmode = 0; /* suppress EPERM/EACCES errors in opendir */
        struct dump_dir *dd = dd_opendir(dir_name, /*flags:*/ DD_OPEN_READONLY );
        logmode = sv_logmode;
        
        if ( dd==NULL )  {
            return 0;
        }
        
        crash_data = create_crash_data_from_dump_dir(dd);
        dd_close(dd);
        
    } else {
        return 0;
    }

    keys = g_hash_table_get_keys(crash_data);
    keys = p = g_list_sort(keys, (GCompareFunc)strcmp);

    /* for each "file" create node */
    while (p) {

        item = g_hash_table_lookup(crash_data, p->data);
        if (item) {
            
            node = xmlNewNode(NULL, BAD_CAST "property");
            xmlNewProp(node, BAD_CAST "name", BAD_CAST p->data);

            /* text containing newlines */
            if ( strrchr(item->content, '\n') != NULL )  {
                xmlNewProp(node, BAD_CAST "type", BAD_CAST "text");
                text = xmlNewText(BAD_CAST item->content);
                xmlAddChild(node, text);

            /* unix time stamp */
            } else if ( g_strcmp0(p->data,"time") == 0 ) {
                xmlNewProp(node, BAD_CAST "type", BAD_CAST "time");
                xmlNewProp(node, BAD_CAST "format", BAD_CAST "%s");
                text = xmlNewText(BAD_CAST item->content);
                xmlAddChild(node, text);

            /* integer */
            } else if ( strspn(item->content,"0123456789") == strlen(item->content) ) {
                xmlNewProp(node, BAD_CAST "type", BAD_CAST "integer");
                xmlNewProp(node, BAD_CAST "value", BAD_CAST item->content);

            /* coredump */
            } else if ( g_strcmp0(p->data,"coredump") == 0 ) {
                gchar **parts = g_strsplit(dir_name, "/", -1);
                gchar *id = parts[g_strv_length(parts)-1];
                gchar *full_path = g_strjoin("/", "/api/problems", id, "dump", NULL);
                
                xmlNewProp(node, BAD_CAST "type", BAD_CAST "data");
                xmlNewProp(node, BAD_CAST "href", BAD_CAST full_path);
                
                g_strfreev(parts);
                g_free(full_path);

            /* everything else is treated as line of text */
            } else {
                xmlNewProp(node, BAD_CAST "type", BAD_CAST "line");
                text = xmlNewText(BAD_CAST item->content);
                xmlAddChild(node, text);
            }

            xmlAddChild(root, node);
            rt++;
        }
        
        p = p->next;
    }

    g_list_free(keys);
    g_hash_table_destroy(crash_data);

    return rt;
}


/* this will fill out XML tree for response to /problems/ */
void list_problems(xmlNodePtr root)
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
    g_list_foreach(list, (GFunc)add_problem, root);

    
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
            if ( stat(dump_dir_name, &statbuf) == 0 && S_ISDIR(statbuf.st_mode) ) {
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


/* this will add <problem> to an xml tree */
void add_problem(problem_t *problem, xmlNodePtr root)
{
    char *end;
    char *href;
    char time_str[256];
    xmlNodePtr node = NULL;
    xmlNodePtr time_node = NULL;
    time_t time;

    time = strtol(problem->time, &end, 10);
    if (!errno && !*end && end != problem->time) {
        if ( strftime(time_str, sizeof(time_str), TIME_FORMAT, localtime(&time)) ) {
            href =  g_strjoin("/", "/problems", problem->id, NULL);
            node = xmlNewNode(NULL, BAD_CAST "problem");

            xmlNewProp(node, BAD_CAST "id", BAD_CAST problem->id);
            xmlNewProp(node, BAD_CAST "href", BAD_CAST href);
            xmlNewChild(node, NULL, BAD_CAST "reason", BAD_CAST problem->reason);
            time_node = xmlNewChild(node, NULL, BAD_CAST "time", BAD_CAST time_str);
            xmlNewProp(time_node, BAD_CAST "format", BAD_CAST TIME_FORMAT);

            xmlAddChild(root, node);

            g_free(href);
        }
    }
    
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