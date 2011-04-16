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

/* free response's memory */
void free_http_response(struct http_resp *resp)
{
    if ( resp->body ) {
        if ( resp->format == XML ) {
            xmlFree(BAD_CAST resp->body);
        } else {
            g_free(resp->body);
        }
    }
    if ( resp->head ) {
        g_string_free(resp->head, true);
    }
    if ( resp->response_line ) {
        g_free(resp->response_line);
    }

}

/* free request's memory */
void free_http_request(struct http_req *req)
{
    if ( req->uri ) {
        g_free(req->uri);
    }
    if ( req->version ) {
        g_free(req->version);
    }
    if ( req->header_options ) {
        g_hash_table_unref(req->header_options);
    }
    if ( req->body ) {
        g_string_free(req->body, true);
    }

}


/* universal server function */
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




void parse_head(struct http_req* request, const GString* headers)
{
    int i,len;
    gchar *uri          = NULL;
    gchar *version      = NULL;
    gchar *prev_key     = NULL;
    gchar **s_temp      = NULL;
    gchar **s_head      = NULL;
    gchar **s_request   = NULL;
    GHashTable *h_opts  = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);

    const char allowed_uri_chars[] = "0123456789abcdefghijklmnopqrstuvwxyz;/?:@=&.%-";
    const char *method_names[] = { "GET", "POST", "DELETE", "HEAD",
                                "PUT", "OPTIONS", "TRACE", "CONNECT", NULL    
    };
    

    /* split by new lines */
    s_head = g_strsplit(headers->str, "\n", -1);
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
    // no //

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

    const gchar *routes[] = { "\\root\\", "problems", "static", NULL
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


void api_entry_point(const struct  http_req *request, struct http_resp *response)
{
    gchar *type;
    GString *content;
    xmlDocPtr doc = NULL;
    xmlNodePtr root = NULL;
    xmlNodePtr node = NULL;
    int body_len;

    type = http_get_type_text(response->format);

    if ( response->format == XML ) {
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
        
    } else if ( response->format == HTML ) {
        content = g_string_sized_new(1024);
        add_html_head(content, "Abrt API Entry Point");
        g_string_append(content, "  <div style=entry>");
        g_string_append(content,
                        "  <a href=\"/problems/\" rel=\"problems\">List Problems</a>");
        g_string_append(content, "  </div>\n </body>\n</html>\n");
        response->body = g_string_free(content, FALSE);
        body_len = strlen(response->body);
        
    } else if ( response->format == JSON ) {
        response->body = g_strdup("Not supported\n");
        body_len = strlen(response->body);
        
    } else if ( response->format == PLAIN ) {
        response->body = g_strdup("abrt api\n/problems/\n");
        body_len = strlen(response->body);
        
    }

    http_response(response, 200);
    http_add_header(response, "Content-Length: %d", body_len);
    http_add_header(response, "Content-Type: %s", type);

    g_free(type);
    xmlFreeDoc(doc);
    xmlCleanupParser();
}


/* this function is called on request to /api/problems/... */
void api_problems(const struct http_req* request, struct http_resp* response)
{
    gchar **url;
    gchar **options;
    gchar *path;
    gchar *type;
    gchar *full_path        = NULL;
    gchar *home             = getenv("HOME");
    int body_len = 0; //content-length
    int ret;

    gchar *content = NULL;

    type = http_get_type_text(response->format);
    options = g_strsplit(request->uri, "?", 2);
    path = rm_slash(options[0]);
    url = g_strsplit(path, "/", -1);

    // we know that 0 = "" and 1 = "problems"
    if ( g_strv_length(url) == 2 ) {
        // list problems
        content = list_problems(response->format);
        //it's ok to serve empty list
        
    } else if ( g_strv_length(url) == 3 ) {
        // assume correct id in url[2]
        full_path = g_strjoin("/", DEBUG_DUMPS_DIR, url[2], NULL);
        content = fill_crash_details(full_path, response->format);

        /* check home if nothing was found in dump dir */
        if ( !content && home ) {
            g_free(full_path);
            full_path = g_strjoin("/", home, ".abrt/spool" , url[2], NULL);
            content = fill_crash_details(full_path, response->format);
        }

        if ( !content ) {
            http_error(response, 404);
        }
        
    } else {
        // serve binary data
        full_path = g_strjoin("/", DEBUG_DUMPS_DIR, url[2], url[3], NULL);
        ret = open(full_path, O_RDONLY);
        if ( ret == -1 ) {
            g_free(full_path);
            full_path = g_strjoin("/", home, ".abrt/spool" , url[2], NULL);
            ret = open(full_path, O_RDONLY);
        }

        if ( ret == -1 ) {
            http_error(response, 404);
        } else {
            http_response(response, 200);
            struct stat buf;
            fstat(ret, &buf);
            http_add_header(response, "Content-Length: %d", buf.st_size);
            body_len = buf.st_size; //bytes
            response->fd = ret;
        }
        
    }


    /* if no error or download was set */
    if ( response->code == UNDECLARED ) {
        http_response(response, 200);
        response->body = content;
        body_len = strlen(response->body);
        http_add_header(response, "Content-Length: %d", body_len);
        http_add_header(response, "Content-Type: %s", type);
    }


    g_free(type);
    g_free(path);
    g_free(full_path);
    g_strfreev(url);
    g_strfreev(options);
}



/* authentize PAM and lower privileges */
bool http_authentize(const struct http_req *request)
{
    gchar *h = NULL;
    
    if ( request->header_options != NULL ) {
        g_hash_table_lookup(request->header_options, "authorization");
    }

    if (h) {
        return true;
    }

    return false;    
    
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

    va_end (arguments);
    
    return response;
}



/*
 * return text representation of code
 * used in: response line and error messages
 */
gchar *http_get_code_text(short code)
{
    gchar *name;
    
    switch (code) {
        case 200:
            name = g_strdup("OK");
            break;
        case 400:
            name = g_strdup("Bad Request");
            break;
        case 401:
            name = g_strdup("Authorization Required");
            break;
        case 404:
            name = g_strdup("Not Found");
            break;
        case 501:
            name = g_strdup("Not Implemented");
            break;
        default:
            name = g_strdup("Unknown");
            break;
    }

    return name;
}




/* fill out response line */
void http_response(struct http_resp *resp, short code)
{
    gchar *code_text = NULL;
    
    if ( resp->response_line != NULL ) {
        g_free(resp->response_line);
    }

    resp->code = code;
    code_text = http_get_code_text(code);

    resp->response_line = g_strdup_printf("HTTP/1.0 %d %s\r\n", code, code_text);

    g_free(code_text);
    
}



/*
 * fill out complete(?) response according to error
 * previous contents will be cleared
 */
struct http_resp* http_error(struct http_resp* resp, short error)
{
    g_free(resp->body);
    if (resp->head != NULL ) {
        g_string_free(resp->head, TRUE);
        resp->head = NULL;
    }
    resp->fd = -1;

    gchar *error_text;
    gchar *code_text;
    GString *content;
    xmlDocPtr doc   = NULL;
    xmlNodePtr root = NULL;
    xmlNodePtr text = NULL;
    int body_len;

    doc = xmlNewDoc(BAD_CAST "1.0");
    root = xmlNewNode(NULL, BAD_CAST "error");

    http_response(resp, error);
    error_text = http_get_code_text(error);
    code_text = g_strdup_printf("%d", error);

    switch (resp->format) {
        case XML:
            xmlNewProp(root, BAD_CAST "code", BAD_CAST code_text);
            text = xmlNewText(BAD_CAST error_text);
            xmlAddChild(root, text);
            xmlDocSetRootElement(doc, root);
            xmlDocDumpFormatMemory(doc, (xmlChar**)&resp->body, &body_len, 1);
        case HTML:
            content = g_string_sized_new(256);
            add_html_head(content, error_text);
            g_string_append_printf(content,
                    "  <span style=error>%d: %s</span>\n", error, error_text);
            g_string_append(content, " </body>\n</html>\n");
            resp->body = g_string_free(content, false);
            body_len = strlen(resp->body);
            break;
        case JSON:
            break;
        case PLAIN:
            resp->body = g_strdup_printf("Error %d: %s\n", error, error_text);
            break;
    }
    
    http_add_header(resp, "Content-Length: %d", body_len);
    http_add_header(resp, "Connection: close");

    /* additional error-specific headers */
    switch (error) {
        case 401:
            http_add_header(resp, "WWW-Authenticate: Basic");
            break;
        default:
            break;        
    }

    xmlFreeDoc(doc);
    xmlCleanupParser();
    g_free(error_text);
    g_free(code_text);
    
    return resp;
}




gchar *set_static_css()
{
    GString *content = g_string_sized_new(512);

    g_string_append(content, "body { background-color: #101010; color: yellow; }\n");
    g_string_append(content, "div { border: 1px solid red; }\n");

    return g_string_free(content, false);
}



void api_serve_static(const struct http_req *req, struct http_resp *resp)
{
        gchar **url;
        gchar *uri;

        uri = rm_slash(req->uri);
        url = g_strsplit(uri, "/", 3);

        if ( g_strv_length(url) < 3 ) {
            http_error(resp, 404);
            return;
        }

        if ( g_strcmp0(url[2], "css") == 0 ) {
            resp->body = set_static_css();
            http_response(resp, 200);
            http_add_header(resp, "Cache-Control: max-age = 36000");
            http_add_header(resp, "Content-Type: text/css");
            http_add_header(resp, "Content-Length: %d", strlen(resp->body));
        } else {
            http_error(resp, 404);
        }
        
}




gchar *http_get_type_text(content_type type)
{
    gchar *c_type = NULL;
    
    switch (type) {
        case XML:
            c_type = g_strdup("text/xml");
            break;
        case PLAIN:
            c_type = g_strdup("text/plain");
            break;
        case HTML:
            c_type = g_strdup("text/html");
            break;
        case JSON:
            c_type = g_strdup("text/json");
            break;
    }

    return c_type;
}




/*
 * prepare ready-to-send response
 */
void generate_response(const struct http_req *request, struct http_resp *response)
{
    //FIXME
    if ( false && !http_authentize(request) ) {
        http_error(response, 401);
        return;
    }

    gchar *c_type;

    response->format = http_get_content_type(request);
    c_type = http_get_type_text(response->format);

    switch ( request->method ) {
        case UNDEFINED:
            http_error(response, 400);
            break;
        case GET:
            break;
        case HEAD:
            break;
        case DELETE:
        case POST:
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
        case 2: //static
            api_serve_static(request, response);
            break;
        case -1: //unknown
        default: //broken
            http_error(response, 404);
            break;
    }

}


/* will read whole dir and append all problems to XML tree */
gchar* fill_crash_details(const char* dir_name, const content_type format)
{
    crash_data_t *crash_data;
    xmlNodePtr root = NULL;
    xmlDocPtr doc = NULL;
    gchar **parts;
    gchar *id;

    gchar *ret = NULL;
    GString *content = NULL;

    DIR *dir = opendir(dir_name);
    
    if (dir != NULL) {
        int sv_logmode = logmode;
        logmode = 0; /* suppress EPERM/EACCES errors in opendir */
        struct dump_dir *dd = dd_opendir(dir_name, /*flags:*/ DD_OPEN_READONLY );
        logmode = sv_logmode;
        
        if ( dd==NULL )  {
            return NULL;
        }
        
        crash_data = create_crash_data_from_dump_dir(dd);
        dd_close(dd);
        
    } else {
        return NULL;
    }

    parts = g_strsplit(dir_name, "/", -1);
    id = parts[g_strv_length(parts)-1];
    
    switch(format) {
        case XML:
            doc = xmlNewDoc(BAD_CAST "1.0");
            root = xmlNewNode(NULL, BAD_CAST "problem");
            xmlNewProp(root, BAD_CAST "id", BAD_CAST id);
            g_hash_table_foreach(crash_data, (GHFunc)add_detail_xml, root);
            xmlDocSetRootElement(doc, root);
            xmlDocDumpFormatMemory(doc, (xmlChar**)&ret, NULL, 1);
            break;
        case HTML:
            content = g_string_sized_new(2048);
            add_html_head(content, id);
            g_hash_table_foreach(crash_data, (GHFunc)add_detail_html, content);
            g_string_append(content, " </body>\n</html>\n");
            ret = g_string_free(content, FALSE);
            break;
        case JSON:
        case PLAIN:
            break;
    }


    g_free(id);
    g_strfreev(parts);
    xmlFreeDoc(doc);
    xmlCleanupParser();
    g_hash_table_destroy(crash_data);

    return ret;
}




int http_get_content_type(const struct http_req *request)
{
    return HTML;
}

void add_html_head(GString *content, const gchar *title)
{
    g_string_append(content, "<html>\n <head>\n");
    g_string_append_printf(content, "  <title>%s</title>\n", title);
    g_string_append(content,
        "<link rel=\"stylesheet\" type=\"text/css\" href=\"/static/css\" />\n");
    g_string_append(content, " </head>\n <body>\n");
}




void add_detail_html(const gchar* key, const crash_item* item, GString *content)
{
    g_string_append(content,
                           "  <div style=\"problem\">\n");

    /* unixtime */
    if        ( item->flags & CD_FLAG_UNIXTIME )  {
    g_string_append_printf(content,
                           "<span style=\"time\">time: %s</span>", item->content);

    /* text */
    } else if ( item->flags & CD_FLAG_TXT ) {
    g_string_append_printf(content,
                           "<span>%s</span><br/>", key);
    g_string_append_printf(content,
                           "<span>%s</span>", item->content);
    
    /* binary */
    } else if ( item->flags & CD_FLAG_BIN ) {
    gchar *id_start = g_strstr_len(content->str, -1, "<title>");
    gchar *id_stop = g_strstr_len(content->str, -1, "</title>");
    if ( id_start && id_stop ) {
        gchar *id = g_strndup(id_start+7, (id_stop-id_start)-8);
        g_string_append_printf(content,
                           "<a href=/problems/%s/%s>%s</a>", id, key, key);
    } else {
        g_string_append_printf(content,
                           "<span>binary: %s</span>", key);
    }


    /* something else */
    } else {
    g_string_append_printf(content,
                           "<span>%s</span><br/>", key);
    g_string_append_printf(content,
                           "<span>%s</span>", item->content);
        
    }

    g_string_append(content,
                           "  </div>");
}




void add_detail_xml(const gchar *key, const crash_item *item, xmlNodePtr root)
{
    xmlNodePtr node = NULL;
    xmlNodePtr text = NULL;

    if (item == NULL) {
        return;
    }

    node = xmlNewNode(NULL, BAD_CAST "item");
    xmlNewProp(node, BAD_CAST "name", BAD_CAST key);

    /* unixtime */
    if        ( item->flags & CD_FLAG_UNIXTIME )  {
        xmlNewProp(node, BAD_CAST "type", BAD_CAST "unixtime");
        //xmlNewProp(node, BAD_CAST "format", BAD_CAST "%s");
        text = xmlNewText(BAD_CAST item->content);
        xmlAddChild(node, text);

    /* text */
    } else if ( item->flags & CD_FLAG_TXT ) {
        xmlNewProp(node, BAD_CAST "type", BAD_CAST "txt");
        text = xmlNewText(BAD_CAST item->content);
        xmlAddChild(node, text);

    /* binary */
    } else if ( item->flags & CD_FLAG_BIN ) {
        xmlChar *id = xmlGetNoNsProp(root, BAD_CAST "id");
        gchar *full_path = g_strjoin("/", "/problems", id, key, NULL);

        xmlNewProp(node, BAD_CAST "type", BAD_CAST "bin");
        xmlNewProp(node, BAD_CAST "href", BAD_CAST full_path);
        xmlNewProp(node, BAD_CAST "rel", BAD_CAST "download");

        xmlFree(id);
        
    /* something else */
    } else {
        xmlNewProp(node, BAD_CAST "type", BAD_CAST "unknown");
        text = xmlNewText(BAD_CAST item->content);
        xmlAddChild(node, text);
    }

    xmlAddChild(root, node);
}


/* this will fill out XML tree for response to /problems/ */
gchar* list_problems(content_type format)
{
    char *home;
    char *home_path;
    GList *list = NULL;
    xmlNodePtr root = NULL;
    xmlDocPtr doc = NULL;

    GString *content;
    gchar *ret;

    home = getenv("HOME");
    if ( home ) {
        home_path = concat_path_file(home, ".abrt/spool");
        list = create_list(list, home_path);
        free(home_path);
    }
    list = create_list(list, (char*)DEBUG_DUMPS_DIR);


    /* now on each list item call appropriate generator */
    switch (format) {
        case XML:
            doc = xmlNewDoc(BAD_CAST "1.0");
            root = xmlNewNode(NULL, BAD_CAST "problems");
            g_list_foreach(list, (GFunc)add_problem_xml, root);
            xmlDocSetRootElement(doc, root);
            xmlDocDumpFormatMemory(doc, (xmlChar**)&ret, NULL, 1);
            break;
        case PLAIN:
            content = g_string_sized_new(1024);
            g_list_foreach(list, (GFunc)add_problem_plain, content);
            ret = g_string_free(content, false);
            break;
        case HTML:
            content = g_string_sized_new(2048);
            add_html_head(content, "Problems list");
            g_list_foreach(list, (GFunc)add_problem_html, content);
            g_string_append(content, " </body>\n</html>\n");
            ret = g_string_free(content, false);
            break;
        case JSON:
            ret = g_strdup("Not supported\n");
            break;
    }
    
    
    // g_list_free_full(list, (GDestroyNotify)free_list); //since glib 2.28
    g_list_foreach(list, (GFunc)free_list, NULL);
    g_list_free(list);
    xmlFreeDoc(doc);
    xmlCleanupParser();

    return ret;
}



void add_problem_html(const problem_t *problem, GString *content)
{
    g_string_append(content, "<div style=problem>\n");
    g_string_append_printf(content,
                    "<a href=\"/problems/%s/\">%s</a>", problem->id, problem->id);
    g_string_append_printf(content,
                    "<span style=\"time\">%s</span>", problem->time);
    g_string_append_printf(content,
                    "<span style=\"problem_reason\">%s</span>", problem->reason);
    g_string_append(content, "</div>\n");
}



void add_problem_plain(const problem_t *problem, GString *content)
{
    g_string_append_printf(content, "%s /problems/%s/\n %s\n\n",
                            problem->time, problem->id, problem->reason);
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
                        //TODO
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
void add_problem_xml(const problem_t *problem, xmlNodePtr root)
{
    char *href;
    xmlNodePtr node = NULL;
    xmlNodePtr text = NULL;
    xmlNodePtr child = NULL;

    href =  g_strjoin("/", "/problems", problem->id, NULL);

    /* problem */
    node = xmlNewNode(NULL, BAD_CAST "problem");
    xmlNewProp(node, BAD_CAST "id", BAD_CAST problem->id);
    xmlNewProp(node, BAD_CAST "href", BAD_CAST href);

        /* time */
        child = xmlNewNode(NULL, BAD_CAST "item");
        xmlNewProp(child, BAD_CAST "name", BAD_CAST "time");
        xmlNewProp(child, BAD_CAST "type", BAD_CAST "unixtime");
        //xmlNewProp(child, BAD_CAST "format", BAD_CAST "%s");
        text = xmlNewText(BAD_CAST problem->time);
        xmlAddChild(child, text);
        xmlAddChild(node, child);

        /* reason */
        child = xmlNewNode(NULL, BAD_CAST "item");
        xmlNewProp(child, BAD_CAST "name", BAD_CAST "reason");
        text = xmlNewText(BAD_CAST problem->reason);
        xmlAddChild(child, text);
        xmlAddChild(node, child);

    xmlAddChild(root, node);

    g_free(href);
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
