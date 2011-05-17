#include "abrtapi.h"


/**
 * Parse HTTP headers.
 *
 * Try to parse given http headers. We don't want to violate
 * RFC but we also won't implement all of it. We'll discover
 * http method, request url and header options.
 *
 * @param request       Request structure to which we'll fill details.
 * @param headers       String containing whol http request's headers.
 */
void parse_head(struct http_req* request, const GString* headers)
{
    int i; //len;
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

    if ( headers->str == NULL ) {
        goto stop;
    }

    /* split by new lines */
    s_head = g_strsplit(headers->str, "\n", -1);
    //len = g_strv_length(s_head);
    if ( g_strv_length(s_head) < 1 ) {
        goto stop;
    }

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
    while ( s_head[i] != NULL && s_head[i][0] != '\n' && s_head[i][0] != '\0' ) {
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



/**
 * Validate http request.
 *
 * Validate as much as possible. Url, headers, etc..
 *
 * @param request       HTTP request containing parsed header.
 * @return              True on success.
 *                      False in failure.
 */
bool validate_request(const struct http_req *request)
{
    gchar **url;

    if ( request->method == UNDEFINED ) {
        return false;
    }

    //TODO Host: ??
    // no //
    if ( request->uri == NULL ) {
        return false;
    }

    /*  one or zero '?' in url */
    url = g_strsplit(request->uri,"?",-1);
    if ( g_strv_length(url) > 2 ) {
        return false;
    }
    g_strfreev(url);

    return true;
}



/**
 * Authentize user using basic authentication and PAM.
 *
 * @param request       HTTP request that should contain login and password.
 * @return              True on success and false on fialure.
 */
bool http_authentize(const struct http_req *request)
{
    gchar *h            = NULL;
    gchar **auth_line   = NULL;
    guchar *auth_data   = NULL;
    gchar **auth        = NULL;
    struct passwd *pw;
    gsize len;
    int i, err;
    

    if ( request->header_options != NULL ) {
        h = g_hash_table_lookup(request->header_options, "authorization");
    } else {
        return false;
    }

    if ( h == NULL ) {
        return false;
    }

    auth_line = g_strsplit(h, " ", -1);

    if ( g_strv_length(auth_line) != 2 || g_ascii_strcasecmp(auth_line[0],"Basic") != 0 ) {
        g_strfreev(auth_line);
        return false;
    }

    auth_data = g_base64_decode(auth_line[1], &len);
    g_strfreev(auth_line);
    
    for (i=0;i<len;i++) {
        if ( !isprint(auth_data[i]) ) {
            return false;
        }
    }

    auth = g_strsplit((gchar*)auth_data, ":", 2);

    if ( g_strv_length(auth) != 2) {
        g_strfreev(auth);
        return false;
    }

    pw = basic_auth_pam(auth[0], auth[1]);

    g_free(auth_data);
    g_strfreev(auth);

    if ( pw == NULL ) {
        return false;
    }

    fprintf(stderr, "uid: %d \n gid: %d", pw->pw_uid, pw->pw_gid);

    err = setgid(pw->pw_gid);
    if ( err == -1 ) {
        fprintf(stderr, "setgid fail: %s\n", strerror(errno));
        return false;
    }
    
    //drop privileges
    err = setuid(pw->pw_uid);
    if ( err == -1 ) {
        fprintf(stderr, "setuid fail\n");
        return false;
    }

    if ( pw->pw_dir ) {
        setenv("HOME", pw->pw_dir, 1);
    }
    
    return true;
}



/**
 * Return text representation if given http response code.
 *
 * @param code      Code value.
 * @return          Allocated string containing textual representation of code.
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
        case 405:
            name = g_strdup("Method Not Allowed");
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



/**
 * Add http header to response structure.
 *
 * Will append string to options part of response. Don't use \n
 * as this function will add CR-LF at the end of the string.
 *
 * @param response          Response to add header option to.
 * @param header_line       Header option to add. Can be formated.
 * @return                  Same structure as given. For ease of use.
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



/**
 * Fill out http response line.
 *
 * Will fill out whole line also with textual representation:
 * e.g. HTTP1/0 200 OK
 *
 * @param resp      Http response structure.
 * @param code      Code used in line.
 */
void http_response(struct http_resp *resp, short code)
{
    gchar *code_text = NULL;

    if ( resp->response_line != NULL ) {
        g_free(resp->response_line);
    }

    resp->code = code;
    code_text = http_get_code_text(code);

    resp->response_line = g_strdup_printf("HTTP/1.1 %d %s\r\n", code, code_text);

    g_free(code_text);

}



/**
 * Generate response according to error.
 *
 * Structure will be cleared before use. Appropriate
 * response line and header options are created. Body
 * is filled out too.
 *
 * @param resp      Response structure to be populated with error.
 * @param error     Http error code.
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
    gchar *type_text;
    GString *content;
    xmlDocPtr doc   = NULL;
    xmlNodePtr root = NULL;
    xmlNodePtr text = NULL;
    int body_len;

    http_response(resp, error);
    error_text = http_get_code_text(error);
    code_text = g_strdup_printf("%d", error);
    type_text = http_get_type_text(resp->format);

    switch (resp->format) {
        case XML:
            doc = xmlNewDoc(BAD_CAST "1.0");
            root = xmlNewNode(NULL, BAD_CAST "error");
            xmlNewProp(root, BAD_CAST "code", BAD_CAST code_text);
            text = xmlNewText(BAD_CAST error_text);
            xmlAddChild(root, text);
            xmlDocSetRootElement(doc, root);
            xmlDocDumpFormatMemory(doc, (xmlChar**)&resp->body, &body_len, 1);
            xmlFreeDoc(doc);
            xmlCleanupParser();
            break;
            
        case HTML:
            content = g_string_sized_new(256);
            add_html_head(content, error_text);
            g_string_append_printf(content,
                    "  <span class=\"error\">%d: %s</span>\n", error, error_text);
            add_html_footer(content);
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
    http_add_header(resp, "Content-Type: %s", type_text);

    /* additional error-specific headers */
    switch (error) {
        case 401:
            http_add_header(resp, "WWW-Authenticate: Basic");
            break;
        default:
            break;
    }

    g_free(error_text);
    g_free(code_text);
    g_free(type_text);

    return resp;
}



/**
 * Get requested (or default) content type.
 *
 * Find request content type in headers or choose default. We
 * ignore priority. Order matters.
 *
 * @param request       Request structure.
 * @return              Content type choosed.
 */
int http_get_content_type(const struct http_req *request)
{
    gchar *values   = NULL;
    gchar *min_pos  = NULL;
    gchar *pos;
    const gchar *types[] = {"application/xml", "text/plain",
                            "text/html", "application/json", NULL};
    short ret = PREF_CONTENT_TYPE;
    int i;

    if (request->header_options != NULL ) {
        values = g_hash_table_lookup(request->header_options, "accept");
    }

    if (values) {
        for (i=0;types[i]!=NULL;i++) {
            pos = g_strstr_len(values, -1, types[i]);

            if (!pos) {
                continue;
            }
            if (!min_pos) {
                min_pos = pos;
                ret = i;
                continue;
            }
            if ( pos < min_pos ) {
                min_pos = pos;
                ret = i;
            }
        }
    }
    
    return ret;
}



/**
 * Return size of the http body or zero.
 *
 * @param request   Http request.
 * @return          Zero or body_lenght, where 0<body_length<MAX_CLEN
 */
int has_body(struct http_req *request)
{
    int ret = 0;
    gchar *c_len;

    if ( request->header_options ) {
        c_len = g_hash_table_lookup(request->header_options, "content-length");
        if ( c_len && g_ascii_isdigit(c_len[0]) ) {
            ret = atoi(c_len);
        }
    }
    
    return ret>MAX_CLEN?0:ret;
}



/**
 * Free memory used by HTTP response.
 *
 * @param resp      Http response structure.
 */
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

    if ( resp->fd > 0) {
        close(resp->fd);
    }

}

/**
 * Free memory used by HTTP request.
 *
 * @param resp      Http request structure.
 */
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




