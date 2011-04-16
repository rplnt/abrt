#include "abrtapi.h"



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



int http_get_content_type(const struct http_req *request)
{
    return HTML;
}


gchar *http_get_content_type_text(content_type type)
{
    return NULL;
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




