#include "abrtapi.h"


/**
 * Select route from url.
 *
 * First-level route. First part of the url is used to switch.
 *
 * @param url       A valid url.
 * @return          Integer that can be used in switch statement.
 */   
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



/**
 * "Print" out api entry point.
 *
 * @param response      Http response that we write our output to.
 */
void api_entry_point(struct http_resp *response)
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
        xmlNewProp(root, BAD_CAST "name", BAD_CAST "abrt-http");
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
        g_string_append(content,
                "<ul><li><a href=\"/problems/\" rel=\"problems\">List Problems</a></li></ul>");
        add_html_footer(content);
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



/**
 * API's problems route.
 *
 * This function is called on request to /problems. It either lists
 * problems, print out detailed info or delete them. TODO
 *
 * @param request       Http request.
 * @param response      Http response.
 */
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

    /*
     * List problems.
     */
    if ( g_strv_length(url) == 2 ) {
        if ( request->method == GET || request->method == HEAD ) {
            content = list_problems(response->format);
        } else {
            http_error(response, 405);
            http_add_header(response, "Allow: GET, HEAD");
        }

    /*
     * Delete problem.
     */
    } else if ( g_strv_length(url) == 3 && request->method == DELETE ) {
        //TODO fatal error: dbus/dbus.h: No such file or directory
//         full_path = g_strjoin("/", DEBUG_DUMPS_DIR, url[2], NULL);
//         if ( delete_dump_dir_possibly_using_abrtd(full_path) ) {
//             http_error(response, 404);
//         } else {
//             response = g_strdup("deleted!");
//         }
        content = g_strdup_printf("Problem %s deleted!\n", url[2]);

    /*
     * Print out details about selected problem.
     */
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

    /*
     * Serve file (intended for binary, but works on all).
     */
    } else if ( request->method == GET || request->method == HEAD ) {
         
        full_path = g_strjoin("/", DEBUG_DUMPS_DIR, url[2], url[3], NULL);
        ret = open(full_path, O_RDONLY);

        if ( ret == -1 ) {
            g_free(full_path);
            full_path = g_strjoin("/", home, ".abrt/spool" , url[2], url[3], NULL);
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
        
    } else {
        http_error(response, 404);
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



/**
 * Serve static files.
 *
 * Should be used to serve program-related static files.
 * For example images, cascade styles, ...
 *
 * @param request       Http request.
 * @param response      Http response.
 */
void api_serve_static(const struct http_req *req, struct http_resp *resp)
{
    gchar **url;
    gchar *uri;
    gchar *full_path;
    gchar *home = getenv("HOME");
    int ret;

    uri = rm_slash(req->uri);
    url = g_strsplit(uri, "/", -1);

    if ( g_strv_length(url) != 3 ) {
        http_error(resp, 404);
        return;
    }

    full_path = g_strjoin("/", home, STATIC_PATH, url[2], NULL);
    ret = open(full_path, O_RDONLY);

    if ( ret == -1 ) {
        http_error(resp, 404);
    } else {
        http_response(resp, 200);
        struct stat buf;
        fstat(ret, &buf);
        http_add_header(resp, "Content-Length: %d", buf.st_size);
        resp->fd = ret;
    }

    g_free(full_path);
    g_strfreev(url);
    g_free(uri);
}



/**
 * Get text version of content-type.
 *
 * @param type          Enum member.
 * @return              Allocated string with textual representation
 *                      of content type or NULL.
 */
gchar *http_get_type_text(content_type type)
{
    gchar *c_type = NULL;
    
    switch (type) {
        case XML:
            c_type = g_strdup("application/xml");
            break;
        case PLAIN:
            c_type = g_strdup("text/plain");
            break;
        case HTML:
            c_type = g_strdup("text/html");
            break;
        case JSON:
            c_type = g_strdup("application/json");
            break;
    }

    return c_type;
}



/**
 * Generatr response to a request.
 *
 * Fill out all response fields so it can be served to client.
 *
 * @param request       Http request.
 * @param response      Http response.
 */
int generate_response(const struct http_req *request, struct http_resp *response)
{
    gchar *keep = NULL;
    int rt=0;
    
    if ( !http_authentize(request) ) {
        http_error(response, 401);
        return rt;
    }

    //fprintf(stderr,"URL: %s\nMethod: %d\n\n",request->uri, request->method);
    fflush(stderr);

    response->format = http_get_content_type(request);

    switch ( request->method ) {
        case UNDEFINED:
            http_error(response, 400);
            break;
        case GET:
            break;
        case HEAD:
            break;
        case DELETE:
            break;
        case POST:
        case PUT:
        case OPTIONS:
        case TRACE:
        case CONNECT:
            http_error(response, 501);
            break;
    }

    if ( response->code != UNDECLARED ) {
        return rt;
    }

    /* switch "first level" */
    switch ( switch_route(request->uri) ) {
        case 0: //root node
            if ( request->method == GET || request->method == HEAD ) {
                api_entry_point(response);
            } else {
                http_error(response, 405);
                http_add_header(response, "Allow: GET, HEAD");
            }
            break;
            
        case 1: //problems
            api_problems(request,response);
            break;
            
        case 2: //static
            if ( request->method == GET || request->method == HEAD ) {
                api_serve_static(request, response);
            } else {
                http_error(response, 405);
                http_add_header(response, "Allow: GET, HEAD");
            }
            break;
            
        case -1: //unknown
        default: //broken
            http_error(response, 404);
            break;
    }


    /* keep-alive */
    if ( request->header_options && response->code == 200 ) {
        keep = g_hash_table_lookup(request->header_options, "connection");
    }
    if ( keep && g_strstr_len(keep, -1, "Keep-Alive") ) {
        http_add_header(response,"Connection: Keep-Alive");
        rt = 1;
    }

    return rt;
}



/**
 * Generate string representing crash in given content-type.
 *
 * @param dir_name      Directory with the crash we want details from.
 * @param format        Desired content type.
 * @return              Newly allocated string or NULL on failure.
 */
gchar* fill_crash_details(const char* dir_name, const content_type format)
{
    crash_data_t *crash_data;
    xmlNodePtr root         = NULL;
    xmlDocPtr doc           = NULL;
    xmlNodePtr action       = NULL;
    gchar **parts           = NULL;
    gchar *del_url          = NULL;
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
        closedir(dir);
        
    } else {
        return NULL;
    }

    parts = g_strsplit(dir_name, "/", -1);
    id = parts[g_strv_length(parts)-1];
    del_url = g_strjoin("/", "/problems", id, NULL );
    
    switch(format) {
        case XML:
            doc = xmlNewDoc(BAD_CAST "1.0");
            root = xmlNewNode(NULL, BAD_CAST "problem");
            xmlNewProp(root, BAD_CAST "id", BAD_CAST id);
            g_hash_table_foreach(crash_data, (GHFunc)add_detail_xml, root);
            action = xmlNewNode(NULL, BAD_CAST "action");
            xmlNewProp(action, BAD_CAST "name", BAD_CAST "delete");
            xmlNewProp(action, BAD_CAST "method", BAD_CAST "DELETE");
            xmlNewProp(action, BAD_CAST "href", BAD_CAST del_url );
            xmlAddChild(root, action);
            xmlDocSetRootElement(doc, root);
            xmlDocDumpFormatMemory(doc, (xmlChar**)&ret, NULL, 1);
            break;
            
        case HTML:
            content = g_string_sized_new(2048);
            add_html_head(content, id);
            g_string_append(content, "<ul>\n");
            g_hash_table_foreach(crash_data, (GHFunc)add_detail_html, content);
            g_string_append(content,
                    "<button name=\"Delete\" onclick=\"delProblem();\">Delete</button>");
            g_string_append(content, "</ul>\n");
            add_html_footer(content);
            ret = g_string_free(content, FALSE);
            break;
            
        case JSON:
            ret = g_strdup("Unsupported\n");
            break;
            
        case PLAIN:
            content = g_string_sized_new(1024);
            g_hash_table_foreach(crash_data, (GHFunc)add_detail_plain, content);
            g_string_append(content, "[delete]");
            ret = g_string_free(content, FALSE);
            break;
    }

    g_free(del_url);
    g_strfreev(parts);
    xmlFreeDoc(doc);
    xmlCleanupParser();
    g_hash_table_destroy(crash_data);

    return ret;
}



/**
 * Add crash detail in HTML to string.
 *
 * @param key           Name of the detail.
 * @param item          Content and type of the crash detail.
 * @param content       String we'll append detail to.
 */
void add_detail_html(const gchar* key, const crash_item* item, GString *content)
{
    g_string_append(content,
                           "  <li class=\"problem\">\n<div>");

    /* unixtime */
    if        ( item->flags & CD_FLAG_UNIXTIME )  {
    g_string_append_printf(content,
                           "<span class=\"time\">time: %s</span>", item->content);

    /* text */
    } else if ( item->flags & CD_FLAG_TXT ) {
    g_string_append_printf(content,
                           "<span class=\"txt_key\">%s</span><br/>", key);
    g_string_append_printf(content,
                           "<span class=\"txt_content\">%s</span>", item->content);
    
    /* binary */
    } else if ( item->flags & CD_FLAG_BIN ) {
    g_string_append_printf(content,
                           "<span class=\"bin_key\">%s</span><br/>", key);
    gchar *id_start = g_strstr_len(content->str, -1, "<title>");
    gchar *id_stop = g_strstr_len(content->str, -1, "</title>");
    if ( id_start && id_stop ) {
        gchar *id = g_strndup(id_start+7, (id_stop-id_start)-7);
        g_string_append_printf(content,
                           "<a href=\"/problems/%s/%s\">Download</a>", id, key);
        g_free(id);
    } else {
        g_string_append_printf(content,
                           "<span class=\"unknow_path\">binary: %s</span>", key);
    }


    /* something else */
    } else {
    g_string_append_printf(content,
                           "<span class=\"unknown_tem\">%s</span><br/>", key);
    g_string_append_printf(content,
                           "<span class=\"unknown_tem\">%s</span>", item->content);
        
    }

    g_string_append(content,
                           "</div></li>");
}



/**
 * Append XML node with a crash detail to a tree.
 *
 * @param key           Name of the detail.
 * @param item          Content and type of the crash detail.
 * @param root          Root node of an XML tree.
 */
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



/**
 * Add crash detail in plaintext to string.
 *
 * @param key           Name of the detail.
 * @param item          Content and type of the crash detail.
 * @param content       String we'll append detail to.
 */
void add_detail_plain(const gchar* key, const crash_item* item, GString* content)
{
    g_string_append_printf(content, "%s:\n %s\n\n", key, item->content);
}



/**
 * Add html header to a string.
 *
 * @param content       String that we'll append our header to.
 * @param title         Title used in header.
 */
void add_html_head(GString *content, const gchar *title)
{
    g_string_append(content, "<html>\n<head>\n");
    g_string_append_printf(content, "<title>%s</title>\n", title);
    g_string_append(content,
        "<link rel=\"stylesheet\" type=\"text/css\" href=\"/static/style.css\" />\n");
    g_string_append(content,
        "<script type=\"text/javascript\" src=\"/static/del.js\" />\n");
    g_string_append(content, "</head>\n<body><div class=\"main\">\n");
    g_string_append(content,
        "<h1><a href=\"/\" class=\"a_home\">ABRT HTTP v0.1</a></h1>\n");
    g_string_append_printf(content,
        "<h2>%s</h2>\n", title);
}



/**
 * Add html footer to a string.
 *
 * @param content       String that we'll append our header to.
 * @param title         Title used in header.
 */
void add_html_footer(GString *content)
{
    g_string_append(content, "</div>\n</body>\n</html>");
}



/**
 * Generate string representing all problems.
 *
 * @param format        Format we want the list in.
 * @return              Allocated string.
 */
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
            g_string_append(content, "<ul class=\"problems\">");
            g_list_foreach(list, (GFunc)add_problem_html, content);
            g_string_append(content, "</ul>\n");
            add_html_footer(content);            
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



/**
 * Append problem summary to a string in HTML.
 *
 * @param problem       Structure containing problem summary.
 * @param content       String that we'll append info to.
 */
void add_problem_html(const problem_t *problem, GString *content)
{
    g_string_append(content, "<li><div>\n");
    g_string_append_printf(content,
                    "<a href=\"/problems/%s/\">%s</a>", problem->id, problem->id);
    g_string_append_printf(content,
                    "<span class=\"reason\">%s</span>", problem->reason);
    g_string_append_printf(content,
                    "<span class=\"time\">%s</span>", problem->time);
    g_string_append(content, "<div></li>\n");
}



/**
 * Append problem summary to a XML tree.
 *
 * @param problem       Structure containing problem summary.
 * @param root          Root node of a tree.
 */
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



/**
 * Append problem summary to a string in plaintext.
 *
 * @param problem       Structure containing problem summary.
 * @param content       String that we'll append info to.
 */
void add_problem_plain(const problem_t *problem, GString *content)
{
    g_string_append_printf(content, "%s /problems/%s/\n %s\n\n",
                            problem->time, problem->id, problem->reason);
}



/**
 * Add problem's summary to a list.
 *
 * @param list          List we'll append problem to.
 * @param dir_name      Direcotry from which we want problem details.
 * @return              New start of the list.
 */
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

                    list = g_list_append(list, problem);

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



/**
 * Free problem_t structure.
 *
 * @param item      Structure to be free'd.
 */
void free_list(problem_t *item)
{
    g_free(item->id);
    g_free(item->reason);
    g_free(item->time);
    g_free(item);
}
