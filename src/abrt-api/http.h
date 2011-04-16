#ifndef HTTP_H
#define HTTP_H


#define METHODS_CNT (8)
/* UNDEFINED means that http_req structure wasn't used */
enum http_method {
    UNDEFINED, //=0
    GET,
    POST,
    DELETE,
    HEAD,
    PUT,
    OPTIONS,
    TRACE,
    CONNECT
};
typedef enum http_method http_method;

/* response codes */
enum {
    UNDECLARED = 0    
};

/* supported responses */
enum content_type {
    XML,
    PLAIN,
    HTML,
    JSON
};
typedef enum content_type content_type;

#define DEFAULT_CONTENT_TYPE XML

struct http_req {
    http_method method;
    gchar *uri;
	gchar *version; 
    GHashTable *header_options;
    GString *body;
};

static char allowed_uri_chars[];


struct http_resp {
    int code;
    gchar *response_line;
    GString *head;
    gchar *body; //NULL if body is empty
    int fd;
    content_type format;
};

/* parse headers of the http request
 * allocate memory
 * set http_method - this indicates that parsing was successfull
 * unallocate memory in case of wrong header
 */
void parse_head(struct http_req* request, const GString* headers);

void generate_response(const struct http_req *request, struct http_resp *response);

gchar* strcode(int code);

bool is_valid_method(gchar *methodstr);

#endif