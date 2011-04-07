#include <glib/ghash.h>

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

enum http_response_code {
    OK = 200,
    CREATED = 201,
    ACCEPTED = 202,
    
    BAD_REQUEST = 400, //~bad syntax~ change request
    UNAUTHORIZED = 402, //send WWW-Authenticate
    FORBIDDEN = 403,
    NOT_FOUND = 404,
    NOT_ALLOWED = 405, //method not allowed
    NOT_ACCEPTABLE = 406, //wrong content type requested
    LENGTH_REQUIRED = 411, //don't want to allocate memory iterativelly
    URI_TOO_LONG = 414, //Request-URI Too Long
    NO_RESPONSE = 444, //troll
    
    SERVER_ERROR = 500, //Internal Server Error
    NOT_IMPLEMENTED = 501, //thank god
    UNAVAILABLE = 503, //Service Unavailable
};

struct http_req {
    enum http_method method;
    gchar *uri;
	gchar *version; 
    GHashTable *uri_options;
    GHashTable *header_options;
    GString *body;
};

static char allowed_uri_chars[];


struct http_resp {
    enum http_response_code code;
    struct http_req *request; // could be useful?
    GHashTable *options;
    GString *body;
};

/* parse headers of the http request
 * allocate memory
 * set http_method - this indicates that parsing was successfull
 * unallocate memory in case of wrong header
 */
void parse_head(struct http_req *request, GString* headers);

gchar* strcode(enum http_response_code code);

bool is_valid_method(gchar *methodstr);