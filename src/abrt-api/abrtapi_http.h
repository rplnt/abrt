#ifndef ABRTAPI_HTTP_H
#define ABRTAPI_HTTP_H

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


/* supported responses */
enum content_type {
    XML,
    PLAIN,
    HTML,
    JSON
};
typedef enum content_type content_type;

/* http request structure */
struct http_req {
    http_method method;
    gchar *uri;
    gchar *version;
    GHashTable *header_options;
    GString *body;
};

/* http response structure */
struct http_resp {
    int code;
    gchar *response_line;
    GString *head;
    gchar *body; //NULL if body is empty
    int fd;
    content_type format;
};

#define UNDECLARED (0)

/* parse http headers */
void parse_head(struct http_req* request, const GString* headers);

/* validate request */
bool validate_request(const struct http_req* request);

/* authentize user */
bool http_authentize(const struct http_req *request);

/* get response text */
gchar *http_get_code_text(short code);


/* add line to response header */
struct http_resp* http_add_header(struct http_resp* response, const gchar* header_line, ...);

/* generate error message */
struct http_resp* http_error(struct http_resp* resp, short error);

/* set response line */
void http_response(struct http_resp *resp, short code);

/* get content type from request */
content_type http_get_content_type(const struct http_req* request);

/* get text for content type */
gchar *http_get_type_text(content_type type);

/* free http structures */
void free_http_response(struct http_resp *resp);
void free_http_request(struct http_req *req);

#endif