#ifndef ABRTAPI_API_H
#define ABRTAPI_API_H

typedef struct problem_summary  {
    gchar* id;
    gchar* time;
    gchar* reason;
} problem_t;

void generate_response(const struct http_req *request, struct http_resp *response);

/* populate list of problems */
void add_problem_xml(const problem_t* problem, xmlNodePtr root);
void add_problem_html(const problem_t *problem, GString *content);
void add_problem_plain(const problem_t *problem, GString *content);

void add_detail_html(const gchar* key, const crash_item* item, GString* content);

void api_entry_point(const struct http_req* request, struct http_resp* response);
void api_problems(const struct http_req* request, struct http_resp* response);

void add_html_head(GString* content, const gchar* title);
gchar* fill_crash_details(const char* dir_name, const content_type format);
gchar* list_problems(content_type format);
GList* create_list(GList *list, char* dir_name);

void add_problem(problem_t* problem, xmlNodePtr root);
void free_list(problem_t *item);
int switch_route(const gchar *url);

void add_detail_xml(const gchar* key, const crash_item* item, xmlNodePtr root);










#endif