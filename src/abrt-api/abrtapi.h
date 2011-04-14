#ifndef ABRTAPI_H
#define ABRTAPI_H

//THIS SHALL BE REMOVED AS IT OVERRIDE MAKEFILES
//###########################################################
#undef DEBUG_DUMPS_DIR
#define DEBUG_DUMPS_DIR "/var/spool/abrt"
//###########################################################*/
//FIXME FIXME FIXME FIXME

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>
#include <wait.h>
#include <glib/ghash.h>
#include <glib-2.0/glib.h>
//#include <glib/gregex.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
//#include <gio/gio.h>

#include "abrtlib.h"
#include "http.h"

/* should be in makefile ? */
#define CONFIG_PATH "api.conf" //path to config file
#define BACKLOG (16) //maximum number of connection
#define INPUT_LEN (128) //maximum length of url/path input
#define PORT_LEN (16) //maximum length of port/service
#define MAX_HEADER_SIZE (10*1024) //max header size
#define READ_BUF (2560) //read from socket at once

/* should be in config file */
#define CERT_FILE "/home/rplnt/projects/certs/cacert.pem"
#define KEY_FILE "/home/rplnt/projects/certs/privkey.pem"


/* option flags */
#define OPT_DBG (1U) //don't daemonize and print errors
#define OPT_ADDR (1U<<1) //address (wheter sock name or ip address) was set
#define OPT_CFG (1U<<2) 
#define OPT_SOCK (1U<<3) //use unix socket
#define OPT_IP  (1U<<4) //use network socket
#define OPT_PORT (1U<<5) //port was set
#define OPT_SSL (1U<<6) //use ssl

#define pass (0)

#define API_VERSION "0.1"

/* problem summary */
typedef struct problem_summary  {
    gchar* id;
    gchar* time;
    gchar* reason;
} problem_t;

/* initialize "classic" socket */
int init_n_socket(char* address, char* port);

/* initialize unix domain socket */
int init_u_socket();

/* SSL helper */
SSL_CTX* init_ssl_context(void);

/* print help message to stderr and exit with ERR ? */
void usage_and_exit();

/* take care of zombies */
void sigchld_handler(int sig);

/* test */
void serve(void *sock, int flags);

/* serve socket */
void servex(int sockfd_in);

/* serve ssl socket */
void serve_ssl(SSL* ssl);

/* copy string with len check */
bool safe_strcpy(char* dest, const char* src, int max_len);

/* fill out port and/or addr and return flags */
int parse_addr_input(char* input, char* addr, char* port);

/* remove CR characters */
bool delete_cr( gchar* in);

int hash_method(gchar *methodstr);

////TODO Clean Up & Comment

int validate_request(const struct http_req *request);
void generate_response(const struct http_req *request, struct http_resp *response);
int fill_crash_details(const char* dir_name, xmlNodePtr root /* TODO XML */);
void list_problems(xmlNodePtr root);
GList* create_list(GList *list, char* dir_name);
void add_problem(problem_t* problem, xmlNodePtr root);
void free_list(problem_t *item);
int switch_route(const gchar *url);
char *rm_slash(const char *path);

bool http_authentize(const struct http_req *request);
struct http_resp* http_add_header(struct http_resp* response, const gchar* header_line, ...);
struct http_resp* http_error(struct http_resp* response, int error);
void http_response(struct http_resp *resp, int code);
                
int api_entry_point(const struct http_req* request, struct http_resp* response);
int api_problems(const struct http_req* request, struct http_resp* response);


#endif