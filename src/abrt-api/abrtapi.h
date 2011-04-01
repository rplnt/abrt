#ifndef ABRTAPI_H
#define ABRTAPI_H

#include "abrtlib.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <signal.h>
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
#include <glib-2.0/glib.h>
//#include <libxml2/libxml/parser.h>
//#include <gio/gio.h>

/* should be in makefile */
#define CONFIG_PATH "api.conf"
#define BACKLOG 10
#define PORT_MIN 1000
#define MAX_HTTP_OPTS 10
#define MAX_HTTP_LEN 1000

/* should be in config file */
#define CERT_FILE "certs/cacert.pem"
#define KEY_FILE "certs/privkey.pem"


/* option flags TODO */
#define OPT_DBG (1U) //don't daemonize and print errors
#define OPT_ADDR (1U<<1) //address (wheter sock name or ip address) was set
#define OPT_CFG (1U<<2) 
#define OPT_SOCK (1U<<3) //use unix socket
#define OPT_IP  (1U<<4) //use network socket
#define OPT_PORT (1U<<5) //port was set
#define OPT_SSL (1U<<6) //use ssl

enum http_method {
    GET, HEAD, POST, PUT, DELETE
};

struct http_req {
    enum http_method method;
    gchar *uri;
    GList *options;
    gchar *body;    
};

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

/* serve socket */
void serve(int sockfd_in);

/* serve ssl */
void serve_ssl(SSL* ssl);

/* fill out port and/or addr and return flags */
int parse_addr_input(char* input, char* addr, char* port);



#endif