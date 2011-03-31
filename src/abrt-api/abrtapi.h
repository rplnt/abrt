#ifndef ABRTAPI_H
#define ABRTAPI_H

#include <unistd.h>
#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <netdb.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/types.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <sys/un.h>
//#include <glib.h>
// #include <abrt/abrtlib.h>
//#include <libxml2/libxml/parser.h>
//#include <gio/gio.h>

#define CONFIG_PATH "api.conf"
#define BACKLOG 10
#define PORT_MIN 1000

/* should be in config file */
#define CERT_FILE "certs/cacert.pem"
#define KEY_FILE "certs/privkey.pem"


/* option flags TODO */
#define OPT_DBG (1U) //don't daemonize
#define OPT_ADDR (1U<<1) //address (wheter sock name or ip address) was set
#define OPT_CFG (1U<<2) 
#define OPT_SOCK (1U<<3) //use unix socket
#define OPT_IP  (1U<<4) //use network socket
#define OPT_PORT (1U<<5) //port was set
#define OPT_SSL (1U<<6) //use ssl


static struct option longopts[] =
{
    /* name,            has_arg,         flag, val */
    { "help",           no_argument,        0, '?' },
    { "address",        required_argument,  0, 'a' },
    { "config-file",    required_argument,  0, 'x' },
    { "debug",          no_argument,        0, 'd' },
    { "ssl",            required_argument,  0, 'e' },
    { 0, 0, 0, 0 }
};

/* initialize "classic" socket */
int init_n_socket(char* address, char* port);

/* initialize unix domain socket */
int init_u_socket();

SSL_CTX* init_ssl_context(void);

/* print help message to stderr and exit with ERR ? */
void usage_and_exit(int err);

/* take care of zombies */
void sigchld_handler(int sig);

/* serve(); */
void serve(int sockfd_in);

/* serve ssl */
void serve_ssl(SSL* ssl);

/* fill out port and/or addr and return flags */
int parse_addr_input(char* input, char* addr, char* port);



#endif