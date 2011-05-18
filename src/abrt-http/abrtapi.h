#ifndef ABRTAPI_H
#define ABRTAPI_H

//THIS SHALL BE REMOVED AS IT OVERRIDE MAKEFILES
//###########################################################
#undef DEBUG_DUMPS_DIR
#define DEBUG_DUMPS_DIR "/var/spool/abrt"
//###########################################################*/
//FIXME FIXME FIXME FIXME

/* includes */
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <signal.h>
#include <security/pam_appl.h>
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
#include <libxml2/libxml/tree.h>
#include <libxml/tree.h>

#include "abrt_dbus.h"
#include "abrtlib.h"
#include "abrtapi_http.h"
#include "abrtapi_api.h"


/* globals */
#define STATIC_PATH ".abrt/static"
#define PREF_CONTENT_TYPE XML
extern content_type default_content_type;
//TODO set from config
//prefered content type, css, ..

/* options */
#define OPT_DBG (1U) //don't daemonize and print errors
#define OPT_ADDR (1U<<1) //address (wheter sock name or ip address) was set
#define OPT_CFG (1U<<2)
#define OPT_SOCK (1U<<3) //use unix socket
#define OPT_IP  (1U<<4) //use network socket
#define OPT_PORT (1U<<5) //port was set
#define OPT_SSL (1U<<6) //use ssl

/* api version */
#define API_VERSION "0.1"


//TODO
/* should be in makefile ? */
#define CONFIG_PATH "/etc/abrt/api.conf" //path to config file
#define BACKLOG (16) //maximum number of connection
#define INPUT_LEN (128) //maximum length of url/path input
#define PORT_LEN (16) //maximum length of port/service
#define READ_BUF (2*1024) //read from socket at once == max header size

/* should be in config file */
#define CERT_FILE "/home/rplnt/projects/certs/cacert.pem"
#define KEY_FILE "/home/rplnt/projects/certs/privkey.pem"
//TODO

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
int serve(void* sock, int flags);

/* fill out port and/or addr and return flags */
int parse_addr_input(char* input, char* addr, char* port);

/* helpers */
/* copy string with len check */
bool safe_strcpy(char* dest, const char* src, int max_len);
/* remove CR characters */
bool delete_cr( gchar* in);
/* remove trailing slashes */
char *rm_slash(const char *path);

/* PAM */
struct passwd* basic_auth_pam(const char *user, const char *pass);

#endif