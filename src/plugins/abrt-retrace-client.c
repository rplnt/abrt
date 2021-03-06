/*
    Copyright (C) 2010  Red Hat, Inc.

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/
#include "abrtlib.h"
#include "parse_options.h"
#include "strbuf.h"
#include <nspr.h>
#include <nss.h>
#include <pk11pub.h>
#include <ssl.h>
#include <sslproto.h>
#include <sslerr.h>
#include <secerr.h>
#include <secmod.h>

struct retrace_settings
{
    int running_tasks;
    int max_running_tasks;
    long long max_packed_size;
    long long max_unpacked_size;
    char **supported_formats;
    char **supported_releases;
};

static const char *dump_dir_name = NULL;
static const char *coredump = NULL;
static const char *url = "retrace.fedoraproject.org";
static const char *required_files[] = { FILENAME_COREDUMP,
                                        FILENAME_EXECUTABLE,
                                        FILENAME_PACKAGE,
                                        FILENAME_OS_RELEASE,
                                        NULL };
static bool ssl_allow_insecure = false;
static bool http_show_headers = false;

/* Add an entry name to the args array if the entry name exists in a
 * dump directory. The entry is added to argindex offset to the array,
 * and the argindex is then increased.
 */
static void args_add_if_exists(const char *args[],
                               struct dump_dir *dd,
                               const char *name,
                               int *argindex)
{
    if (dd_exist(dd, name))
    {
        args[*argindex] = name;
        *argindex += 1;
    }
}

/* Create an archive with files required for retrace server and return
 * a file descriptor. Returns -1 if it fails.
 */
static int create_archive(bool unlink_temp)
{
    struct dump_dir *dd = dd_opendir(dump_dir_name, /*flags:*/ 0);
    if (!dd)
        return -1;

    /* Open a temporary file. */
    char *filename = xstrdup("/tmp/abrt-retrace-client-archive-XXXXXX.tar.xz");
    int tempfd = mkstemps(filename, /*suffixlen:*/7);
    if (tempfd == -1)
        perror_msg_and_die("Cannot open temporary file");
    if (unlink_temp)
        xunlink(filename);
    free(filename);

    /* Run xz:
     * - xz reads input from a pipe
     * - xz writes output to the temporary file.
     */
    const char *xz_args[4];
    xz_args[0] = "xz";
    xz_args[1] = "-2";
    xz_args[2] = "-";
    xz_args[3] = NULL;

    int tar_xz_pipe[2];
    xpipe(tar_xz_pipe);
    pid_t xz_child = fork();
    if (xz_child == -1)
        perror_msg_and_die("fork");
    else if (xz_child == 0)
    {
        close(tar_xz_pipe[1]);
        xmove_fd(tar_xz_pipe[0], STDIN_FILENO);
        xdup2(tempfd, STDOUT_FILENO);
        execvp(xz_args[0], (char * const*)xz_args);
	perror_msg("Can't execute '%s'", xz_args[0]);
    }

    close(tar_xz_pipe[0]);

    /* Run tar, and set output to a pipe with xz waiting on the other
     * end.
     */
    const char *tar_args[10];
    tar_args[0] = "tar";
    tar_args[1] = "cO";
    tar_args[2] = xasprintf("--directory=%s", dump_dir_name);
    int index = 3;
    while (required_files[index - 3])
        args_add_if_exists(tar_args, dd, required_files[index - 3], &index);

    tar_args[index] = NULL;
    dd_close(dd);

    pid_t tar_child = fork();
    if (tar_child == -1)
        perror_msg_and_die("fork");
    else if (tar_child == 0)
    {
        xmove_fd(xopen("/dev/null", O_RDWR), STDIN_FILENO);
        xmove_fd(tar_xz_pipe[1], STDOUT_FILENO);
        execvp(tar_args[0], (char * const*)tar_args);
	perror_msg("Can't execute '%s'", tar_args[0]);
    }

    close(tar_xz_pipe[1]);

    /* Prevent having zombie child process. */
    int status;
    VERB1 log_msg("Waiting for tar...");
    waitpid(tar_child, &status, 0);
    free((void*)tar_args[2]);
    VERB1 log_msg("Waiting for xz...");
    waitpid(xz_child, &status, 0);
    VERB1 log_msg("Done...");
    xlseek(tempfd, 0, SEEK_SET);
    return tempfd;
}

static SECStatus ssl_bad_cert_handler(void *arg, PRFileDesc *sock)
{
    PRErrorCode err = PR_GetError();
    CERTCertificate *cert = SSL_PeerCertificate(sock);
    char *subject = CERT_NameToAscii(&cert->subject);
    char *subject_cn = CERT_GetCommonName(&cert->subject);
    char *issuer = CERT_NameToAscii(&cert->issuer);
    CERT_DestroyCertificate(cert);
    char *target_host = SSL_RevealURL(sock);
    if (!target_host)
        target_host = xstrdup("(unknown)");
    switch (err)
    {
    case SEC_ERROR_CA_CERT_INVALID:
        error_msg("Issuer certificate is invalid: '%s'.", issuer);
        break;
    case SEC_ERROR_UNTRUSTED_ISSUER:
        error_msg("Certificate is signed by an untrusted issuer: '%s'.", issuer);
        break;
    case SSL_ERROR_BAD_CERT_DOMAIN:
        error_msg("Certificate subject name '%s' does not match target host name '%s'.",
                subject_cn, target_host);
        break;
    case SEC_ERROR_EXPIRED_CERTIFICATE:
        error_msg("Remote certificate has expired.");
        break;
    case SEC_ERROR_UNKNOWN_ISSUER:
        error_msg("Certificate issuer is not recognized: '%s'", issuer);
        break;
    default:
        error_msg("Bad certifiacte received. Subject '%s', issuer '%s'.",
                subject, issuer);
        break;
    }
    PR_Free(target_host);
    return ssl_allow_insecure ? SECSuccess : SECFailure;
}

static SECStatus ssl_handshake_callback(PRFileDesc *sock, void *arg)
{
    return SECSuccess;
}

static const char *ssl_get_configdir()
{
    struct stat buf;
    if (getenv("SSL_DIR"))
    {
        if (0 == stat(getenv("SSL_DIR"), &buf) &&
            S_ISDIR(buf.st_mode))
        {
            return getenv("SSL_DIR");
        }
    }
    if (0 == stat("/etc/pki/nssdb", &buf) &&
        S_ISDIR(buf.st_mode))
    {
        return "/etc/pki/nssdb";
    }
    return NULL;
}

static PK11GenericObject *nss_load_cacert(const char *filename)
{
    PK11SlotInfo *slot = PK11_FindSlotByName("PEM Token #0");
    if (!slot)
        error_msg_and_die("Failed to get slot 'PEM Token #0': %d.", PORT_GetError());

    CK_ATTRIBUTE template[4];
    CK_OBJECT_CLASS class = CKO_CERTIFICATE;

#define PK11_SETATTRS(x,id,v,l) (x)->type = (id);       \
  (x)->pValue=(v); (x)->ulValueLen = (l)

    PK11_SETATTRS(&template[0], CKA_CLASS, &class, sizeof(class));
    CK_BBOOL cktrue = CK_TRUE;
    PK11_SETATTRS(&template[1], CKA_TOKEN, &cktrue, sizeof(CK_BBOOL));
    PK11_SETATTRS(&template[2], CKA_LABEL, (unsigned char*)filename, strlen(filename)+1);
    PK11_SETATTRS(&template[3], CKA_TRUST, &cktrue, sizeof(CK_BBOOL));
    PK11GenericObject *cert = PK11_CreateGenericObject(slot, template, 4, PR_FALSE);
    PK11_FreeSlot(slot);
    return cert;
}

static char *ssl_get_password(PK11SlotInfo *slot, PRBool retry, void *arg)
{
    return NULL;
}

static void ssl_connect(PRFileDesc **tcp_sock,
                        PRFileDesc **ssl_sock)
{
    *tcp_sock = PR_NewTCPSocket();
    if (!*tcp_sock)
        error_msg_and_die("Failed to create a TCP socket");
    PRSocketOptionData sock_option;
    sock_option.option  = PR_SockOpt_Nonblocking;
    sock_option.value.non_blocking = PR_FALSE;
    PRStatus pr_status = PR_SetSocketOption(*tcp_sock, &sock_option);
    if (PR_SUCCESS != pr_status)
    {
        PR_Close(*tcp_sock);
        error_msg_and_die("Failed to set socket blocking mode.");
    }
    *ssl_sock = SSL_ImportFD(NULL, *tcp_sock);
    if (!*ssl_sock)
    {
        PR_Close(*tcp_sock);
        error_msg_and_die("Failed to wrap TCP socket by SSL");
    }
    SECStatus sec_status = SSL_OptionSet(*ssl_sock, SSL_HANDSHAKE_AS_CLIENT, PR_TRUE);
    if (SECSuccess != sec_status)
    {
        PR_Close(*ssl_sock);
        error_msg_and_die("Failed to enable client handshake to SSL socket.");
    }
    if (SECSuccess != SSL_OptionSet(*ssl_sock, SSL_ENABLE_SSL2, PR_TRUE))
        error_msg_and_die("Failed to enable client handshake to SSL socket.");
    if (SECSuccess != SSL_OptionSet(*ssl_sock, SSL_ENABLE_SSL3, PR_TRUE))
        error_msg_and_die("Failed to enable client handshake to SSL socket.");
    if (SECSuccess != SSL_OptionSet(*ssl_sock, SSL_ENABLE_TLS, PR_TRUE))
        error_msg_and_die("Failed to enable client handshake to SSL socket.");

    sec_status = SSL_SetURL(*ssl_sock, url);
    if (SECSuccess != sec_status)
    {
        PR_Close(*ssl_sock);
        error_msg_and_die("Failed to set URL to SSL socket.");
    }
    char buffer[PR_NETDB_BUF_SIZE];
    PRHostEnt host_entry;
    pr_status = PR_GetHostByName(url, buffer, sizeof(buffer), &host_entry);
    if (PR_SUCCESS != pr_status)
    {
        char *error = xmalloc(PR_GetErrorTextLength());
        PRInt32 count = PR_GetErrorText(error);
        PR_Close(*ssl_sock);
        if (count)
            error_msg_and_die("Failed to get host by name: %s", error);
        else
        {
            error_msg_and_die("Failed to get host by name: pr_status == %d, pr_error == %d, url '%s'",
                              pr_status, PR_GetError(), url);
        }
    }
    PRNetAddr addr;
    PRInt32 rv = PR_EnumerateHostEnt(0, &host_entry, /*port:*/443, &addr);
    if (rv < 0)
    {
        PR_Close(*ssl_sock);
        error_msg_and_die("Failed to enumerate host ent.");
    }
    pr_status = PR_Connect(*ssl_sock, &addr, PR_INTERVAL_NO_TIMEOUT);
    if (PR_SUCCESS != pr_status)
    {
        PR_Close(*ssl_sock);
        error_msg_and_die("Failed to connect SSL address.");
    }
    if (SECSuccess != SSL_BadCertHook(*ssl_sock,
                                      (SSLBadCertHandler)ssl_bad_cert_handler,
                                      NULL))
    {
        PR_Close(*ssl_sock);
        error_msg_and_die("Failed to set certificate hook.");
    }
    if (SECSuccess != SSL_HandshakeCallback(*ssl_sock,
                                            (SSLHandshakeCallback)ssl_handshake_callback,
                                            NULL))
    {
        PR_Close(*ssl_sock);
        error_msg_and_die("Failed to set handshake callback.");
    }
    sec_status = SSL_ResetHandshake(*ssl_sock, /*asServer:*/PR_FALSE);
    if (SECSuccess != sec_status)
    {
        PR_Close(*ssl_sock);
        error_msg_and_die("Failed to reset handshake.");
    }
    sec_status = SSL_ForceHandshake(*ssl_sock);
    if (SECSuccess != sec_status)
    {
        PR_Close(*ssl_sock);
        error_msg_and_die("Failed to force handshake: NSS error %d",
                          PR_GetError());
    }
}

static void ssl_disconnect(PRFileDesc *ssl_sock)
{
    PRStatus pr_status = PR_Close(ssl_sock);
    if (PR_SUCCESS != pr_status)
        error_msg("Failed to close SSL socket.");
}

/**
 * Parse a header's value from HTTP message. Only alnum values are supported.
 * @returns
 * Caller must free the returned value.
 * If no header is found, NULL is returned.
 */
static char *http_get_header_value(const char *message,
                                   const char *header_name)
{
    char *headers_end = strstr(message, "\r\n\r\n");
    if (!headers_end)
        return NULL;
    char *search_string = xasprintf("\r\n%s:", header_name);
    char *header = strcasestr(message, search_string);
    if (!header || header > headers_end)
        return NULL;
    header += strlen(search_string);
    free(search_string);
    while (*header == ' ')
        ++header;
    int len = 0;
    while (header[len] && header[len] != '\r' && header[len] != '\n')
        ++len;
    while (header[len - 1] == ' ') /* strip spaces from right */
        --len;
    return xstrndup(header, len);
}

/**
 * Parse body from HTTP message.
 * Caller must free the returned value.
 */
static char *http_get_body(const char *message)
{
    char *body = strstr(message, "\r\n\r\n");
    if (!body)
        return NULL;

    body += strlen("\r\n\r\n");

    while (*body == ' ')
        ++body;

    int len = strlen(body);
    while (body[len - 1] == ' ')
        --len;

    return xstrndup(body, len);
}

static int http_get_response_code(const char *message)
{
    if (0 != strncmp(message, "HTTP/", strlen("HTTP/")))
        error_msg_and_die("Invalid response from server: HTTP header not found.");
    char *space = strstr(message, " ");
    if (!space)
        error_msg_and_die("Invalid response from server: HTTP header not found.");
    int response_code;
    if (1 != sscanf(space + 1, "%d", &response_code))
        error_msg_and_die("Invalid response from server: HTTP header not found.");
    return response_code;
}

static void http_print_headers(FILE *file, const char *message)
{
    const char *headers_end = strstr(message, "\r\n\r\n");
    const char *c;
    if (!headers_end)
        headers_end = message + strlen(message);
    for (c = message; c != headers_end + 2; ++c)
    {
        if (*c == '\r')
            continue;
        putc(*c, file);
    }
}

/**
 * @returns
 * Caller must free the returned value.
 */
static char *tcp_read_response(PRFileDesc *tcp_sock)
{
    struct strbuf *strbuf = strbuf_new();
    char buf[32768];
    PRInt32 received = 0;
    do {
        received = PR_Recv(tcp_sock, buf, sizeof(buf) - 1, /*flags:*/0,
                           PR_INTERVAL_NO_TIMEOUT);
        if (received > 0)
        {
            buf[received] = '\0';
            strbuf_append_str(strbuf, buf);
        }
        if (received == -1)
        {
            error_msg_and_die("Receiving of data failed: NSS error %d",
                              PR_GetError());
        }
    } while (received > 0);
    return strbuf_free_nobuf(strbuf);
}

static void get_settings(struct retrace_settings *settings)
{
    /* defaults */
    settings->running_tasks = 0;
    settings->max_running_tasks = 0;
    settings->max_packed_size = 0;
    settings->max_unpacked_size = 0;
    settings->supported_formats = NULL;
    settings->supported_releases = NULL;

    PRFileDesc *tcp_sock, *ssl_sock;
    ssl_connect(&tcp_sock, &ssl_sock);
    struct strbuf *http_request = strbuf_new();
    strbuf_append_strf(http_request,
                       "GET /settings HTTP/1.1\r\n"
                       "Host: %s\r\n"
                       "Content-Length: 0\r\n"
                       "Connection: close\r\n"
                       "\r\n", url);
    PRInt32 written = PR_Send(tcp_sock, http_request->buf, http_request->len,
                              /*flags:*/0, PR_INTERVAL_NO_TIMEOUT);
    if (written == -1)
    {
        PR_Close(ssl_sock);
        error_msg_and_die("Failed to send HTTP header of length %d: NSS error %d",
                          http_request->len, PR_GetError());
    }
    strbuf_free(http_request);

    char *http_response = tcp_read_response(tcp_sock);
    if (http_show_headers)
        http_print_headers(stderr, http_response);
    int response_code = http_get_response_code(http_response);
    if (response_code != 200)
    {
        error_msg_and_die("Unexpected HTTP response from server: %d\n%s",
                          response_code, http_response);
    }

    char *headers_end = strstr(http_response, "\r\n\r\n");
    char *c, *row, *value;
    if (!headers_end)
        error_msg_and_die("Invalid response from server: missing HTTP message body.");
    row = headers_end + strlen("\r\n\r\n");

    do
    {
        /* split rows */
        c = strchr(row, '\n');
        if (c)
            *c = '\0';

        /* split key and values */
        value = strchr(row, ' ');
        if (!value)
        {
            row = c + 1;
            continue;
        }

        *value = '\0';
        ++value;

        if (0 == strcasecmp("running_tasks", row))
            settings->running_tasks = atoi(value);
        else if (0 == strcasecmp("max_running_tasks", row))
            settings->max_running_tasks = atoi(value);
        else if (0 == strcasecmp("max_packed_size", row))
            settings->max_packed_size = atoi(value) * 1024 * 1024;
        else if (0 == strcasecmp("max_unpacked_size", row))
            settings->max_unpacked_size = atoi(value) * 1024 * 1024;
        else if (0 == strcasecmp("supported_formats", row))
        {
            /* ToDo */
        }
        else if (0 == strcasecmp("supported_releases", row))
        {
            /* ToDo */
        }

        /* the beginning of the next row */
        row = c + 1;
    } while (c);

    free(http_response);
    ssl_disconnect(ssl_sock);
}

static int create(bool delete_temp_archive,
                  char **task_id,
                  char **task_password)
{
    struct retrace_settings settings;
    get_settings(&settings);

    if (settings.running_tasks >= settings.max_running_tasks)
    {
        error_msg_and_die("Retrace server is fully occupied at the moment. "
                          "Try again later please.");
    }

    long long unpacked_size = 0;
    struct stat file_stat;

    /* get raw size */
    if (coredump)
    {
        if (stat(coredump, &file_stat) == -1)
            error_msg_and_die("Unable to stat file %s", coredump);

        unpacked_size = (long long)file_stat.st_size;
    }
    else if (dump_dir_name != NULL)
    {
        char *path;
        int i = 0;
        while (required_files[i])
        {
            path = concat_path_file(dump_dir_name, required_files[i]);
            if (stat(path, &file_stat) == -1)
            {
                error_msg("Unable to stat file %s", path);
                free(path);
                xfunc_die();
            }

            unpacked_size += (long long)file_stat.st_size;
            free(path);

            ++i;
        }
    }

    if (unpacked_size > settings.max_unpacked_size)
    {
        error_msg_and_die("The size of your crash is %lld bytes, "
                          "but the retrace server only accepts "
                          "crashes smaller or equal to %lld bytes.",
                          unpacked_size, settings.max_unpacked_size);
    }

    int tempfd = create_archive(delete_temp_archive);
    if (-1 == tempfd)
        return 1;

    /* Get the file size. */
    fstat(tempfd, &file_stat);
    if ((long long)file_stat.st_size > settings.max_packed_size)
    {
        error_msg_and_die("The size of your archive is %lld bytes, "
                          "but the retrace server only accepts "
                          "archives smaller or equal %lld bytes.",
                          (long long)file_stat.st_size,
                          settings.max_packed_size);
    }

    PRFileDesc *tcp_sock, *ssl_sock;
    ssl_connect(&tcp_sock, &ssl_sock);
    /* Upload the archive. */
    struct strbuf *http_request = strbuf_new();
    strbuf_append_strf(http_request,
                       "POST /create HTTP/1.1\r\n"
                       "Host: %s\r\n"
                       "Content-Type: application/x-xz-compressed-tar\r\n"
                       "Content-Length: %lld\r\n"
                       "Connection: close\r\n"
                       "\r\n", url, (long long)file_stat.st_size);
    PRInt32 written = PR_Send(tcp_sock, http_request->buf, http_request->len,
                              /*flags:*/0, PR_INTERVAL_NO_TIMEOUT);
    if (written == -1)
    {
        PR_Close(ssl_sock);
        error_msg_and_die("Failed to send HTTP header of length %d: NSS error %d",
                          http_request->len, PR_GetError());
    }
    strbuf_free(http_request);
    int result = 0;
    while (1)
    {
        char buf[32768];
        int r = read(tempfd, buf, sizeof(buf));
        if (r <= 0)
        {
            if (r == -1)
            {
                if (EINTR == errno || EAGAIN == errno || EWOULDBLOCK == errno)
                    continue;
                perror_msg_and_die("Failed to read from a pipe");
            }
            break;
        }
        written = PR_Send(tcp_sock, buf, r,
                          /*flags:*/0, PR_INTERVAL_NO_TIMEOUT);
        if (written == -1)
        {
            /* Print error message, but do not exit.  We need to check
               if the server send some explanation regarding the
               error. */
            result = 1;
            error_msg("Failed to send data: NSS error %d (%s): %s",
                      PR_GetError(),
                      PR_ErrorToName(PR_GetError()),
                      PR_ErrorToString(PR_GetError(), PR_LANGUAGE_I_DEFAULT));
            break;
        }
    }
    close(tempfd);
    /* Read the HTTP header of the response from server. */
    char *http_response = tcp_read_response(tcp_sock);
    char *http_body = http_get_body(http_response);
    if (!http_body)
        error_msg_and_die("Invalid response from server: missing HTTP message body.");
    if (http_show_headers)
        http_print_headers(stderr, http_response);
    int response_code = http_get_response_code(http_response);
    if (response_code == 500 || response_code == 507)
        error_msg_and_die("There is a problem on the server side: %s", http_body);
    else if (response_code != 201)
        error_msg_and_die("Unexpected HTTP response from server: %d\n%s", response_code, http_body);
    free(http_body);
    *task_id = http_get_header_value(http_response, "X-Task-Id");
    if (!*task_id)
        error_msg_and_die("Invalid response from server: missing X-Task-Id");
    *task_password = http_get_header_value(http_response, "X-Task-Password");
    if (!*task_password)
        error_msg_and_die("Invalid response from server: missing X-Task-Password");
    free(http_response);
    ssl_disconnect(ssl_sock);
    return result;
}

static int run_create(bool delete_temp_archive)
{
    char *task_id, *task_password;
    int result = create(delete_temp_archive, &task_id, &task_password);
    if (0 != result)
        return result;
    printf("Task Id: %s\nTask Password: %s\n", task_id, task_password);
    free(task_id);
    free(task_password);
    return 0;
}

/* Caller must free task_status and status_message */
static void status(const char *task_id,
                   const char *task_password,
                   char **task_status,
                   char **status_message)
{
    PRFileDesc *tcp_sock, *ssl_sock;
    ssl_connect(&tcp_sock, &ssl_sock);
    struct strbuf *http_request = strbuf_new();
    strbuf_append_strf(http_request,
                       "GET /%s HTTP/1.1\r\n"
                       "Host: %s\r\n"
                       "X-Task-Password: %s\r\n"
                       "Content-Length: 0\r\n"
                       "Connection: close\r\n"
                       "\r\n", task_id, url, task_password);
    PRInt32 written = PR_Send(tcp_sock, http_request->buf, http_request->len,
                              /*flags:*/0, PR_INTERVAL_NO_TIMEOUT);
    if (written == -1)
    {
        PR_Close(ssl_sock);
        error_msg_and_die("Failed to send HTTP header of length %d: NSS error %d",
                          http_request->len, PR_GetError());
    }
    strbuf_free(http_request);
    char *http_response = tcp_read_response(tcp_sock);
    char *http_body = http_get_body(http_response);
    if (!*http_body)
        error_msg_and_die("Invalid response from server: missing body");
    if (http_show_headers)
        http_print_headers(stderr, http_response);
    int response_code = http_get_response_code(http_response);
    if (response_code != 200)
    {
        error_msg_and_die("Unexpected HTTP response from server: %d\n%s",
                          response_code, http_body);
    }
    *task_status = http_get_header_value(http_response, "X-Task-Status");
    if (!*task_status)
        error_msg_and_die("Invalid response from server: missing X-Task-Status");
    *status_message = http_body;
    free(http_response);
    ssl_disconnect(ssl_sock);
}

static void run_status(const char *task_id, const char *task_password)
{
    char *task_status;
    char *status_message;
    status(task_id, task_password, &task_status, &status_message);
    printf("Task Status: %s\n%s\n", task_status, status_message);
    free(task_status);
    free(status_message);
}

/* Caller must free backtrace */
static void backtrace(const char *task_id, const char *task_password,
                      char **backtrace)
{
    PRFileDesc *tcp_sock, *ssl_sock;
    ssl_connect(&tcp_sock, &ssl_sock);
    struct strbuf *http_request = strbuf_new();
    strbuf_append_strf(http_request,
                       "GET /%s/backtrace HTTP/1.1\r\n"
                       "Host: %s\r\n"
                       "X-Task-Password: %s\r\n"
                       "Content-Length: 0\r\n"
                       "Connection: close\r\n"
                       "\r\n", task_id, url, task_password);
    PRInt32 written = PR_Send(tcp_sock, http_request->buf, http_request->len,
                              /*flags:*/0, PR_INTERVAL_NO_TIMEOUT);
    if (written == -1)
    {
        PR_Close(ssl_sock);
        error_msg_and_die("Failed to send HTTP header of length %d: NSS error %d",
                          http_request->len, PR_GetError());
    }
    strbuf_free(http_request);
    char *http_response = tcp_read_response(tcp_sock);
    char *http_body = http_get_body(http_response);
    if (!http_body)
        error_msg_and_die("Invalid response from server: missing HTTP message body.");
    if (http_show_headers)
        http_print_headers(stderr, http_response);
    int response_code = http_get_response_code(http_response);
    if (response_code != 200)
    {
        error_msg_and_die("Unexpected HTTP response from server: %d\n%s",
                          response_code, http_body);
    }
    *backtrace = http_body;
    free(http_response);
    ssl_disconnect(ssl_sock);
}

static void run_backtrace(const char *task_id, const char *task_password)
{
    char *backtrace_text;
    backtrace(task_id, task_password, &backtrace_text);
    printf("%s", backtrace_text);
    free(backtrace_text);
}

static void run_log(const char *task_id, const char *task_password)
{
    PRFileDesc *tcp_sock, *ssl_sock;
    ssl_connect(&tcp_sock, &ssl_sock);
    struct strbuf *http_request = strbuf_new();
    strbuf_append_strf(http_request,
                       "GET /%s/log HTTP/1.1\r\n"
                       "Host: %s\r\n"
                       "X-Task-Password: %s\r\n"
                       "Content-Length: 0\r\n"
                       "Connection: close\r\n"
                       "\r\n", task_id, url, task_password);
    PRInt32 written = PR_Send(tcp_sock, http_request->buf, http_request->len,
                              /*flags:*/0, PR_INTERVAL_NO_TIMEOUT);
    if (written == -1)
    {
        PR_Close(ssl_sock);
        error_msg_and_die("Failed to send HTTP header of length %d: NSS error %d",
                          http_request->len, PR_GetError());
    }
    strbuf_free(http_request);
    char *http_response = tcp_read_response(tcp_sock);
    char *http_body = http_get_body(http_response);
    if (!http_body)
        error_msg_and_die("Invalid response from server: missing HTTP message body.");
    if (http_show_headers)
        http_print_headers(stderr, http_response);
    int response_code = http_get_response_code(http_response);
    if (response_code != 200)
    {
        error_msg_and_die("Unexpected HTTP response from server: %d\n%s",
                          response_code, http_body);
    }
    puts(http_body);
    free(http_body);
    free(http_response);
    ssl_disconnect(ssl_sock);
}

static int run_batch(bool delete_temp_archive)
{
    char *task_id, *task_password;
    int retcode = create(delete_temp_archive, &task_id, &task_password);
    if (0 != retcode)
        return retcode;
    char *task_status = xstrdup("");
    char *status_message = xstrdup("");
    while (0 != strncmp(task_status, "FINISHED", strlen("finished")))
    {
        free(task_status);
        free(status_message);
        sleep(10);
        status(task_id, task_password, &task_status, &status_message);
        puts(status_message);
        fflush(stdout);
    }
    if (0 == strcmp(task_status, "FINISHED_SUCCESS"))
    {
        char *backtrace_text;
        backtrace(task_id, task_password, &backtrace_text);
        if (dump_dir_name)
        {
            char *backtrace_path = xasprintf("%s/backtrace", dump_dir_name);
            int backtrace_fd = xopen3(backtrace_path, O_WRONLY | O_CREAT | O_TRUNC, 0640);
            xwrite(backtrace_fd, backtrace_text, strlen(backtrace_text));
            close(backtrace_fd);
            free(backtrace_path);
        }
        else
            printf("%s", backtrace_text);
        free(backtrace_text);
    }
    else
    {
        run_log(task_id, task_password);
        retcode = 1;
    }
    free(task_status);
    free(status_message);
    free(task_id);
    free(task_password);
    return retcode;
}

int main(int argc, char **argv)
{
    abrt_init(argv);

    const char *task_id = NULL;
    const char *task_password = NULL;

    enum {
        OPT_verbose   = 1 << 0,
        OPT_syslog    = 1 << 1,
        OPT_insecure  = 1 << 2,
        OPT_url       = 1 << 3,
        OPT_headers   = 1 << 4,
        OPT_group_1   = 1 << 5,
        OPT_dir       = 1 << 6,
        OPT_core      = 1 << 7,
        OPT_no_unlink = 1 << 8,
        OPT_group_2   = 1 << 9,
        OPT_task      = 1 << 10,
        OPT_password  = 1 << 11
    };

    /* Keep enum above and order of options below in sync! */
    struct options options[] = {
        OPT__VERBOSE(&g_verbose),
        OPT_BOOL('s', "syslog", NULL, _("log to syslog")),
        OPT_BOOL('k', "insecure", NULL,
                 "allow insecure connection to retrace server"),
        OPT_STRING(0, "url", &url, "URL",
                   "retrace server URL"),
        OPT_BOOL(0, "headers", NULL,
                 "(debug) show received HTTP headers"),
        OPT_GROUP("For create and batch operations"),
        OPT_STRING('d', "dir", &dump_dir_name, "DIR",
                   "read data from ABRT crash dump directory"),
        OPT_STRING('c', "core", &coredump, "COREDUMP",
                   "read data from coredump"),
        OPT_BOOL(0, "no-unlink", NULL,
                 "(debug) do not delete temporary archive created"
                 " from dump dir in /tmp"),
        OPT_GROUP("For status, backtrace, and log operations"),
        OPT_STRING('t', "task", &task_id, "ID",
                   "id of your task on server"),
        OPT_STRING('p', "password", &task_password, "PWD",
                   "password of your task on server"),
        OPT_END()
    };

    const char usage[] = "abrt-retrace-client <operation> [options]\n"
        "Operations: create/status/backtrace/log/batch";

    char *env_url = getenv("RETRACE_SERVER_URL");
    if (env_url)
        url = env_url;

    unsigned opts = parse_opts(argc, argv, options, usage);
    if (opts & OPT_syslog)
    {
        openlog(msg_prefix, 0, LOG_DAEMON);
        logmode = LOGMODE_SYSLOG;
    }
    const char *operation = NULL;
    if (optind < argc)
        operation = argv[optind];
    else
        show_usage_and_die(usage, options);
    ssl_allow_insecure = opts & OPT_insecure;
    http_show_headers = opts & OPT_headers;

    /* Initialize NSS */
    SECStatus sec_status;
    const char *configdir = ssl_get_configdir();
    if (configdir)
        sec_status = NSS_Initialize(configdir, "", "", "", NSS_INIT_READONLY);
    else
        sec_status = NSS_NoDB_Init(NULL);
    if (SECSuccess != sec_status)
        error_msg_and_die("Failed to initialize NSS.");

    char *user_module = xstrdup("library=libnsspem.so name=PEM");
    SECMODModule* mod = SECMOD_LoadUserModule(user_module, NULL, PR_FALSE);
    free(user_module);
    if (!mod || !mod->loaded)
        error_msg_and_die("Failed to initialize security module.");

    PK11GenericObject *cert = nss_load_cacert("/etc/pki/tls/certs/ca-bundle.crt");
    PK11_SetPasswordFunc(ssl_get_password);
    NSS_SetDomesticPolicy();

    /* Run the desired operation. */
    int result = 0;
    if (0 == strcasecmp(operation, "create"))
    {
        if (!dump_dir_name && !coredump)
            error_msg_and_die("Either dump directory or coredump is needed.");
        result = run_create(0 == (opts & OPT_no_unlink));
    }
    else if (0 == strcasecmp(operation, "batch"))
    {
        if (!dump_dir_name && !coredump)
            error_msg_and_die("Either dump directory or coredump is needed.");
        result = run_batch(0 == (opts & OPT_no_unlink));
    }
    else if (0 == strcasecmp(operation, "status"))
    {
        if (!task_id)
            error_msg_and_die("Task id is needed.");
        if (!task_password)
            error_msg_and_die("Task password is needed.");
        run_status(task_id, task_password);
    }
    else if (0 == strcasecmp(operation, "backtrace"))
    {
        if (!task_id)
            error_msg_and_die("Task id is needed.");
        if (!task_password)
            error_msg_and_die("Task password is needed.");
        run_backtrace(task_id, task_password);
    }
    else if (0 == strcasecmp(operation, "log"))
    {
        if (!task_id)
            error_msg_and_die("Task id is needed.");
        if (!task_password)
            error_msg_and_die("Task password is needed.");
        run_log(task_id, task_password);
    }
    else
        error_msg_and_die("Unknown operation: %s", operation);

    /* Shutdown NSS. */
    SSL_ClearSessionCache();
    PK11_DestroyGenericObject(cert);
    SECMOD_UnloadUserModule(mod);
    SECMOD_DestroyModule(mod);
    sec_status = NSS_Shutdown();
    if (SECSuccess != sec_status)
        error_msg("Failed to shutdown NSS.");

    PR_Cleanup();

    return result;
}
