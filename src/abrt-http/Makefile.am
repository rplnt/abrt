bin_PROGRAMS = abrt-http

abrt_http_SOURCES = \
    abrtapi.c abrtapi.h \
    abrtapi_api.h abrtapi_api.c \
    abrtapi_http.h abrtapi_http.c \
    abrtapi_pam.c
abrt_http_CPPFLAGS = \
    -I$(srcdir)/../include/report -I$(srcdir)/../include \
    -I$(srcdir)/../lib \
    $(LIBXML_CFLAGS) \
    $(GLIB_CFLAGS) \
    $(DBUS_CFLAGS) \
    $(OPENSSL_CFLAGS) \
    -D_GNU_SOURCE \
    -Wall -Wwrite-strings -Werror \
    -DDEBUG_DUMPS_DIR=\"$(DEBUG_DUMPS_DIR)\"
#    $(GTK_CFLAGS)
abrt_http_LDADD = \
    ../lib/libreport.la \
    ../lib/libabrt_dbus.la \
    -lpam -lpam_misc \
    $(GLIB_LIBS) \
    $(LIBXML_LIBS) \
    $(OPENSSL_LIBS)

#man_MANS = abrt-http.1
#EXTRA_DIST = $(man_MANS)

DEFS = -DLOCALEDIR=\"$(localedir)\" @DEFS@
