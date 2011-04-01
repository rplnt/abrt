bin_PROGRAMS = abrt-api

abrt_api_SOURCES = \
    main.c \
    abrtapi.h abrtapi.c
abrt_api_CPPFLAGS = \
    -I$(srcdir)/../include/report -I$(srcdir)/../include \
    -I$(srcdir)/../lib \
    $(GLIB_CFLAGS) \
    -D_GNU_SOURCE \
    -Wall -Wwrite-strings -Werror
#    $(GTK_CFLAGS)
abrt_api_LDADD = \
    ../lib/libreport.la \
    $(GLIB_LIBS) \
    -lglib-2.0 \
    -lssl \
    -lcrypto \
    -lxml2

#man_MANS = abrt-api.1
#EXTRA_DIST = $(man_MANS)

#completiondir = $(sysconfdir)/bash_completion.d
#dist_completion_DATA = abrt-cli.bash

DEFS = -DLOCALEDIR=\"$(localedir)\" @DEFS@
