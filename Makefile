VERSION:=$(shell cat VERSION)
override CFLAGS+=-D_RH_VERSION=\"$(VERSION)\"

ifneq (,$(DEBUG))
override CFLAGS+=-Wall -O0 -g
else
override CFLAGS+=-O2
endif

ifneq (,$(STATIC))
override LDFLAGS+=-static
endif

ifneq (,$(STRIP))
override LDFLAGS+=-s
endif

ifneq (,$(MAGIC))
override CFLAGS+=-DWITH_LIBMAGIC
override LDFLAGS+=-lmagic
endif

ifneq (,$(PIE))
# Linux and other systems with gcc and binutils
override CFLAGS+=-fPIE
override LDFLAGS+=-pie -Wl,-z,relro
endif

default: ryshttpd
all: ryshttpd htupload

RYSHTTPD_SRCS = $(filter-out htupload.c, $(wildcard *.c))
HTUPLOAD_SRCS = htupload.c conf.c say.c error.c memory.c io.c strxstr.c regexmatch.c xmalloc.c xstrlcpy.c xmemmem.c
HDRS = $(wildcard *.h)
RYSHTTPD_OBJS = $(RYSHTTPD_SRCS:.c=.o)
HTUPLOAD_OBJS = $(HTUPLOAD_SRCS:.c=.o)

%.o: %.c VERSION $(HDRS)
	$(CC) $(CFLAGS) -c -o $@ $<

ryshttpd: $(RYSHTTPD_OBJS)
	$(CC) $(RYSHTTPD_OBJS) -o $@ $(LDFLAGS)

htupload: $(HTUPLOAD_OBJS)
	$(CC) $(HTUPLOAD_OBJS) -o $@ $(LDFLAGS)

distclean: clean
clean:
	rm -f *.o ryshttpd htupload
