AM_CPPFLAGS =

if LOCAL_TALLOC
AM_CPPFLAGS += -I$(top_srcdir)/src/ccan/talloc
endif

if LOCAL_LLHTTP
AM_CPPFLAGS += -I$(top_srcdir)/src/llhttp/
NEEDED_LLHTTP_LIBS =
else
NEEDED_LLHTTP_LIBS = $(LLHTTP_LIBS)
endif

if LOCAL_PROTOBUF_C
AM_CPPFLAGS += -I$(top_builddir)/src/protobuf/
NEEDED_LIBPROTOBUF_LIBS = libprotobuf.a
else
NEEDED_LIBPROTOBUF_LIBS = $(LIBPROTOBUF_C_LIBS)
endif
