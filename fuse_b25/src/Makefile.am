bin_PROGRAMS = fuse_b25 fuse_b25.org

fuse_b25_SOURCES = \
	b25.c \
	bcas.c \
	bcas.h \
	stream.c \
	stream.h \
	convert.c \
	b24str.c \
	demulti2.c \
	demulti2.h

fuse_b25_org_SOURCES = \
	b25.org.c \
	bcas.c \
	bcas.h \
	stream.c \
	stream.h \
	convert.c \
	b24str.c \
	demulti2.c \
	demulti2.h

AM_CFLAGS = $(FUSE_CFLAGS) $(PCSC_CFLAGS)
fuse_b25_LDADD = $(FUSE_LIBS) $(PCSC_LIBS)
fuse_b25_org_LDADD = $(FUSE_LIBS) $(PCSC_LIBS)
