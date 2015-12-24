bin_PROGRAMS = fuse_b25 fuse_b25.org

COMMON_SRC = \
	bcas.c \
	bcas.h \
	stream.c \
	stream.h \
	pfdmap.c \
	pfdmap.h \
	convert.c \
	b24str.c \
	demulti2.c \
	demulti2.h

fuse_b25_SOURCES = \
	b25.c \
	$(COMMON_SRC)

fuse_b25_org_SOURCES = \
	b25.org.c \
	$(COMMON_SRC)

AM_CFLAGS = $(FUSE_CFLAGS) $(PCSC_CFLAGS)
fuse_b25_LDADD = $(FUSE_LIBS) $(PCSC_LIBS)
fuse_b25_org_LDADD = $(FUSE_LIBS) $(PCSC_LIBS)
