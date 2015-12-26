bin_PROGRAMS = fuse_b25

COMMON_SRC = \
	bcas.c \
	bcas.h \
	stream.c \
	stream.h \
	secfilter.c \
	secfilter.h \
	pfdmap.c \
	pfdmap.h \
	convert.c \
	convert.h \
	b24str.c \
	demulti2.c \
	demulti2.h

fuse_b25_SOURCES = \
	b25.c \
	$(COMMON_SRC)

AM_CFLAGS = $(FUSE_CFLAGS) $(PCSC_CFLAGS) -fno-strict-aliasing -Wall
fuse_b25_LDADD = $(FUSE_LIBS) $(PCSC_LIBS)

