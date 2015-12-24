#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.63])
AC_INIT([fuse_b25], [0.4.7],
    [http://hibari.2ch.net/test/read.cgi/linux/1293388638/])
AC_CONFIG_SRCDIR([src/b25.c])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE

# for defining _GNU_SOURCE
AC_USE_SYSTEM_EXTENSIONS

# Checks for programs.
AC_PROG_CC
dnl AM_PROG_CC_C_O
PKG_PROG_PKG_CONFIG
AC_C_INLINE
AC_C_BIGENDIAN

# Checks for libraries.
PKG_CHECK_MODULES([FUSE], [fuse >= 2.8])
AC_SUBST([FUSE_CFLAGS])
AC_SUBST([FUSE_LIBS])

PKG_CHECK_MODULES([PCSC], [libpcsclite])
AC_SUBST([PCSC_CFLAGS])
AC_SUBST([PCSC_LIBS])


# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h iconv.h linux/dvb/dmx.h nttypes.h stddef.h stdint.h stdlib.h string.h sys/ioctl.h sys/time.h syslog.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_OFF_T
AC_TYPE_SIZE_T

AC_TYPE_INT64_T
AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T

# Checks for library functions.
AC_CHECK_FUNCS([eaccess gettimeofday memset strdup])
AC_FUNC_MALLOC
AC_FUNC_REALLOC

AC_CONFIG_FILES([Makefile src/Makefile fuse_b25.spec])
AC_OUTPUT
