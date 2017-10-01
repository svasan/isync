AC_INIT([isync], [1.3.0])
AC_CONFIG_HEADERS([autodefs.h])
AM_INIT_AUTOMAKE

AM_MAINTAINER_MODE

AC_PROG_CC_C99
if test "$GCC" = yes; then
    CFLAGS="$CFLAGS -pipe -W -Wall -Wshadow -Wstrict-prototypes -std=c99 -pedantic -Wno-overlength-strings"
fi

CPPFLAGS="$CPPFLAGS -D_GNU_SOURCE"

AC_CACHE_CHECK([whether strftime supports %z], ob_cv_strftime_z,
    [AC_TRY_RUN(
[#include <time.h>
#include <string.h>

int main(void)
{
    time_t t = 0;
    char buf[32];
    strftime(buf, sizeof(buf), "%z", localtime(&t));
    return !(buf[0] == '+' || buf[0] == '-');
}
], [ob_cv_strftime_z=yes], [ob_cv_strftime_z=no], [ob_cv_strftime_z="yes (assumed)"])])
if test "x$ob_cv_strftime_z" = x"no"; then
    AC_MSG_ERROR([libc lacks necessary feature])
fi

AC_CHECK_HEADERS(sys/poll.h sys/select.h)
AC_CHECK_FUNCS(vasprintf strnlen memrchr timegm)

AC_CHECK_LIB(socket, socket, [SOCK_LIBS="-lsocket"])
AC_CHECK_LIB(nsl, inet_ntoa, [SOCK_LIBS="$SOCK_LIBS -lnsl"])
AC_SUBST(SOCK_LIBS)

have_ipv6=true
sav_LIBS=$LIBS
LIBS="$LIBS $SOCK_LIBS"
AC_CHECK_FUNCS(getaddrinfo inet_ntop, , [have_ipv6=false])
LIBS=$sav_LIBS
if $have_ipv6; then
    AC_DEFINE(HAVE_IPV6, 1, [if your libc has IPv6 support])
fi

have_ssl_paths=
AC_ARG_WITH(ssl,
  AC_HELP_STRING([--with-ssl[=PATH]], [where to look for SSL [detect]]),
  [ob_cv_with_ssl=$withval])
if test "x$ob_cv_with_ssl" != xno; then
  case $ob_cv_with_ssl in
    ""|yes)
      dnl Detect the pkg-config tool, as it may have extra info about the openssl
      dnl installation we can use. I *believe* this is what we are expected to do
      dnl on really recent Redhat Linux hosts.
      PKG_PROG_PKG_CONFIG
      if test "x$PKG_CONFIG" != "x" ; then
        AC_MSG_CHECKING([OpenSSL presence with pkg-config])
        if $PKG_CONFIG --exists openssl; then
          SSL_LIBS=`$PKG_CONFIG --libs-only-l openssl`
          SSL_LDFLAGS=`$PKG_CONFIG --libs-only-L openssl`
          SSL_CPPFLAGS=`$PKG_CONFIG --cflags-only-I openssl`
          have_ssl_paths=yes
          AC_MSG_RESULT([found])
        else
          AC_MSG_RESULT([not found])
        fi
      fi
      ;;
    *)
      SSL_LDFLAGS=-L$ob_cv_with_ssl/lib$libsuff
      SSL_CPPFLAGS=-I$ob_cv_with_ssl/include
      ;;
  esac
  if test -z "$have_ssl_paths"; then
    sav_LDFLAGS=$LDFLAGS
    LDFLAGS="$LDFLAGS $SSL_LDFLAGS"
    AC_CHECK_LIB(dl, dlopen, [LIBDL=-ldl])
    AC_CHECK_LIB(crypto, CRYPTO_lock, [LIBCRYPTO=-lcrypto])
    AC_CHECK_LIB(ssl, SSL_connect,
                 [SSL_LIBS="-lssl $LIBCRYPTO $LIBDL" have_ssl_paths=yes])
    LDFLAGS=$sav_LDFLAGS
  fi

  sav_CPPFLAGS=$CPPFLAGS
  CPPFLAGS="$CPPFLAGS $SSL_CPPFLAGS"
  AC_CHECK_HEADER(openssl/ssl.h, , [have_ssl_paths=])
  CPPFLAGS=$sav_CPPFLAGS

  if test -z "$have_ssl_paths"; then
    if test -n "$ob_cv_with_ssl"; then
      AC_MSG_ERROR([OpenSSL libs and/or includes were not found where specified])
    fi
  else
    AC_DEFINE(HAVE_LIBSSL, 1, [if you have the OpenSSL libraries])
    CPPFLAGS="$CPPFLAGS $SSL_CPPFLAGS"
    LDFLAGS="$LDFLAGS $SSL_LDFLAGS"
  fi
fi
AC_SUBST(SSL_LIBS)

have_sasl_paths=
AC_ARG_WITH(sasl,
  AS_HELP_STRING([--with-sasl[=PATH]], [where to look for SASL [detect]]),
  [ob_cv_with_sasl=$withval])
if test "x$ob_cv_with_sasl" != xno; then
  case $ob_cv_with_sasl in
    ""|yes)
      dnl FIXME: Try various possible paths here...
      ;;
    *)
      SASL_LDFLAGS=-L$ob_cv_with_sasl/lib$libsuff
      SASL_CPPFLAGS=-I$ob_cv_with_sasl/include
      ;;
  esac
  if test -z "$have_sasl_paths"; then
    sav_LDFLAGS=$LDFLAGS
    LDFLAGS="$LDFLAGS $SASL_LDFLAGS"
    AC_CHECK_LIB(sasl2, sasl_client_init,
                 [SASL_LIBS="-lsasl2" have_sasl_paths=yes])
    LDFLAGS=$sav_LDFLAGS
  fi

  sav_CPPFLAGS=$CPPFLAGS
  CPPFLAGS="$CPPFLAGS $SASL_CPPFLAGS"
  AC_CHECK_HEADER(sasl/sasl.h, , [have_sasl_paths=])
  CPPFLAGS=$sav_CPPFLAGS

  if test -z "$have_sasl_paths"; then
    if test -n "$ob_cv_with_sasl"; then
      AC_MSG_ERROR([SASL libs and/or includes were not found where specified])
    fi
  else
    AC_DEFINE(HAVE_LIBSASL, 1, [if you have the SASL libraries])
    CPPFLAGS="$CPPFLAGS $SASL_CPPFLAGS"
    LDFLAGS="$LDFLAGS $SASL_LDFLAGS"
  fi
fi
AC_SUBST(SASL_LIBS)

AC_CACHE_CHECK([for Berkeley DB >= 4.1], ac_cv_berkdb4,
  [ac_cv_berkdb4=no
    sav_LIBS=$LIBS
    LIBS="$LIBS -ldb"
   AC_TRY_LINK([#include <db.h>],
               [DB *db;
	        db_create(&db, 0, 0);
	        db->truncate(db, 0, 0, 0);
	        db->open(db, 0, "foo", "foo", DB_HASH, DB_CREATE, 0)],
	       [ac_cv_berkdb4=yes])
    LIBS=$sav_LIBS
  ])
if test "x$ac_cv_berkdb4" = xyes; then
  AC_SUBST([DB_LIBS], ["-ldb"])
  AC_DEFINE(USE_DB, 1, [if Berkeley DB should be used])
fi

have_zlib=
AC_ARG_WITH(zlib,
  AS_HELP_STRING([--with-zlib], [use zlib [detect]]),
  [ob_cv_with_zlib=$withval])
if test "x$ob_cv_with_zlib" != xno; then
  AC_CHECK_LIB([z], [deflate],
      [AC_CHECK_HEADER(zlib.h,
          [have_zlib=1
           AC_SUBST([Z_LIBS], ["-lz"])
           AC_DEFINE([HAVE_LIBZ], 1, [if you have the zlib library])]
       )]
  )
fi

AC_ARG_ENABLE(compat,
  AC_HELP_STRING([--disable-compat], [don't include isync compatibility wrapper [no]]),
  [ob_cv_enable_compat=$enableval])
if test "x$ob_cv_enable_compat" != xno; then
  AC_CHECK_FUNCS(getopt_long)
fi
AM_CONDITIONAL(with_compat, test "x$ob_cv_enable_compat" != xno -a "x$ac_cv_berkdb4" = xyes)
AM_CONDITIONAL(with_mdconvert, test "x$ac_cv_berkdb4" = xyes)

AC_CONFIG_FILES([Makefile src/Makefile src/compat/Makefile isync.spec])
AC_OUTPUT

AC_MSG_RESULT()
if test -n "$have_ssl_paths"; then
    AC_MSG_RESULT([Using SSL])
else
    AC_MSG_RESULT([Not using SSL])
fi
if test -n "$have_sasl_paths"; then
    AC_MSG_RESULT([Using SASL])
else
    AC_MSG_RESULT([Not using SASL])
fi
if test -n "$have_zlib"; then
    AC_MSG_RESULT([Using zlib])
else
    AC_MSG_RESULT([Not using zlib])
fi
if test "x$ac_cv_berkdb4" = xyes; then
    AC_MSG_RESULT([Using Berkeley DB])
else
    AC_MSG_RESULT([Not using Berkeley DB])
fi
AC_MSG_RESULT()
