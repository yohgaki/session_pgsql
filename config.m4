dnl
dnl $Id: config.m4 113073 2003-01-22 23:39:59Z yohgaki $
dnl

PHP_ARG_WITH(session-pgsql,for pgsql sesssion storage support,
[  --with-session-pgsql[=DIR] Include pgsql(PostgreSQL) support for session storage])

if test "$PHP_SESSION_PGSQL" != "no"; then

  dnl
  dnl check libmm
  dnl
  LIBNAME=mm
  LIBSYMBOL=mm_create

  for i in /usr/local /usr ; do
    if test -f "$i/include/mm.h"; then
      MM_DIR=$i
    fi
  done

  if test -z "$MM_DIR" ; then
    AC_MSG_ERROR([cannot find mm.h under /usr/local /usr])
  fi

  if test -z "MM_DIR/lib/libmm.so"; then
    AC_MSG_ERROR([cannot find libmm.so under /usr/local /usr])
  fi

dnl  PHP_CHECK_LIBRARY($LIBNAME, $LIBSYMBOL,
dnl   [
dnl     AC_DEFINE(HAVE_MMLIB,1,[Whether you have libmm or not])
dnl   ],[
dnl     AC_MSG_ERROR([wrong libmm])
dnl   ],[
dnl     -L$MM_DIR/lib
dnl   ])
  
  PHP_ADD_INCLUDE($MM_DIR/include)
  PHP_ADD_LIBRARY_WITH_PATH($LIBNAME, $MM_DIR/lib, SESSION_PGSQL_SHARED_LIBADD)

  dnl
  dnl check libpq
  dnl
  LIBNAME=pq
  LIBSYMBOL=PQescapeString

  if test "$PHP_SESSION_PGSQL" = "yes"; then
    PGSQL_SEARCH_PATHS="/usr/local/pgsql /usr/local /usr"
  else
    PGSQL_SEARCH_PATHS=$PHP_SESSION_PGSQL
  fi

  PHP_EXPAND_PATH($PGSQL_INCLUDE, PGSQL_INCLUDE)

  AC_MSG_CHECKING(for pg_config)
  for i in $PHP_SESSION_PGSQL $PHP_SESSION_PGSQL/bin /usr/local/pgsql/bin /usr/local/bin /usr/bin ""; do
    if test -x $i/pg_config; then
      PG_CONFIG="$i/pg_config"
      break;
    fi
  done

  if test -n "$PG_CONFIG"; then
    AC_MSG_RESULT([$PG_CONFIG])
    PGSQL_INCLUDE=`$PG_CONFIG --includedir`
    PGSQL_LIBDIR=`$PG_CONFIG --libdir`
    if test -r "$PGSQL_INCLUDE/pg_config.h"; then
      AC_DEFINE(HAVE_PG_CONFIG_H,1,[Whether to have pg_config.h])
    fi
  else
    AC_MSG_RESULT(not found)
    if test "$PHP_PGSQL" = "yes"; then
      PGSQL_SEARCH_PATHS="/usr /usr/local /usr/local/pgsql"
    else
      PGSQL_SEARCH_PATHS=$PHP_PGSQL
    fi

    for i in $PGSQL_SEARCH_PATHS; do
      for j in include include/pgsql include/postgres include/postgresql ""; do
        if test -r "$i/$j/libpq-fe.h"; then
          PGSQL_INC_BASE=$i
          PGSQL_INCLUDE=$i/$j
          if test -r "$i/$j/pg_config.h"; then
            AC_DEFINE(HAVE_PG_CONFIG_H,1,[Whether to have pg_config.h])
          fi
        fi
      done

      for j in lib $PHP_LIBDIR/pgsql $PHP_LIBDIR/postgres $PHP_LIBDIR/postgresql ""; do
        if test -f "$i/$j/libpq.so" || test -f "$i/$j/libpq.a"; then
          PGSQL_LIBDIR=$i/$j
        fi
      done
    done
  fi

  if test -z "$PGSQL_INCLUDE"; then
    AC_MSG_ERROR([Cannot find libpq-fe.h. Please specify correct PostgreSQL installation path])
  fi

  if test -z "$PGSQL_LIBDIR"; then
    AC_MSG_ERROR([Cannot find libpq.so. Please specify correct PostgreSQL installation path])
  fi

  if test -z "$PGSQL_INCLUDE" -a -z "$PGSQL_LIBDIR" ; then
    AC_MSG_ERROR([Unable to find libpq anywhere under $withval])
  fi

dnl  PHP_CHECK_LIBRARY($LIBNAME, $LIBSYMBOL,
dnl   [
dnl     AC_DEFINE(HAVE_LIBPQ,1,[Whether you have libpq or not])
dnl   ],[
dnl     AC_MSG_ERROR([wrong libpq version (Need PostgreSQL 7.2.x or later)])
dnl   ],[
dnl     -L$PGSQL_LIBDIR
dnl   ])

  PHP_ADD_INCLUDE($PGSQL_INCLUDE)
  PHP_ADD_LIBRARY_WITH_PATH($LIBNAME, $PGSQL_LIBDIR, SESSION_PGSQL_SHARED_LIBADD)
  
  PHP_SUBST(SESSION_PGSQL_SHARED_LIBADD)

  AC_DEFINE(HAVE_SESSION_PGSQL, 1, [Whether you have pgsql session save handler])
  PHP_NEW_EXTENSION(session_pgsql, session_pgsql.c, $ext_shared)
fi
