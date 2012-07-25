/* 
   +----------------------------------------------------------------------+
   | This source file is subject to LGPL license.                         |
   | Copyright (c) Yasuo Ohgaki                                           |
   +----------------------------------------------------------------------+
   | Authors: yohgaki@php.net                                             |
   +----------------------------------------------------------------------+
 */

#ifndef MOD_PGSQL_H
#define MOD_PGSQL_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_SESSION_PGSQL

#define PHP_SESSION_PGSQL_VERSION "0.2.0-dev"

#include <libpq-fe.h>
#include "ext/session/php_session.h"
#include "main/SAPI.h"

extern ps_module ps_mod_pgsql;
#define ps_pgsql_ptr &ps_mod_pgsql

extern zend_module_entry session_pgsql_module_entry;
#define phpext_session_pgsql_ptr &session_pgsql_module_entry

PS_FUNCS(pgsql);

/* MAX_PGSQL_SERVERS should be prim number for better distribution */
#define MAX_PGSQL_SERVERS 31
#define PS_DEFAULT_PGSQL_FILE "/tmp/php_session_pgsql"

typedef struct _php_session_pgsql_globals {
	/* php.ini vars */
	char *db;
	int create_table;
	int serializable;
	int use_app_vars;
	char *sem_file_name;
	int gc_interval;
	int vacuum_interval;
	int failover_mode;
	int disable;
	int short_circuit;
	int keep_expired;

	/* internal globals */
	PGconn *pgsql_link[MAX_PGSQL_SERVERS];
	PGconn *current_db;
	int current_id;
	char *connstr[MAX_PGSQL_SERVERS]; /* malloc/free should be used */
	char *remote_addr; /* malloc/free should be used */
	int servers; /* better to use prim number. i.e. 2,3,5,7,11... session db servers */
	int sess_new;
	int sess_del;
	int sess_short_circuit;
	char *sess_val;
	int sess_vallen;
	int sess_cnt;
	int sess_error;
	int sess_warning;
	int sess_notice;
	int sess_created;
	int sess_modified;
	int sess_expire;
	char *sess_custom; /* malloc/free should be used */
	char *sess_error_message; /* malloc/free should be used */
	char *sess_addr_created;  /* malloc/free should be used */
	char *sess_addr_modified; /* malloc/free should be used */
	
	int app_modified;
	int app_new;
	zval *app_vars;
} php_session_pgsql_globals; 

/* php function registration */
PHP_FUNCTION(session_pgsql_status);
PHP_FUNCTION(session_pgsql_reset);
PHP_FUNCTION(session_pgsql_info);
PHP_FUNCTION(session_pgsql_set_field);
PHP_FUNCTION(session_pgsql_get_field);
PHP_FUNCTION(session_pgsql_add_error);
PHP_FUNCTION(session_pgsql_get_error);

#ifdef ZTS
extern int session_pgsql_globals_id;
#define PS_PGSQL(v) TSRMG(session_pgsql_globals_id, php_session_pgsql_globals *, v)
#else
extern php_session_pgsql_globals session_pgsql_globalsb;
#define PS_PGSQL(v) (session_pgsql_globals.v)
#endif

extern SAPI_API sapi_module_struct sapi_module;

#else

#define ps_pgsql_ptr NULL
#define phpext_session_pgsql_ptr NULL

#endif

#endif
