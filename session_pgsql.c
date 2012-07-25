/* 
   +----------------------------------------------------------------------+
   | This source file is subject to LGPL license.	                      |
   | Copyright (c) Yasuo Ohgaki                                           |
   +----------------------------------------------------------------------+
   | Authors: Yasuo Ohgaki <yohgaki@php.net>							  |
   +----------------------------------------------------------------------+
 */

/* $Id: session_pgsql.c 326806 2012-07-25 10:17:32Z yohgaki $ */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#define SMART_STR_PREALLOC 512

#include <sys/time.h>
#include <unistd.h>
#include <assert.h>
#include "php.h"
#include "php_ini.h"
#include "php_config.h"
#include "ext/standard/info.h"
#include "ext/standard/php_string.h"
#include "ext/standard/php_var.h"
#include "ext/standard/php_smart_str.h"

#ifdef HAVE_SESSION_PGSQL
#include "mm.h"
#include "php_session_pgsql.h"

#ifndef DEBUG
#undef NDEBUG
#endif

ps_module ps_mod_pgsql = {
  	PS_MOD(pgsql)
};


typedef struct {
	MM *mm;
	time_t *last_gc;
	time_t *last_vacuum;
	pid_t owner;
} ps_pgsql_instance_t;

static ps_pgsql_instance_t *ps_pgsql_instance;


#ifdef ZTS
int session_pgsql_globals_id;
#else
php_session_pgsql_globals session_pgsql_globals;
#endif

static void php_session_pgsql_init_globals(php_session_pgsql_globals *session_pgsql_globals_p TSRMLS_DC);
static int php_ps_pgsql_init_servers(const int force_init TSRMLS_DC);
static int php_ps_pgsql_init_mm(TSRMLS_D);
static int php_ps_pgsql_create_table(const int id TSRMLS_DC);
static PGconn *php_ps_pgsql_connect(const int id TSRMLS_DC);
static PGconn *php_ps_pgsql_get_db(const char *key TSRMLS_DC);

static int ps_pgsql_app_read(TSRMLS_D);
static int ps_pgsql_app_write(TSRMLS_D);
static int ps_pgsql_sess_read(const char *key, char **val, int *vallen TSRMLS_DC);
static int ps_pgsql_sess_write(const char *key, const char *val, const size_t vallen TSRMLS_DC);
static int ps_pgsql_sess_gc(TSRMLS_D);

#define PS_PGSQL_DATA ps_pgsql *data = PS_GET_MOD_DATA()
#define QUERY_BUF_SIZE 256
#define BUF_SIZE 512

#if 0
#define ELOG( x )   php_log_err( x TSRMLS_CC)
#else
#define ELOG( x )
#endif

static PHP_INI_MH(OnUpdate_session_pgsql_db)
{
	int i, cnt=0;
	int len = strlen(new_value);
	char *tmp;

	tmp = new_value;
	for (i = 0; i < len; i++) {
		if (new_value[i] == ';') {
			if (cnt > MAX_PGSQL_SERVERS) {
				php_log_err("session pgsql: Too many session database servers. Some servers are ignored." TSRMLS_CC);
				break;
			}
			PS_PGSQL(connstr)[cnt] = malloc(&new_value[i] - tmp + 1); 
			memcpy(PS_PGSQL(connstr)[cnt], tmp, &new_value[i] - tmp);
			PS_PGSQL(connstr)[cnt][&new_value[i] - tmp] = '\0';
			cnt++;
			tmp = &new_value[++i];
		}
	}
	if (tmp != &new_value[i]) {
		/* should be last server w/o ';' */
		PS_PGSQL(connstr)[cnt] = malloc(&new_value[i] - tmp + 1); 
		memcpy(PS_PGSQL(connstr)[cnt], tmp, &new_value[i] - tmp);
		PS_PGSQL(connstr)[cnt][&new_value[i] - tmp] = '\0';
		cnt++;
	}
  	PS_PGSQL(servers) = cnt;
	PS_PGSQL(db) = new_value;
	return SUCCESS;
}

/* {{{ PHP_INI
 */
PHP_INI_BEGIN()
STD_PHP_INI_ENTRY("session_pgsql.disable",       "0",    PHP_INI_SYSTEM, OnUpdateBool, disable, php_session_pgsql_globals, session_pgsql_globals)
STD_PHP_INI_ENTRY("session_pgsql.db",            "host=localhost dbname=php_session user=nobody", PHP_INI_SYSTEM, OnUpdate_session_pgsql_db, db, php_session_pgsql_globals, session_pgsql_globals)
STD_PHP_INI_ENTRY("session_pgsql.sem_file_name", PS_DEFAULT_PGSQL_FILE, PHP_INI_SYSTEM, OnUpdateString, sem_file_name, php_session_pgsql_globals, session_pgsql_globals)
STD_PHP_INI_ENTRY("session_pgsql.create_table",  "1",    PHP_INI_SYSTEM, OnUpdateBool, create_table, php_session_pgsql_globals, session_pgsql_globals)
STD_PHP_INI_ENTRY("session_pgsql.failover_mode", "0",    PHP_INI_SYSTEM, OnUpdateBool, failover_mode, php_session_pgsql_globals, session_pgsql_globals)
STD_PHP_INI_ENTRY("session_pgsql.short_circuit", "0",    PHP_INI_SYSTEM, OnUpdateBool, short_circuit, php_session_pgsql_globals, session_pgsql_globals)
STD_PHP_INI_ENTRY("session_pgsql.keep_expired",  "0",    PHP_INI_SYSTEM, OnUpdateBool, keep_expired, php_session_pgsql_globals, session_pgsql_globals)
STD_PHP_INI_ENTRY("session_pgsql.use_app_vars",  "0",    PHP_INI_SYSTEM, OnUpdateBool, use_app_vars, php_session_pgsql_globals, session_pgsql_globals)
STD_PHP_INI_ENTRY("session_pgsql.serializable",  "0",    PHP_INI_SYSTEM, OnUpdateBool, serializable, php_session_pgsql_globals, session_pgsql_globals)
STD_PHP_INI_ENTRY("session_pgsql.gc_interval",   "3600", PHP_INI_SYSTEM, OnUpdateLong, gc_interval, php_session_pgsql_globals, session_pgsql_globals)
STD_PHP_INI_ENTRY("session_pgsql.vacuum_interval", "21600", PHP_INI_SYSTEM, OnUpdateLong, vacuum_interval, php_session_pgsql_globals, session_pgsql_globals)
PHP_INI_END()
/* }}} */

PHP_MINIT_FUNCTION(session_pgsql);
PHP_MSHUTDOWN_FUNCTION(session_pgsql);
PHP_RINIT_FUNCTION(session_pgsql);
PHP_RSHUTDOWN_FUNCTION(session_pgsql);
PHP_MINFO_FUNCTION(session_pgsql);

/* {{{ session_pgsql_functions[]
 */
zend_function_entry session_pgsql_functions[] = {
	PHP_FE(session_pgsql_status,	NULL)
	PHP_FE(session_pgsql_reset,		NULL)
	PHP_FE(session_pgsql_info,		NULL)
	PHP_FE(session_pgsql_set_field,		NULL)
	PHP_FE(session_pgsql_get_field,		NULL)
	PHP_FE(session_pgsql_add_error,		NULL)
	PHP_FE(session_pgsql_get_error,		NULL)
	{NULL, NULL, NULL} 
};
/* }}} */

/* {{{ session_pgsql_module_entry
 */
zend_module_entry session_pgsql_module_entry = {
	STANDARD_MODULE_HEADER,
	"session pgsql",
	session_pgsql_functions,
	PHP_MINIT(session_pgsql), PHP_MSHUTDOWN(session_pgsql),
	PHP_RINIT(session_pgsql), PHP_RSHUTDOWN(session_pgsql),
	PHP_MINFO(session_pgsql),
	PHP_SESSION_PGSQL_VERSION, 
	STANDARD_MODULE_PROPERTIES
};
/* }}} */

#ifdef COMPILE_DL_SESSION_PGSQL
ZEND_GET_MODULE(session_pgsql)
#endif

/* {{{ PHP_MINIT_FUNCTION
 */
PHP_MINIT_FUNCTION(session_pgsql)
{
#ifdef ZTS
	php_session_pgsql_globals *session_pgsql_globals;
	ts_allocate_id(&session_pgsql_globals_id, sizeof(php_session_pgsql_globals),
				   (ts_allocate_ctor) php_session_pgsql_init_globals, NULL);
	session_pgsql_globals = ts_resource(session_pgsql_globals_id);
#else
	php_session_pgsql_init_globals(&session_pgsql_globals TSRMLS_CC);
#endif

	ELOG("MINIT Called");

	REGISTER_INI_ENTRIES();

	/* if sapi is bianry sapi(CGI/CLI) disable session pgsql.
	   session pgsql rely on shared memory to work. it's problematic
	   using session pgsql with PHP bianry */
	if (PS_PGSQL(disable) || !strcmp(sapi_module.name, "cli")
		|| !strcmp(sapi_module.name, "cgi") || !strcmp(sapi_module.name, "cgi-fcgi")) {
		if (!PS_PGSQL(disable) && strcmp(sapi_module.name, "cli")) {
			php_log_err("session pgsql: Disabled. It will not work with CLI or CGI and. Set session_pgsql.disable in php.ini to remove this error message." TSRMLS_CC);
		}
		PS_PGSQL(disable) = 1;
		return SUCCESS; /* Don't spit annoying error messages */
	}
	/* init mm */
	if (php_ps_pgsql_init_mm(TSRMLS_C) == FAILURE) {
		return FAILURE;
	}
	/* init $_APP hash */
	if (PS_PGSQL(use_app_vars)) {
		zend_register_auto_global("_APP", sizeof("_APP")-1, 0, NULL TSRMLS_CC);
	}
	
	/* register pgsql session save handler */
	php_session_register_module(&ps_mod_pgsql);

	return SUCCESS;
}
/* }}} */

/* {{{ PHP_MSHUTDOEN_FUNCTION
 */
PHP_MSHUTDOWN_FUNCTION(session_pgsql)
{
	int i;
	
	ELOG("MSHUTDOWN Called");

	if (PS_PGSQL(disable)) {
		return SUCCESS;
	}
	
	/* cleanup globals for users loading extension...
	   selectively loading session_pgsql does not make sense, though. */
	if (PS_PGSQL(sess_custom)) {
		free(PS_PGSQL(sess_custom));
	}
	if (PS_PGSQL(sess_error_message)) {
		free(PS_PGSQL(sess_error_message));
	}
	if (PS_PGSQL(sess_addr_created)) {
		free(PS_PGSQL(sess_addr_created));
	}
	if (PS_PGSQL(sess_addr_modified)) {
		free(PS_PGSQL(sess_addr_modified));
	}
	if (PS_PGSQL(remote_addr)) {
		free(PS_PGSQL(remote_addr));
	}
	/* link is closed at shutdown
	   These values will be initilized */
	for (i = 0; i < PS_PGSQL(servers); i++) {
		if (PS_PGSQL(pgsql_link)[i]) {
			PQfinish(PS_PGSQL(pgsql_link)[i]);
		}
		if (PS_PGSQL(connstr)[i]) {
 			free(PS_PGSQL(connstr)[i]);
		}
	}
	/* clean up mm */
	if (ps_pgsql_instance->owner == getpid() && ps_pgsql_instance->mm) {
		if (ps_pgsql_instance->last_gc) {
			mm_free(ps_pgsql_instance->mm, ps_pgsql_instance->last_gc);
		}
		if (ps_pgsql_instance->last_vacuum) {
			mm_free(ps_pgsql_instance->mm, ps_pgsql_instance->last_vacuum);
		}
		mm_destroy(ps_pgsql_instance->mm);
		free(ps_pgsql_instance);
	}
	return SUCCESS;
}
/* }}} */


/* {{{ PHP_RSHUTDOEN_FUNCTION
 */
PHP_RINIT_FUNCTION(session_pgsql)
{
	zval *remote_addr, *tmp;

	ELOG("RINIT Called");

	if (PS_PGSQL(disable)) {
		return SUCCESS;
	}
	
	/* initilize postgresql server connections */
	if (php_ps_pgsql_init_servers(0 TSRMLS_CC) == FAILURE) {
		/* No servers are available */
		php_log_err("session pgsql: Cannot connect to any PostgreSQL server. Check session_pgsql.db" TSRMLS_CC);
		return FAILURE; 
	}

	/* These clean up cannot be done at rshutdown, since it executed
	   before session write. */
	if (PS_PGSQL(sess_custom)) {
		free(PS_PGSQL(sess_custom));
		PS_PGSQL(sess_custom) = NULL;
	}
	if (PS_PGSQL(sess_error_message)) {
		free(PS_PGSQL(sess_error_message));
		PS_PGSQL(sess_error_message) = NULL;
	}
	if (PS_PGSQL(sess_addr_created)) {
		free(PS_PGSQL(sess_addr_created));
		PS_PGSQL(sess_addr_created) = NULL;
	}
	if (PS_PGSQL(sess_addr_modified)) {
		free(PS_PGSQL(sess_addr_modified));
		PS_PGSQL(sess_addr_modified) = NULL;
	}
	if (PS_PGSQL(remote_addr)) {
		free(PS_PGSQL(remote_addr));
	}
	if (zend_hash_find(&EG(symbol_table), "_SERVER", sizeof("_SERVER") , (void **) &tmp) == SUCCESS
		&& zend_hash_find(Z_ARRVAL_P(tmp), "REMOTE_ADDR", sizeof("REMOTE_ADDR"), (void **) &remote_addr) == SUCCESS) {
		PS_PGSQL(remote_addr) = strdup(Z_STRVAL_P(remote_addr));
	} else {
		PS_PGSQL(remote_addr) = strdup("");
	}
	PS_PGSQL(current_db) = NULL;
	return SUCCESS;
}
/* }}} */


/* {{{ PHP_RSHUTDOEN_FUNCTION
 */
PHP_RSHUTDOWN_FUNCTION(session_pgsql)
{
	ELOG("RSHUTDOWN Called");
	/* NOTE: RSHUTDOWN is called *before* writing/closing session... */
/* 	if (PS_PGSQL(disable)) { */
/* 		return SUCCESS; */
/* 	} */
	return SUCCESS;
}
/* }}} */

/* {{{ PHP_MINFO_FUNCTION
 */
PHP_MINFO_FUNCTION(session_pgsql)
{
	php_info_print_table_start();
	php_info_print_table_header(2, "PostgreSQL Session Save Handler Support", "enabled");
	php_info_print_table_row(2, "Version", PHP_SESSION_PGSQL_VERSION);
	php_info_print_table_end();

	DISPLAY_INI_ENTRIES();
}
/* }}} */

/* {{{ php_session_pgsql_init_globals
 */
static void php_session_pgsql_init_globals(php_session_pgsql_globals *session_pgsql_globals_p TSRMLS_DC) 
{
	int i;
	for (i = 0; i < MAX_PGSQL_SERVERS; i++) {
		PS_PGSQL(pgsql_link)[i] = NULL;
		PS_PGSQL(connstr)[i] = NULL;
	}
	PS_PGSQL(sess_custom) = NULL;
	PS_PGSQL(sess_error_message) = NULL;
	PS_PGSQL(sess_addr_created)  = NULL;
	PS_PGSQL(sess_addr_modified) = NULL;
	PS_PGSQL(remote_addr) = NULL;
	PS_PGSQL(sess_val) = NULL;
}
/* }}} */

/* {{{ php_ps_pgsql_init_mm
 */
static int php_ps_pgsql_init_mm(TSRMLS_D)
{
	smart_str buf={0};

	ps_pgsql_instance = calloc(sizeof(*ps_pgsql_instance), 1);
   	if (!ps_pgsql_instance) {
		return FAILURE;
	}
	
	/* create shared memory file using sapi_name */
	if (PS_PGSQL(sem_file_name) && PS_PGSQL(sem_file_name)[0]) {
		smart_str_appends(&buf,PS_PGSQL(sem_file_name));
	}
	else {
		smart_str_appends(&buf, PS_DEFAULT_PGSQL_FILE);
	}
	smart_str_appends(&buf,sapi_module.name);
	smart_str_append_long(&buf,getpid());
	smart_str_0(&buf);
	ps_pgsql_instance->mm = mm_create(0, buf.c);
	smart_str_free(&buf);
	if (!ps_pgsql_instance->mm) {
		mm_destroy(ps_pgsql_instance->mm);
		free(ps_pgsql_instance);
		php_log_err("session pgsql: MM failure" TSRMLS_CC);		
		return FAILURE;
	}
	ps_pgsql_instance->last_gc = mm_calloc(ps_pgsql_instance->mm, 1, sizeof(time_t));
	if (!ps_pgsql_instance->mm) {
		mm_destroy(ps_pgsql_instance->mm);
		free(ps_pgsql_instance);
		php_log_err("session pgsql: MM failure" TSRMLS_CC);		
		return FAILURE;
	}
	ps_pgsql_instance->last_vacuum = mm_calloc(ps_pgsql_instance->mm, 1, sizeof(time_t));
	ps_pgsql_instance->owner = getpid();
	*(ps_pgsql_instance->last_gc) = time(NULL) + PS_PGSQL(gc_interval);
	*(ps_pgsql_instance->last_vacuum) = time(NULL) + PS_PGSQL(vacuum_interval);

	return SUCCESS;
}
/* }}} */

/* {{{ php_ps_pgsql_init_servers
 */
static int php_ps_pgsql_init_servers(const int force_init TSRMLS_DC) 
{
	int id;
	static int initialized = 0;

	if (!force_init && initialized) {
		return SUCCESS;
	}
	
	initialized = 1;
	for (id = 0; id < PS_PGSQL(servers); id++) {
		assert(PS_PGSQL(connstr)[id]);
		/* if link is bad, NULL is returned */
		if (PS_PGSQL(pgsql_link)[id]) {
			PQreset(PS_PGSQL(pgsql_link)[id]);
		}
		else {
			PS_PGSQL(pgsql_link)[id] = PQconnectdb(PS_PGSQL(connstr)[id]);
		}
		if (PQstatus(PS_PGSQL(pgsql_link)[id]) == CONNECTION_OK
			&& PS_PGSQL(pgsql_link)[id] && PS_PGSQL(create_table)) {
			/* if there is problem, link is set to NULL */
			if (php_ps_pgsql_create_table(id TSRMLS_CC) == FAILURE) {
				php_error(E_NOTICE, "session pgsql: Cannot create tables (%s)", PS_PGSQL(connstr)[id]);
			}
		}
	}
	for (id = 0; id < PS_PGSQL(servers); id++) {
		if (PS_PGSQL(pgsql_link)[id]) {
			/* there is at least one server that is usable */
			return SUCCESS;
		}
	}
	return FAILURE;
}
/* }}} */

/* {{{ php_pg_pgsql_create_table
 */
static int php_ps_pgsql_create_table(const int id TSRMLS_DC) 
{
	PGresult *pg_result;
	char *query_create_sess_table =
	"CREATE TABLE php_session ( "
	"sess_id            text, "
	"sess_name          text, "
	"sess_data          text, "
	"sess_created       integer, "
	"sess_modified      integer, "
	"sess_expire        integer, "
	"sess_addr_created  text, "
	"sess_addr_modified text, "
	"sess_counter       integer, "
	"sess_error         integer, "
	"sess_warning       integer, "
	"sess_notice        integer, "
	"sess_err_message   text, "
	"sess_custom        text); ";

	char *query_create_app_vars_table =
	"CREATE TABLE php_app_vars ( "
	"app_modified       integer, "
	"app_name           text, "
	"app_vars           text);";

	int num;

	assert(PS_PGSQL(pgsql_link)[id] != NULL);
	pg_result = PQexec(PS_PGSQL(pgsql_link)[id],
					   "SELECT relname FROM pg_class WHERE relname = 'php_session';");
	if (!pg_result) {
		goto cleanup;
	}
	num = PQntuples(pg_result);
	PQclear(pg_result);
	if (!num) {
		/* No session table */
		pg_result = PQexec(PS_PGSQL(pgsql_link)[id], query_create_sess_table);
		if (PQresultStatus(pg_result) != PGRES_COMMAND_OK) {
			goto cleanup;
		}
		PQclear(pg_result);
		pg_result = PQexec(PS_PGSQL(pgsql_link)[id],
						   "CREATE INDEX php_session_idx ON php_session USING BTREE (sess_id);");
		PQclear(pg_result);
	}

	pg_result = PQexec(PS_PGSQL(pgsql_link)[id],
					   "SELECT relname FROM pg_class WHERE relname = 'php_app_vars';");
	if (!pg_result) {
		goto cleanup;
	}
	num = PQntuples(pg_result);
	PQclear(pg_result);
	if (!num) {
		pg_result = PQexec(PS_PGSQL(pgsql_link)[id], query_create_app_vars_table);
		if (PQresultStatus(pg_result) != PGRES_COMMAND_OK) {
			goto cleanup;
		}
		PQclear(pg_result);
	}
	return SUCCESS;

cleanup:
	if (pg_result)
		PQclear(pg_result);
	PQfinish(PS_PGSQL(pgsql_link)[id]);
	PS_PGSQL(pgsql_link)[id] = NULL;
	return FAILURE;
}
/* }}} */

/* {{{ php_ps_pgsql_connect
 */
static PGconn *php_ps_pgsql_connect(const int id TSRMLS_DC)
{
	if (!PS_PGSQL(connstr)[id]) {
		/* bailout while debugging. PS_PGSQL(connstr)[id] can be null when
		   session_pgsql is compiled in and user tried to load session_pgsql
		   as a external module */
		assert(PS_PGSQL(connstr)[id] != NULL);
		return NULL;
	}
	if ((PQstatus(PS_PGSQL(pgsql_link)[id])) == CONNECTION_BAD) {
		PQreset(PS_PGSQL(pgsql_link)[id]); /* reset connection. database server may be rebooted */
		if (PQstatus(PS_PGSQL(pgsql_link)[id]) == CONNECTION_BAD) {
			/* seems it's really dead */
			PQfinish(PS_PGSQL(pgsql_link)[id]);
			PS_PGSQL(pgsql_link)[id] = NULL;
			php_error(E_WARNING, "session pgsql: PostgreSQL server connection is broken or bad connection string (%s)", PS_PGSQL(connstr)[id]);
			return NULL;
		}
	}
	return PS_PGSQL(pgsql_link)[id];
}
/* }}} */

/* {{{ php_ps_pgsql_get_db
 */
static PGconn *php_ps_pgsql_get_db(const char *key TSRMLS_DC) 
{
	PGconn *db = NULL;
	div_t tmp;
	int i, sum = 0, id = 0;
	size_t len;
	
	if (PS_PGSQL(servers) == 1) {
		db = php_ps_pgsql_connect(0 TSRMLS_CC);
		PS_PGSQL(current_id) = 0;
		return db;
	}
	/* take care load balance and failover */
	/* don't distribute session if failover_mode is enabled */
	if (!PS_PGSQL(failover_mode)) {
		len = strlen(key);
		for(i = 0; i < len; i++)	{
			sum += (int)key[i];
		}
		tmp = div(sum, PS_PGSQL(servers));
		id = tmp.rem;
		db = php_ps_pgsql_connect(id TSRMLS_CC);
		PS_PGSQL(current_id) = id;
	}
	if (!db) {
		/* if something wrong. use next server that is usable */
		int start_id = PS_PGSQL(current_id);
		PS_PGSQL(current_id) = -1;
		if (start_id+1 <= PS_PGSQL(servers)) {
			for (id = start_id+1; id < PS_PGSQL(servers) && PS_PGSQL(pgsql_link)[id]; id++) {
				/* if link is bad, NULL is returned */
				db = php_ps_pgsql_connect(id TSRMLS_CC);
				if (db) {
					PS_PGSQL(current_id) = id;
					break;
				}
			}
		}
		for (id = 0; id < start_id && PS_PGSQL(pgsql_link)[id]; id++) {
			/* if link is bad, NULL is returned */
			db = php_ps_pgsql_connect(id TSRMLS_CC);
			if (db) {
				PS_PGSQL(current_id) = id;
				break;
			}
		}
	}
	return db;
}
/* }}} */

/* {{{ ps_pgsql_valid_str
 */
static int ps_pgsql_valid_str(const char *key TSRMLS_DC)
{
	size_t len;
	const char *p;
	char c;
	int ret = 1;

	for (p = key; (c = *p); p++) {
		/* valid characters are a..z, A..Z, 0..9, _-, */
		if (!((c >= 'a' && c <= 'z') ||
			  (c >= 'A' && c <= 'Z') ||
			  (c >= '0' && c <= '9') ||
			  (c == '_' || c == '-' || c == ','))) {
			ret = 0;
			break;
		}
	}
	len = p - key;
	if (len < 16 || len > 1024) {
		ret = 0;
	}
	return ret;
}
/* }}} */

/* {{{ ps_pgsql_app_read
 */
static int ps_pgsql_app_read(TSRMLS_D) 
{
	int ret = SUCCESS;

	if (PS_PGSQL(use_app_vars)) {
		PGconn *pg_link = PS_PGSQL(current_db);
		PGresult *pg_result;
		char query[QUERY_BUF_SIZE+1];
		char *escaped_session_name;
		size_t len, session_name_len;
		
		len = strlen(PS(session_name));
		escaped_session_name = emalloc(len*2 + 1);
		session_name_len = PQescapeStringConn(PS_PGSQL(current_db), escaped_session_name, PS(session_name), len, NULL);
		snprintf(query, QUERY_BUF_SIZE, "SELECT app_vars FROM php_app_vars WHERE app_name = '%s';", escaped_session_name);
		efree(escaped_session_name);
		pg_result = PQexec(pg_link, query);
		MAKE_STD_ZVAL(PS_PGSQL(app_vars));
		if (PQresultStatus(pg_result) == PGRES_TUPLES_OK) {
			if (PQntuples(pg_result) == 0) {
				/* insert data when writing */
				PS_PGSQL(app_new) = 1;
				array_init(PS_PGSQL(app_vars));
				ZEND_SET_GLOBAL_VAR_WITH_LENGTH("_APP", sizeof("_APP"), PS_PGSQL(app_vars), 1, 0);
			}
			else {
				php_unserialize_data_t var_hash;
				char *data;
				/* update data when writing */
				PS_PGSQL(app_new) = 0;
				data = PQgetvalue(pg_result, 0, 0);
				
				PHP_VAR_UNSERIALIZE_INIT(var_hash);
				php_var_unserialize(&PS_PGSQL(app_vars), (const unsigned char **)&data, data + strlen(data), &var_hash TSRMLS_CC); 
				PHP_VAR_UNSERIALIZE_DESTROY(var_hash);
				ZEND_SET_GLOBAL_VAR_WITH_LENGTH("_APP", sizeof("_APP"), PS_PGSQL(app_vars), 1, 0);
			}
		}
		else {
			php_error(E_WARNING,"Session pgsql READ(applicatoin vars) failed: %s (%s)",
					  PQresultErrorMessage(pg_result), query);
			ret = FAILURE;
		}
		PQclear(pg_result);
	}
	return ret;
}
/* }}} */

/* {{{ ps_pgsql_app_write
 */
static int ps_pgsql_app_write(TSRMLS_D)
{
	PGconn *pg_link = PS_PGSQL(current_db);
	PGresult *pg_result;
	char *query_insert = "INSERT INTO php_app_vars (app_modified, app_name, app_vars) VALUES (%d, '%s', '%s');";
	char *query_update = "UPDATE php_app_vars SET app_modified = %d, app_vars = '%s'";
	char *query = NULL;
	unsigned char *escaped_data;
	size_t escaped_data_len = 0, query_len;
	php_serialize_data_t var_hash;
	smart_str buf = {0};

	PHP_VAR_SERIALIZE_INIT(var_hash);
	php_var_serialize(&buf, &(PS_PGSQL(app_vars)), &var_hash TSRMLS_CC);
	PHP_VAR_SERIALIZE_DESTROY(var_hash);

	assert(buf.c && buf.len);
	escaped_data = (char *)emalloc(buf.len*2+1);
	escaped_data_len = PQescapeStringConn(PS_PGSQL(current_db), escaped_data, buf.c, buf.len, NULL);
	if (PS_PGSQL(app_new)) {
		/* INSERT */
		query_len = strlen(query_insert) + strlen(PS(session_name)) + escaped_data_len + 16;
		query = emalloc(query_len + 1);
		snprintf(query, query_len, query_insert, time(NULL), PS(session_name), escaped_data);
		pg_result = PQexec(pg_link, query);
		if (PQresultStatus(pg_result) != PGRES_COMMAND_OK) {
			php_error(E_WARNING, "Session pgsql $_APP write(insert) failed. (%s)", PQerrorMessage(pg_link) TSRMLS_CC);
		}
	}
	else {
		/* UPDATE */
		query_len = strlen(query_insert) + escaped_data_len + 16;
		query = emalloc(query_len + 1);
		snprintf(query, query_len, query_update, time(NULL), escaped_data);
		pg_result = PQexec(pg_link, query);
		if (PQresultStatus(pg_result) != PGRES_COMMAND_OK) {
			php_error(E_WARNING, "Session pgsql $_APP write(update) failed. (%s) ", PQerrorMessage(pg_link) TSRMLS_CC);
		}
	}
	PQclear(pg_result);
	efree(query);
	efree(escaped_data);

	return SUCCESS;
}
/* }}} */

/* {{{ ps_pgsql_sess_read
 */
static int ps_pgsql_sess_read(const char *key, char **val, int *vallen TSRMLS_DC) 
{
	PGresult *pg_result;
/* 	ExecStatusType pg_status; */
	char query[QUERY_BUF_SIZE+1];
	char *query_tpl = "SELECT sess_expire, sess_counter, sess_error, sess_warning, sess_notice, sess_data, sess_custom, sess_created, sess_modified, sess_addr_created, sess_addr_modified FROM php_session WHERE sess_id = '%s';";
	int ret = FAILURE;

	/* start reading */
	if (PS_PGSQL(serializable)) {
		pg_result = PQexec(PS_PGSQL(current_db), "BEGIN; SET TRANSACTION ISOLATION LEVEL SERIALIZABLE;");
	}
	else {
		pg_result = PQexec(PS_PGSQL(current_db), "BEGIN;");
	}
	PQclear(pg_result);
	if (PQresultStatus(pg_result) != PGRES_COMMAND_OK) {
		/* try again. server may be rebooted */
		PQreset(PS_PGSQL(current_db));
		if (PS_PGSQL(serializable)) {
			pg_result = PQexec(PS_PGSQL(current_db), "BEGIN; SET TRANSACTION ISOLATION LEVEL SERIALIZABLE;");
		}
		else {
			pg_result = PQexec(PS_PGSQL(current_db), "BEGIN;");
		}
		if (PQresultStatus(pg_result) != PGRES_COMMAND_OK) {
			php_error(E_WARNING, "session pgsql: Cannot start transaction. (%s)", PQresultErrorMessage(pg_result));
			PQclear(pg_result);
			return FAILURE;
		}
		PQclear(pg_result);
	}


	PS_PGSQL(sess_new) = 0;
	PS_PGSQL(sess_del) = 0;
	*vallen = 0;
	if (ps_pgsql_valid_str(key TSRMLS_CC)) {
		snprintf(query, QUERY_BUF_SIZE, query_tpl, key);
		pg_result = PQexec(PS_PGSQL(current_db), query);
		if (PQresultStatus(pg_result) == PGRES_TUPLES_OK) {
			if (PQntuples(pg_result) == 0) {
				/* new session */
				PS_PGSQL(sess_new) = 1;
			}
			else {
				/* session data exists */
				char *expire;
				time_t exp, now = time(NULL);
					
				expire = PQgetvalue(pg_result, 0, 0);
				exp = (time_t)atoi(expire);
				if ((exp < now) && !PS_PGSQL(keep_expired)) {
					/* session is expired. delete and create record. */
					PS_PGSQL(sess_del) = 1;
				}
				else {
					char *tmp;
					PS_PGSQL(sess_expire) = (int)atoi(PQgetvalue(pg_result, 0, 0));
					/* update counter */
					PS_PGSQL(sess_cnt) = (int)atoi(PQgetvalue(pg_result, 0, 1));
					PS_PGSQL(sess_cnt)++;
					/* set error/wanirng/notice cournters */
					PS_PGSQL(sess_error)   = (int)atoi(PQgetvalue(pg_result, 0, 2));
					PS_PGSQL(sess_warning) = (int)atoi(PQgetvalue(pg_result, 0, 3));
					PS_PGSQL(sess_notice)  = (int)atoi(PQgetvalue(pg_result, 0, 4));
					if (exp < now) {
						*vallen = 0;
						*val = estrdup("");
						PS_PGSQL(short_circuit) = 0; /* disable short circuit */
					}
					else {
						/* session data - PQgetvalue reuturns "" for NULL */
						tmp = PQgetvalue(pg_result, 0, 5);
						*vallen = strlen(tmp);
						*val = estrndup(tmp, *vallen);
					}
					/* custom field */
					tmp = PQgetvalue(pg_result, 0, 6);
					PS_PGSQL(sess_custom) = strdup(tmp);
					/* other */
					PS_PGSQL(sess_created)  = (int)atoi(PQgetvalue(pg_result, 0, 7));
					PS_PGSQL(sess_modified) = (int)atoi(PQgetvalue(pg_result, 0, 8));
					PS_PGSQL(sess_addr_created)  = strdup(PQgetvalue(pg_result, 0, 9));
					PS_PGSQL(sess_addr_modified) = strdup(PQgetvalue(pg_result, 0, 10));
				}
			}
			ret = SUCCESS;
		}
		else {
			/* something wrong, but try to delete and insert data anyway */
			PS_PGSQL(sess_del) = 1;
			ret = SUCCESS;
		}
		PQclear(pg_result);	
	}
	else {
		PS_PGSQL(sess_new) = 1;
		php_error(E_NOTICE,"session pgsql: Invalid Session ID detected");
	}
	if (*vallen == 0) {
		*val = estrndup("", 0);
	}
	/* save values for short circuit */
	if (PS_PGSQL(sess_new) || PS_PGSQL(sess_del)) {
		PS_PGSQL(sess_vallen) = 0;
		PS_PGSQL(sess_val) = estrndup("", 0);
	}
	else {
		PS_PGSQL(sess_vallen) = *vallen;
		PS_PGSQL(sess_val) = estrndup(*val, *vallen);
	}

	return ret;
}
/* }}} */

/* {{{ ps_pgsql_sess_write
 */
static int ps_pgsql_sess_write(const char *key, const char *val, const size_t vallen TSRMLS_DC) 
{
	PGresult *pg_result;
	size_t query_len;
	time_t now, exp;
	char *query;
	char *query_delete =
	   "DELETE FROM php_session WHERE sess_id = '%s';";
	char *query_insert =
	   "INSERT INTO php_session (sess_id, sess_name, sess_created, sess_addr_created, sess_modified, sess_expire, sess_data, sess_counter, sess_error, sess_warning, sess_notice, sess_custom) "
	   "VALUES ('%s', '%s', %d, '%s', %d, %d, '%s', 1, 0, 0, 0 %s);";
	char *query_update =
	   "UPDATE php_session SET sess_data = '%s', sess_modified = %d, sess_addr_modified = '%s', sess_expire = %d , sess_counter = %d, sess_error = %d, sess_warning = %d , sess_notice = %d %s"
	   "WHERE sess_id = '%s';";
	char *escaped_val, *escaped_custom;
	smart_str buf= {0};
	size_t custom_len, key_len;

	if (!ps_pgsql_valid_str(key TSRMLS_CC)) {
		return FAILURE;
	}
	
	key_len = strlen(key);
	if (PS_PGSQL(sess_del) && !PS_PGSQL(keep_expired)) {
		query_len = strlen(query_delete) + key_len;
		query = emalloc(query_len+1);
		snprintf(query, query_len, query_delete, key);
		pg_result = PQexec(PS_PGSQL(current_db), query);
		PQclear(pg_result);
		efree(query);
		PS_PGSQL(sess_new) = 1;
	}

	now = time(NULL);
	exp = now + PS(gc_maxlifetime);
	query_len = key_len;
	escaped_val = (char *)emalloc(vallen*2+1);
	query_len += PQescapeStringConn(PS_PGSQL(current_db), escaped_val, val, vallen, NULL);
	query_len += strlen(PS_PGSQL(remote_addr));
	if (PS_PGSQL(sess_new)) {
		char *escaped_sess_name;
		size_t name_len;
		/* INSERT */
		query_len += strlen(query_insert);
		if (PS_PGSQL(sess_custom) && PS_PGSQL(sess_custom)[0]) {
			smart_str_appendl(&buf, ", '", 3);
			custom_len = strlen(PS_PGSQL(sess_custom));
			escaped_custom = (char *)emalloc(custom_len*2+1);
			custom_len = PQescapeStringConn(PS_PGSQL(current_db), escaped_custom, PS_PGSQL(sess_custom), custom_len, NULL);
			smart_str_appendl(&buf, escaped_custom, custom_len);
			smart_str_appends(&buf, "' ");
			smart_str_0(&buf);
			efree(escaped_custom);
		}
		else {
			smart_str_appends(&buf, ", ''");
			smart_str_0(&buf);
		}
		query_len += buf.len;
		name_len = strlen(PS(session_name));
		escaped_sess_name = (char *)emalloc(name_len*2+1);
		query_len += PQescapeStringConn(PS_PGSQL(current_db), escaped_sess_name, PS(session_name), name_len, NULL);
		query_len += 32*3; /* 32 bytes for an int should be enough */ 
		query = emalloc(query_len+1);
		snprintf(query, query_len, query_insert,
				 key, escaped_sess_name, now, PS_PGSQL(remote_addr), now, exp, escaped_val, buf.c);
		pg_result = PQexec(PS_PGSQL(current_db), query);
		PQclear(pg_result);
		smart_str_free(&buf);
		efree(escaped_sess_name);
		efree(query);
	}
	else if (!PS_PGSQL(sess_short_circuit) || vallen != PS_PGSQL(sess_vallen) || strncmp(val, PS_PGSQL(sess_val), PS_PGSQL(sess_vallen))) {
		/* UPDATE - skip updating if possible */
		query_len += strlen(query_update);
		if (PS_PGSQL(sess_custom) && PS_PGSQL(sess_custom)[0]) {
			smart_str_appends(&buf, ", sess_custom = '");
			custom_len = strlen(PS_PGSQL(sess_custom));
			escaped_custom = (char *)emalloc(custom_len*2+1);
			custom_len = PQescapeStringConn(PS_PGSQL(current_db), escaped_custom, PS_PGSQL(sess_custom), custom_len, NULL);
			smart_str_appendl(&buf, escaped_custom, custom_len);
			smart_str_appends(&buf, "' ");
			smart_str_0(&buf);
			efree(escaped_custom);
		}
		else {
			smart_str_appends(&buf, "");
			smart_str_0(&buf);
		}
		query_len += buf.len;
		query_len += 32*6;  /* 32 bytes for an int should be enough */ 
		query = emalloc(query_len+1);
		snprintf(query, query_len, query_update,
				 escaped_val, now, PS_PGSQL(remote_addr), exp, PS_PGSQL(sess_cnt),
				 PS_PGSQL(sess_error), PS_PGSQL(sess_warning), PS_PGSQL(sess_notice), buf.c, key);
		pg_result = PQexec(PS_PGSQL(current_db), query);
		PQclear(pg_result);
		smart_str_free(&buf);
		efree(query);
	}

	/* save error message is any */
	if (PS_PGSQL(sess_error_message)) {
		char *escaped_error_message;
		size_t len, error_message_len;
		smart_str buf = {0};

		len = strlen(PS_PGSQL(sess_error_message));
		escaped_error_message = (char *)emalloc(len*2+1);
		error_message_len = PQescapeStringConn(PS_PGSQL(current_db), escaped_error_message, PS_PGSQL(sess_error_message), len, NULL);
		smart_str_appends(&buf, "UPDATE php_session SET sess_err_message = '");
		smart_str_appendl(&buf, escaped_error_message, error_message_len);
		smart_str_appends(&buf, "' WHERE sess_id='");
		smart_str_appends(&buf, key);
		smart_str_appendl(&buf, "';", 2);
		smart_str_0(&buf);
		
		pg_result = PQexec(PS_PGSQL(current_db), buf.c);

		PQclear(pg_result);
		smart_str_free(&buf);
		efree(escaped_error_message);
	}
	efree(escaped_val);
	
	pg_result = PQexec(PS_PGSQL(current_db), "END;");
	if (PQresultStatus(pg_result) != PGRES_COMMAND_OK) {
		PQclear(pg_result);
		return FAILURE;
	}
	PQclear(pg_result);
	
	return SUCCESS;	
}
/* }}} */

/* {{{ pg_pgsql_sess_gc
 */
static int ps_pgsql_sess_gc(TSRMLS_D)
{
	PGresult *pg_result;
	char query[QUERY_BUF_SIZE+1];
	char *query_gc = "DELETE FROM php_session WHERE sess_expire < %d;";
	char *query_vacuum = "VACUUM ANALYZE php_session; VACUUM ANALYZE php_app_vars; REINDEX TABLE php_session;";
	int id;
	time_t now = time(NULL);

	ELOG("GC Called");
	/* Send query at once */
	sprintf(query, query_gc, now);
	if (*(ps_pgsql_instance->last_gc) &&
		*(ps_pgsql_instance->last_gc) < now - PS_PGSQL(gc_interval)) {
		*(ps_pgsql_instance->last_gc) = now;
		for (id = 0; id < PS_PGSQL(servers); id++) {
			if (PS_PGSQL(pgsql_link)[id]) {
				PQsendQuery(PS_PGSQL(pgsql_link)[id], query);
			}
		}
	}
	if (*(ps_pgsql_instance->last_vacuum) &&
		*(ps_pgsql_instance->last_vacuum) < now - PS_PGSQL(vacuum_interval)) {
		*(ps_pgsql_instance->last_vacuum) = now;
		for (id = 0; id < PS_PGSQL(servers); id++) {
			if (PS_PGSQL(pgsql_link)[id]) {
				PQsendQuery(PS_PGSQL(pgsql_link)[id], query_vacuum);
			}
		}
	}
	/* Get result and clear */
	for (id = 0; id < PS_PGSQL(servers); id++) {
		if (PS_PGSQL(pgsql_link)[id]) {
			while ((pg_result = PQgetResult(PS_PGSQL(pgsql_link)[id])))
				PQclear(pg_result);
		}
	}
	return SUCCESS;
}
/* }}} */


/*********** session save handler functions ************/
/* {{{ PS_OPEN_FUNC
 */
PS_OPEN_FUNC(pgsql)
{
	ELOG("OPEN CALLED");
	/* mod_data cannot be NULL to make session save handler module work */
	*mod_data = (void *)1; 
	/* short circuit option */
	if (PS_PGSQL(short_circuit)) {
		PS_PGSQL(sess_short_circuit) = 1;
	}
	else {
		PS_PGSQL(sess_short_circuit) = 0;
	}
	return SUCCESS;
}
/* }}} */


/* {{{ PS_CLOSE_FUNC
 */
PS_CLOSE_FUNC(pgsql)
{
	ELOG("CLOSE Called");
	*mod_data = (void *)0; /* mod_data should be set to NULL to avoid additional close call */

	if (PS_PGSQL(sess_val)) {
		efree(PS_PGSQL(sess_val));
	}
	PS_PGSQL(sess_vallen) = 0;
	PS_PGSQL(sess_val) = NULL;
	/* GC is done here for better response when GC is performed */
	ps_pgsql_sess_gc(TSRMLS_C);
	return SUCCESS;
}
/* }}} */


/* {{{ PS_READ_FUNC
 */
PS_READ_FUNC(pgsql)
{
	int ret;
	ELOG("READ Called");
	PS_PGSQL(current_db) = php_ps_pgsql_get_db(key TSRMLS_CC);
	if (PS_PGSQL(current_db) == NULL) {
		return FAILURE;
	}
	ret = ps_pgsql_sess_read(key, val, vallen TSRMLS_CC);
	if (ret != FAILURE && PS_PGSQL(use_app_vars)) {
		/* Init app vars */
		ret = ps_pgsql_app_read(TSRMLS_C);
	}
  	return ret;
}
/* }}} */

/* {{{ PS_WRITE_FUNC
 */
PS_WRITE_FUNC(pgsql)
{
	int ret;
	ELOG("WRITE Called");
	if (!PS_PGSQL(current_db)) {
		return FAILURE;
	}
	ret = ps_pgsql_sess_write(key, val, vallen TSRMLS_CC);
	if (ret != FAILURE && PS_PGSQL(use_app_vars)) {
		ret = ps_pgsql_app_write(TSRMLS_C);
	}
	return ret;
}
/* }}} */

/* {{{ PS_DESTROY_FUNC
 */
PS_DESTROY_FUNC(pgsql)
{
	PGresult *pg_result;
	size_t query_len;
	char *query;
	/* session module calls PS(mod)->close, request shutdown then request init function.
	   Transaction should be ended here. (session_pgsql don't use session read/write for
	   better performance */
	char *query_update = "DELETE FROM php_session WHERE sess_id = '%s';END;";
	int ret = FAILURE;

	ELOG("DESTROY Called");
	
	if (!PS_PGSQL(current_db)) {
		return ret;
	}
	if (ps_pgsql_valid_str(key TSRMLS_CC)) {
		query_len = strlen(query_update)+strlen(key);
		query = (char *)emalloc(query_len+1);
		snprintf(query, query_len, query_update, key);
		pg_result = PQexec(PS_PGSQL(current_db), query);
		if (PQresultStatus(pg_result) == PGRES_COMMAND_OK) {
			ret = SUCCESS;
		}
		PQclear(pg_result);
		efree(query);
	}
	
	return ret;
}
/* }}} */

/* {{{ PS_GC_FUNC
 */
PS_GC_FUNC(pgsql)
{
	/* this module does not use probablity for gc, but gc_interval */
	*nrdels = 0;
	return SUCCESS;
}
/* }}} */

/********************* MODULE FUNCTIONS ***********************/
/* {{{ proto array session_pgsql_status(void)
   Returns current pgsql save handler status */
PHP_FUNCTION(session_pgsql_status)
{
	int i;
	char buf[BUF_SIZE];
	char *servers;
	
	if (ZEND_NUM_ARGS()) {
		WRONG_PARAM_COUNT;
	}

	if (PS_PGSQL(disable)) {
		php_error(E_WARNING, "session_pgsql is disabled");
		RETURN_FALSE;
	}
	if (!PS_PGSQL(current_db)) {
		php_error(E_NOTICE, "session_pgsql has no database connection");
		RETURN_FALSE;
	}

	array_init(return_value);
	servers = safe_estrdup(PS_PGSQL(db));
	add_assoc_string(return_value, "Servers", servers, 0);
	add_assoc_long(return_value, "Number of Servers", PS_PGSQL(servers));
	add_assoc_long(return_value, "Failover Mode", PS_PGSQL(failover_mode));
	add_assoc_long(return_value, "Short Circuit", PS_PGSQL(short_circuit));
	add_assoc_long(return_value, "Keep Expired", PS_PGSQL(keep_expired));
	for (i = 0; i < PS_PGSQL(servers); i++) {
		snprintf(buf, BUF_SIZE, "Server String #%d", i);
		add_assoc_string(return_value, buf, PS_PGSQL(connstr)[i], 1);
		snprintf(buf, BUF_SIZE, "Server Status #%d", i);
		if (PS_PGSQL(pgsql_link)[i]) {
			add_assoc_long(return_value, buf, 1);
		}
		else {
			add_assoc_long(return_value, buf, 0);
		}
	}
}
/* }}} */

/* {{{ proto bool session_pgsql_reset(void)
   Reset connection to session database servsers */
PHP_FUNCTION(session_pgsql_reset)
{
	if (PS_PGSQL(disable)) {
		php_error(E_WARNING, "session_pgsql is disabled");
		RETURN_FALSE;
	}

	if (php_ps_pgsql_init_servers(1 TSRMLS_CC) == FAILURE) {
		RETURN_FALSE;
	}
	RETURN_TRUE;
}
/* }}} */

/* {{{ proto array session_pgsql_status(void)
   Returns current session info */
PHP_FUNCTION(session_pgsql_info)
{
	if (ZEND_NUM_ARGS()) {
		WRONG_PARAM_COUNT;
	}

	if (PS_PGSQL(disable)) {
		php_error(E_WARNING, "session_pgsql is disabled");
		RETURN_FALSE;
	}
	if (!PS_PGSQL(current_db)) {
		php_error(E_NOTICE, "session_pgsql has no database connection");
	}

	array_init(return_value);
	add_assoc_string(return_value, "Session ID", PS(id), 1);
	add_assoc_long(return_value,   "Server ID",  PS_PGSQL(current_id));
	add_assoc_string(return_value, "Connection", PS_PGSQL(connstr)[PS_PGSQL(current_id)], 1);
	add_assoc_long(return_value,   "Accesses",   PS_PGSQL(sess_cnt));
	add_assoc_long(return_value,   "Errors",     PS_PGSQL(sess_error));
	add_assoc_long(return_value,   "Warnings",   PS_PGSQL(sess_warning));
	add_assoc_long(return_value,   "Notices",    PS_PGSQL(sess_notice));
	add_assoc_long(return_value,   "Created",    PS_PGSQL(sess_created));
	add_assoc_long(return_value,   "Modified",   PS_PGSQL(sess_modified));
	add_assoc_long(return_value,   "Expires",    PS_PGSQL(sess_expire));
	if (PS_PGSQL(sess_addr_created)) {
		add_assoc_string(return_value,   "Address Created",    PS_PGSQL(sess_addr_created), 1);
	}
	else {
		add_assoc_string(return_value,   "Address Created",    "", 1);
	}
	if (PS_PGSQL(sess_addr_modified)) {
		add_assoc_string(return_value,   "Address Modified",   PS_PGSQL(sess_addr_modified), 1);
	}
	else {
		add_assoc_string(return_value,   "Address Modified",   "", 1);
	}
	if (PS_PGSQL(sess_custom)) {
		add_assoc_string(return_value, "Custom", PS_PGSQL(sess_custom), 1);
	}
	else {
		add_assoc_string(return_value, "Custom", "", 1);
	}
}
/* }}} */

/* {{{ proto bool session_pgsql_set_field(string value)
   Set custom field value */
PHP_FUNCTION(session_pgsql_set_field)
{
	char *field = NULL;
	long len;
	int argc = ZEND_NUM_ARGS();
	
	if (zend_parse_parameters(argc TSRMLS_CC, "s", &field, &len) == FAILURE) {
		RETURN_FALSE;
	}

	if (PS_PGSQL(disable)) {
		php_error(E_WARNING, "session_pgsql is disabled");
		RETURN_FALSE;
	}
	if (!PS_PGSQL(current_db)) {
		php_error(E_NOTICE, "session_pgsql has no database connection");
		RETURN_FALSE;
	}

	PS_PGSQL(sess_short_circuit) = 0; /* force session write */
	if (PS_PGSQL(sess_custom)) {
		free(PS_PGSQL(sess_custom));
	}
	PS_PGSQL(sess_custom) = (char *)malloc(len+1);
	memcpy(PS_PGSQL(sess_custom), field, len);
	PS_PGSQL(sess_custom)[len] = '\0';
	RETURN_TRUE;
}
/* }}} */

/* {{{ proto string session_pgsql_get_field(void)
   Get custom field value */
PHP_FUNCTION(session_pgsql_get_field)
{
	if (ZEND_NUM_ARGS()) {
		WRONG_PARAM_COUNT;
	}
	if (PS_PGSQL(disable)) {
		php_error(E_WARNING, "session_pgsql is disabled");
		RETURN_FALSE;
	}
	if (!PS_PGSQL(current_db)) {
		php_error(E_NOTICE, "session_pgsql has no database connection");
		RETURN_FALSE;
	}

	if (PS_PGSQL(sess_custom) && PS_PGSQL(sess_custom)[0]) {
		RETURN_STRING(PS_PGSQL(sess_custom), 1);
	}
	RETURN_STRING("", 1);
}
/* }}} */

/* {{{ proto bool session_pgsql_add_error(int error_level [, string error_message])
   Increments error counts and sets last error message */
PHP_FUNCTION(session_pgsql_add_error)
{
	char *error_message;
	long error_level, len;
	int argc = ZEND_NUM_ARGS();
	
	if (zend_parse_parameters(argc TSRMLS_CC, "l|s", &error_level, &error_message, &len) == FAILURE) {
		RETURN_FALSE;
	}

	if (PS_PGSQL(disable)) {
		php_error(E_WARNING, "session_pgsql is disabled");
		RETURN_FALSE;
	}
	if (!PS_PGSQL(current_db)) {
		php_error(E_NOTICE, "session_pgsql has no database connection");
		RETURN_FALSE;
	}

	PS_PGSQL(sess_short_circuit) = 0; /* force session write */
	switch (error_level) {
		case E_ERROR:
		case E_USER_ERROR:
			PS_PGSQL(sess_error)++;
			break;
		case E_WARNING:
		case E_USER_WARNING:
			PS_PGSQL(sess_warning)++;
			break;
		case E_NOTICE:
		case E_USER_NOTICE:
			PS_PGSQL(sess_notice)++;
			break;
		default:
			php_error(E_WARNING, "Invalid error level");
			RETURN_FALSE;
	}
	if (argc > 1) {
		if (PS_PGSQL(sess_error_message)) {
			free(PS_PGSQL(sess_error_message));
		}
		PS_PGSQL(sess_error_message) = malloc(len+1);
		memcpy(PS_PGSQL(sess_error_message), error_message, len);
		PS_PGSQL(sess_error_message)[len] = '\0';
	}
	RETURN_TRUE;
}
/* }}} */

/* {{{ proto array session_pgsql_get_error([bool with_error_message])
   Returns number of errors and last error message */
PHP_FUNCTION(session_pgsql_get_error)
{
	int with_error_message = 0;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|b", &with_error_message) == FAILURE) {
		RETURN_FALSE;
	}

	if (PS_PGSQL(disable)) {
		php_error(E_WARNING, "session_pgsql is disabled");
		RETURN_FALSE;
	}
	if (!PS_PGSQL(current_db)) {
		php_error(E_NOTICE, "session_pgsql has no database connection");
		RETURN_FALSE;
	}

	array_init(return_value);
	add_assoc_long(return_value, "Errors",   PS_PGSQL(sess_error));
	add_assoc_long(return_value, "Warnings", PS_PGSQL(sess_warning));
	add_assoc_long(return_value, "Notices",  PS_PGSQL(sess_notice));
	if (with_error_message) {
		PGresult *pg_result;
		smart_str buf= {0};
		char *escaped;
		size_t len;

		if (PS_PGSQL(sess_error_message)) {
			add_assoc_string(return_value, "Error Message", PS_PGSQL(sess_error_message), 1);
			return;
		}
		len = strlen(PS(id));
		escaped = (char *)emalloc(len*2+1);
		len = PQescapeStringConn(PS_PGSQL(current_db), escaped, PS(id), len, NULL);
		smart_str_appends(&buf, "SELECT sess_err_message FROM php_session WHERE sess_id = '");
		smart_str_appendl(&buf, escaped, len);
		smart_str_appends(&buf, "';");
		smart_str_0(&buf);
		pg_result = PQexec(PS_PGSQL(current_db), buf.c);
		smart_str_free(&buf);
		efree(escaped);
		if (PQntuples(pg_result) == 1) {
			char *tmp;
			tmp = safe_estrdup(PQgetvalue(pg_result, 0, 0));
			add_assoc_string(return_value, "Error Message", tmp, 0);
		}
		else {
			/* new session */
			add_assoc_string(return_value, "Error Message", "", 1);
		}
		PQclear(pg_result);
	}
}
/* }}} */

#endif

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: sw=4 ts=4 fdm=marker
 * vim<600: sw=4 ts=4
 */
