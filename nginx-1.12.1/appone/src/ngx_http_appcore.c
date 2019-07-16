
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_appcore.h>
#define APPFRAME_VERSION "1.0.0.1"
static ngx_int_t ngx_http_appcore_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_http_appcore_postconfiguration(ngx_conf_t *cf);
static void *ngx_http_appcore_create_srv_conf(ngx_conf_t *cf);
static char *ngx_http_appcore_merge_srv_conf(ngx_conf_t *cf, 
		void *parent, void *child);
static void *ngx_http_appcore_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_appcore_merge_loc_conf(ngx_conf_t *cf, 
		void *parent, void *child);
static ngx_int_t ngx_http_appcore_setcookie_fmt_init(ngx_conf_t *cf, 
		ngx_str_t fmt, ngx_array_t **lengths, ngx_array_t **values);
static ngx_int_t ngx_http_appcore_variable(ngx_http_request_t *r,
		ngx_http_variable_value_t *v, uintptr_t data);

static ngx_int_t
ngx_http_tcpudp_proxy_addr_variable(ngx_http_request_t *r,
		ngx_http_variable_value_t *v, uintptr_t data);

static ngx_int_t ngx_http_appcore_loc_variable(ngx_http_request_t *r,
		ngx_http_variable_value_t *v, uintptr_t data);

static char *ngx_http_appcore_max_connections(ngx_conf_t *cf, 
		ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_appcore_max_connections_auto(ngx_conf_t *cf);
static ngx_int_t ngx_http_appcore_license_value(ngx_conf_t *cf, char *name);

static ngx_http_variable_t  ngx_http_appcore_vars[] = {
	{ 	
		ngx_string("gateway_version"), NULL, 
		ngx_http_appcore_variable, 
		offsetof(ngx_http_appcore_srv_conf_t, gateway_version),
		NGX_HTTP_VAR_NOHASH, 0 
	},

	{ 	
		ngx_string("jump_resource_id"), NULL, 
		ngx_http_appcore_loc_variable, 
		offsetof(ngx_http_appcore_loc_conf_t, jump_resource_id),
		NGX_HTTP_VAR_NOHASH, 0 
	},

	{
		ngx_string("sid_cookie_name"), NULL, 
		ngx_http_appcore_variable,
		offsetof(ngx_http_appcore_srv_conf_t, sid_cookie_name), 
		NGX_HTTP_VAR_NOHASH, 0
	},
	{ 
		ngx_string("uname_cookie_name"), NULL, 
		ngx_http_appcore_variable,
		offsetof(ngx_http_appcore_srv_conf_t, uname_cookie_name),
		NGX_HTTP_VAR_NOHASH, 0
	},
	{ 
		ngx_string("passwd_cookie_name"), NULL, 
		ngx_http_appcore_variable,
		offsetof(ngx_http_appcore_srv_conf_t, passwd_cookie_name),
		NGX_HTTP_VAR_NOHASH, 0
	},
	{ 
		ngx_string("appid_cookie_name"), NULL, 
		ngx_http_appcore_variable,
		offsetof(ngx_http_appcore_srv_conf_t, appid_cookie_name),
		NGX_HTTP_VAR_NOHASH, 0
	},
	{
		ngx_string("redirect_cookie_name"), NULL, 
		ngx_http_appcore_variable,
		offsetof(ngx_http_appcore_srv_conf_t, redirect_cookie_name), 
		NGX_HTTP_VAR_NOHASH, 0
	},

    {
        ngx_string("proxy_addr"), NULL,      
		ngx_http_tcpudp_proxy_addr_variable, 
		offsetof(ngx_http_appcore_loc_conf_t, proxy_addr),
        NGX_HTTP_VAR_NOHASH,
		0
    },

	{ ngx_null_string, NULL, NULL, 0, 0, 0 }
};	

static ngx_command_t ngx_http_appcore_commands[] = {
    { ngx_string("proxy_addr"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_1MORE,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_appcore_loc_conf_t, proxy_addr),
      NULL 
	}, 
	{
		ngx_string("gateway_version"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
		NGX_HTTP_SRV_CONF_OFFSET,
		offsetof(ngx_http_appcore_srv_conf_t, gateway_version),
		NULL
	},
	{
		ngx_string("server_name"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
		NGX_HTTP_SRV_CONF_OFFSET,
		offsetof(ngx_http_appcore_srv_conf_t, gateway_version),
		NULL
	},
	{
		ngx_string("jump_resource_id"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_appcore_loc_conf_t, jump_resource_id),
		NULL
	},

	{
		ngx_string("sessionid_cookie_name"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
		NGX_HTTP_SRV_CONF_OFFSET,
		offsetof(ngx_http_appcore_srv_conf_t, sid_cookie_name),
		0 
	},
	{
		ngx_string("username_cookie_name"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
		NGX_HTTP_SRV_CONF_OFFSET,
		offsetof(ngx_http_appcore_srv_conf_t, uname_cookie_name),
		0 
	},
	{
		ngx_string("password_cookie_name"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
		NGX_HTTP_SRV_CONF_OFFSET,
		offsetof(ngx_http_appcore_srv_conf_t, passwd_cookie_name),
		0 
	},
	{
		ngx_string("username_setcookie_fmt"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_appcore_loc_conf_t, username_setcookie_fmt),
		0 
	},
	{
		ngx_string("password_setcookie_fmt"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_appcore_loc_conf_t, password_setcookie_fmt),
		0 
	},
	{
		ngx_string("sessionid_setcookie_fmt"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_appcore_loc_conf_t, sid_setcookie_fmt),
		0 
	},
	{
		ngx_string("appid_cookie_name"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
		NGX_HTTP_SRV_CONF_OFFSET,
		offsetof(ngx_http_appcore_srv_conf_t, appid_cookie_name),
		0 
	},
	{
		ngx_string("appid_setcookie_fmt"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_appcore_loc_conf_t, appid_setcookie_fmt),
		0 
	},
	{
		ngx_string("redirect_cookie_name"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
		NGX_HTTP_SRV_CONF_OFFSET,
		offsetof(ngx_http_appcore_srv_conf_t, redirect_cookie_name),
		0 
	},
	{
		ngx_string("redirect_setcookie_fmt"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_appcore_loc_conf_t, redirect_setcookie_fmt),
		0 
	},

	{
		ngx_string("max_connections"),
		NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
		ngx_http_appcore_max_connections,
		0,
		0,
		0 
	},

	ngx_null_command
};

static ngx_http_module_t ngx_http_appcore_module_ctx = {
	ngx_http_appcore_add_variables,			/* preconfiguration */
	ngx_http_appcore_postconfiguration,		/* postconfiguration */

	NULL,									/* create main configuration */
	NULL,									/* init main configuration */

	ngx_http_appcore_create_srv_conf,		/* create server configuration */
	ngx_http_appcore_merge_srv_conf,		/* merge server configuration */

	ngx_http_appcore_create_loc_conf,		/* create location configuration */
	ngx_http_appcore_merge_loc_conf,		/* merge location configuration */
};

ngx_module_t ngx_http_appcore_module = {
	NGX_MODULE_V1,
	&ngx_http_appcore_module_ctx,			/* module context */
	ngx_http_appcore_commands,				/* module directives */
	NGX_HTTP_MODULE,						/* module type */
	NULL,									/* init master */
	NULL,									/* init module */
	NULL,									/* init process */
	NULL,									/* init thread */
	NULL,									/* exit thread */
	NULL,									/* exit process */
	NULL,									/* exit master */
	NGX_MODULE_V1_PADDING
};

static ngx_int_t
ngx_http_appcore_add_variables(ngx_conf_t *cf)
{
	ngx_http_variable_t  *var, *v;

	for (v = ngx_http_appcore_vars; v->name.len; v++) {
		var = ngx_http_add_variable(cf, &v->name, v->flags);
		if (var == NULL) {
			return NGX_ERROR;
		}

		var->get_handler = v->get_handler;
		var->data = v->data;
	}

	return NGX_OK;
}

static ngx_int_t 
ngx_http_appcore_postconfiguration(ngx_conf_t *cf)
{
    return NGX_OK;
}

static void *
ngx_http_appcore_create_srv_conf(ngx_conf_t *cf)
{
	ngx_http_appcore_srv_conf_t *ascf = NULL;
	
	ascf = ngx_pcalloc(cf->pool, sizeof(ngx_http_appcore_srv_conf_t));
	if (NULL == ascf) {
		return NULL;
	}

	return ascf;
}

static char *
ngx_http_appcore_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
	ngx_http_appcore_srv_conf_t	*prev = parent;
	ngx_http_appcore_srv_conf_t	*conf = child;

	ngx_conf_merge_str_value(conf->uname_cookie_name, prev->uname_cookie_name,
			"UN");
	ngx_conf_merge_str_value(conf->passwd_cookie_name, prev->passwd_cookie_name,
			"PWD");
	ngx_conf_merge_str_value(conf->sid_cookie_name, prev->sid_cookie_name,
			"SESSIONID");
	ngx_conf_merge_str_value(conf->appid_cookie_name, prev->appid_cookie_name,
			"APPID");
	ngx_conf_merge_str_value(conf->server_cookie_name, prev->server_cookie_name,
			"SERVERNAME");
	ngx_conf_merge_str_value(conf->redirect_cookie_name, prev->redirect_cookie_name,
			"REDIRECT");
	ngx_conf_merge_str_value(conf->gateway_version, prev->gateway_version, 
			"0.0.0.0");
	ngx_conf_merge_str_value(conf->appone_version, prev->appone_version, 
			APPFRAME_VERSION);

	conf->appid_cookie_var_index = ngx_http_get_cookie_variable_index(cf, &conf->appid_cookie_name);
	if (NGX_ERROR == conf->appid_cookie_var_index) {
		ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "get appid cookie variable index failed");
		return NGX_CONF_ERROR;
	}
	
	conf->server_cookie_var_index = ngx_http_get_cookie_variable_index(cf, &conf->server_cookie_name);
	if (NGX_ERROR == conf->server_cookie_var_index) {
		ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "get server cookie variable index failed");
		return NGX_CONF_ERROR;
	}

	conf->sid_cookie_var_index = ngx_http_get_cookie_variable_index(cf, 
			&conf->sid_cookie_name);
	if (NGX_ERROR == conf->sid_cookie_var_index) {
		ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "get sid cookie variable index failed");
		return NGX_CONF_ERROR;
	}

	conf->redirect_cookie_var_index = ngx_http_get_cookie_variable_index(cf, 
			&conf->redirect_cookie_name);
	if (NGX_ERROR == conf->redirect_cookie_var_index) {
		ngx_conf_log_error(NGX_LOG_ERR, cf, 0,"get reddirect cookie variable index failed");
		return NGX_CONF_ERROR;
	}

	return NGX_CONF_OK;
}

static void *
ngx_http_appcore_create_loc_conf(ngx_conf_t *cf)
{
	ngx_http_appcore_loc_conf_t *alcf = NULL;
	
	alcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_appcore_loc_conf_t));
	if (NULL == alcf) {
		return NULL;
	}

	return alcf;
}

static char *
ngx_http_appcore_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
	ngx_int_t rc = NGX_OK;
	ngx_http_appcore_loc_conf_t	*prev = parent;
	ngx_http_appcore_loc_conf_t	*conf = child;

	ngx_conf_merge_str_value(conf->redirect_setcookie_fmt,
			prev->redirect_setcookie_fmt,
			"$redirect_cookie_name=NULL; expires=01 Jan 1970 08:00:00 GMT; path=/;");
	ngx_conf_merge_str_value(conf->proxy_addr, prev->proxy_addr, "");
	ngx_conf_merge_str_value(conf->server_name, prev->server_name, "");
	ngx_conf_merge_str_value(conf->login_default, prev->login_default, "");
	ngx_conf_merge_str_value(conf->jump_resource_id, prev->jump_resource_id, "");

	rc = ngx_http_appcore_setcookie_fmt_init(cf, conf->username_setcookie_fmt,
			&conf->username_setcookie_lengths, &conf->username_setcookie_values);
	if (NGX_ERROR == rc) {
		return NGX_CONF_ERROR;
	}

	rc = ngx_http_appcore_setcookie_fmt_init(cf, conf->password_setcookie_fmt,
			&conf->password_setcookie_lengths, &conf->password_setcookie_values);
	if (NGX_ERROR == rc) {
		return NGX_CONF_ERROR;
	}

	rc = ngx_http_appcore_setcookie_fmt_init(cf, conf->sid_setcookie_fmt,
			&conf->sid_setcookie_lengths, &conf->sid_setcookie_values);
	if (NGX_ERROR == rc) {
		return NGX_CONF_ERROR;
	}

	rc = ngx_http_appcore_setcookie_fmt_init(cf, conf->appid_setcookie_fmt,
			&conf->appid_setcookie_lengths, &conf->appid_setcookie_values);
	if (NGX_ERROR == rc) {
		return NGX_CONF_ERROR;
	}

	rc = ngx_http_appcore_setcookie_fmt_init(cf, conf->redirect_setcookie_fmt,
			&conf->redirect_setcookie_lengths, &conf->redirect_setcookie_values);
	if (NGX_ERROR == rc) {
		return NGX_CONF_ERROR;
	}

	return NGX_CONF_OK;
}

static char *
ngx_http_appcore_max_connections(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_event_conf_t *ecf = NULL;
    ngx_str_t *value = NULL;
	ngx_uint_t connections = 0;

	ecf = ngx_event_get_conf(cf->cycle->conf_ctx, ngx_event_core_module);

    value = cf->args->elts;

	if (ecf->connections != NGX_CONF_UNSET_UINT) {
		ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
				"\"%V\" is set, worker_connections will be reset", &value[0]);
	}

	if (ngx_strcmp("auto", value[1].data) == 0) {
		connections = ngx_http_appcore_max_connections_auto(cf);
	} else {
		connections = ngx_atoi(value[1].data, value[1].len);
		if (connections == (ngx_uint_t) NGX_ERROR) {
			ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
					"invalid number \"%V\"", &value[1]);

			return NGX_CONF_ERROR;
		}
	}

	ecf->connections = (connections + ngx_ncpu - 1)/ngx_ncpu;

	if (ecf->connections < 6000) {
		ecf->connections = 6000;
	} else if (ecf->connections > 60000) {
		ecf->connections = 60000;
	}

	ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
			"appone max_connections \"%d\"", ecf->connections);

    cf->cycle->connection_n = ecf->connections;

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_appcore_max_connections_auto(ngx_conf_t *cf)
{
	ngx_int_t license = 0;

	license = ngx_http_appcore_license(cf, NGX_HTTP_APPCORE_LICENSE_ALL);

	return license * NGX_HTTP_APPCORE_ONE_LICENSE_CONNECTIONS_NUM_MIN;
}

static ngx_int_t
ngx_http_appcore_setcookie_fmt_init(ngx_conf_t *cf, ngx_str_t fmt,
		ngx_array_t **lengths, ngx_array_t **values)
{
	ngx_http_script_compile_t sc;

	ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));

	sc.cf = cf;
	sc.source = &fmt;
	sc.lengths = lengths;
	sc.values = values;
	sc.variables = ngx_http_script_variables_count(&fmt);
	sc.complete_lengths = 1;
	sc.complete_values = 1;

	if (ngx_http_script_compile(&sc) != NGX_OK) {
		ngx_conf_log_error(NGX_LOG_ERR, cf, 0,
				"'%V' script compile failed", &fmt);
		return NGX_ERROR;
	}

	return NGX_OK;
}

static ngx_int_t
ngx_http_appcore_variable(ngx_http_request_t *r,
		ngx_http_variable_value_t *v, uintptr_t data)
{
	ngx_str_t *s = NULL;
	ngx_http_appcore_srv_conf_t *ascf = NULL;

	ascf = ngx_http_get_module_srv_conf(r, ngx_http_appcore_module);	
	if (NULL == ascf) {
		v->not_found = 1;
		return NGX_OK;
	}
	
	s = (ngx_str_t*)((char*)ascf + data);

	if (s->data) {
		v->len = s->len;
		v->valid = 1;
		v->no_cacheable = 0;
		v->not_found = 0;
		v->data = s->data;
	} else {
		v->not_found = 1;
	}
	
	return NGX_OK;
}

static ngx_int_t
ngx_http_tcpudp_proxy_addr_variable(ngx_http_request_t *r,
		ngx_http_variable_value_t *v, uintptr_t data)
{
	ngx_http_appcore_loc_conf_t *tdclcf = NULL;
	ngx_str_t *s = NULL;

	tdclcf = ngx_http_get_module_loc_conf(r, ngx_http_appcore_module);	
	
	s = (ngx_str_t*)((char*)tdclcf + data);
		
	if (s->data) {
		v->len = s->len;
		v->valid = 1;
		v->no_cacheable = 0;
		v->not_found = 0;
		v->data = s->data;
	} else {
		v->not_found = 1;
	}

	return NGX_OK;
}

static ngx_int_t
ngx_http_appcore_loc_variable(ngx_http_request_t *r,
		ngx_http_variable_value_t *v, uintptr_t data)
{
	ngx_str_t *s = NULL;
	ngx_http_appcore_loc_conf_t *alcf = NULL;

	alcf = ngx_http_get_module_loc_conf(r, ngx_http_appcore_module);	
	if (NULL == alcf) {
		v->not_found = 1;
		return NGX_OK;
	}
	
	s = (ngx_str_t*)((char*)alcf + data);

	if (s->data) {
		v->len = s->len;
		v->valid = 1;
		v->no_cacheable = 0;
		v->not_found = 0;
		v->data = s->data;
	} else {
		v->not_found = 1;
	}
	
	return NGX_OK;
}

ngx_int_t 
ngx_http_appcore_get_sid(ngx_http_request_t *r, ngx_str_t *sid)
{
	ngx_http_appcore_srv_conf_t *ascf = NULL;
    ngx_http_variable_value_t *vv = NULL;

	ascf = ngx_http_get_module_srv_conf(r, ngx_http_appcore_module);
	
	vv = ngx_http_get_indexed_variable(r, ascf->sid_cookie_var_index);
	if (NULL == vv || vv->not_found) {
		ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
				"not found sessionid in cookie");
		return NGX_ERROR;
	}

	if (0 == vv->len) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
				"found sessionid in cookie but it is NULL");
		return NGX_ERROR;
	}

	sid->len = vv->len;
	sid->data = vv->data;

	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
			"found resource sessionid \"%V\" in cookie", sid);

	return NGX_OK;
}
ngx_int_t
ngx_http_appcore_get_servername(ngx_http_request_t *r, ngx_str_t *servername)
{
	ngx_http_appcore_srv_conf_t *ascf = NULL;
    ngx_http_variable_value_t *vv = NULL;

	ascf = ngx_http_get_module_srv_conf(r, ngx_http_appcore_module);
	
	vv = ngx_http_get_indexed_variable(r, ascf->server_cookie_var_index);
	if (NULL == vv || vv->not_found) {
		ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
				"not found servername in cookie");
		return NGX_ERROR;
	}

	if (0 == vv->len) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
				"found servername in cookie but it is NULL");
		return NGX_ERROR;
	}

	servername->len = vv->len;
	servername->data = vv->data;

	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
			"found resource servername \"%V\" in cookie", servername);

	return NGX_OK;
}
ngx_int_t 
ngx_http_appcore_get_appid_from_uri(ngx_http_request_t *r, ngx_str_t *appid)
{
	if(ngx_http_parse_uri_value(r, NULL, 1, appid, 
			NULL) != NGX_OK) {
		ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, 
				"not found appid in request uri");
		return NGX_ERROR;
	}

	if (0 == appid->len) {
		return NGX_ERROR;
	}

	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
			"found resource appid \"%V\" in request uri", appid);
	return NGX_OK;
}

ngx_int_t 
ngx_http_appcore_get_appid_from_referer(ngx_http_request_t *r, ngx_str_t *appid)
{
	ngx_table_elt_t *referer = NULL;
	ngx_str_t *value = NULL;
	u_char *pos = NULL;
	ngx_int_t left = 0;
	ngx_str_t uri = ngx_null_string;

	referer = r->headers_in.referer;

	if (NULL == referer) {
		ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, 
				"referer header not found");
		return NGX_ERROR;
	}

	value = &referer->value;
	pos = value->data;
	left = value->len;

	if (left < 4 || ngx_strncasecmp(pos, (u_char*)"http", 4) != 0) {
		ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, 
				"referer \"%V\"format may be incorrect", value);
		return NGX_ERROR;
	}
	pos += 4;
	left -= 4;
	if (left > 0 && *pos == 's') {
		pos++;	
		left--;
	}

	if (left < 3 || ngx_strncasecmp(pos, (u_char*)"://", 3) != 0) {
		ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, 
				"referer \"%V\"format may be incorrect", value);
		return NGX_ERROR;
	}
	pos += 3;
	left -= 3;
	
	while (left-- > 0) {
		if (*pos++ == '/') {
			break;
		}
	}

	uri.data = --pos;
	uri.len = ++left;

	if(ngx_http_parse_uri_value(r, &uri, 1, appid, 
			NULL) != NGX_OK) {
		ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, 
				"not found appid in referer uri \"%V\"", &uri);
		return NGX_ERROR;
	}

	if (0 == appid->len) {
		return NGX_ERROR;
	}

	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
			"found resource appid \"%V\" in referer uri", appid);
	return NGX_OK;
}

ngx_int_t 
ngx_http_appcore_get_appid_from_cookie(ngx_http_request_t *r, ngx_str_t *appid)
{
	ngx_http_appcore_srv_conf_t *ascf = NULL;
    ngx_http_variable_value_t *vv = NULL;

	ascf = ngx_http_get_module_srv_conf(r, ngx_http_appcore_module);
	
	vv = ngx_http_get_indexed_variable(r, ascf->appid_cookie_var_index);
	if (NULL == vv || vv->not_found) {
		ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
				"not found appid in cookie");
		return NGX_ERROR;
	}

	appid->len = vv->len;
	appid->data = vv->data;

	if (0 == appid->len) {
		return NGX_ERROR;
	}

	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
			"found resource appid \"%V\" in cookie", appid);

	return NGX_OK;
}

ngx_int_t 
ngx_http_appcore_get_redirect(ngx_http_request_t *r, ngx_str_t *redirect)
{
	ngx_http_appcore_srv_conf_t *ascf = NULL;
    ngx_http_variable_value_t *vv = NULL;

	ascf = ngx_http_get_module_srv_conf(r, ngx_http_appcore_module);
	
	vv = ngx_http_get_indexed_variable(r, ascf->redirect_cookie_var_index);
	if (NULL == vv || vv->not_found) {
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
				"not found redirect in cookie");
		return NGX_ERROR;
	}

	if (0 == vv->len) {
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
				"found redirect in cookie but it is NULL");
		return NGX_ERROR;
	}

	redirect->len = vv->len;
	redirect->data = vv->data;

	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
			"found redirect \"%V\" in cookie", redirect);

	return NGX_OK;
}

char * 
ngx_http_appcore_error_itoa(ngx_http_request_t *r, ngx_int_t code, 
		uintptr_t data)
{
	return NGX_OK;
}

ngx_int_t 
ngx_http_appcore_license(ngx_conf_t *cf, ngx_int_t license)
{
	static ngx_int_t usernum = -1;
	static ngx_int_t remoteusernum = -1;
	ngx_int_t num = 0;

	if (NGX_HTTP_APPCORE_LICENSE_USERNUM & license) {
		if (usernum < 0) {
			usernum = ngx_http_appcore_license_value(cf,
					"USERNUM");
		}
		num += usernum;
	}

	if (NGX_HTTP_APPCORE_LICENSE_REMOTEUSERNUM & license) {
		if (remoteusernum < 0) {
			remoteusernum = ngx_http_appcore_license_value(cf,
					"REMOTEUSERNUM");
		}
		num += remoteusernum;
	}	
	return num;
}

static ngx_int_t 
ngx_http_appcore_license_value(ngx_conf_t *cf, char *name)
{
	return 999999999999;
}

#if 0
#define ENCRYPT_LEN 16
static unsigned char encrypt_iv[ENCRYPT_LEN+1]="abcdef1234567890";
static unsigned char encrypt_key[ENCRYPT_LEN+1]="1234567890abcdef";
ngx_int_t
ngx_encode_aes(ngx_http_request_t *r, ngx_str_t *cipher, ngx_str_t *plain)
{
	const EVP_CIPHER *encrypt = EVP_get_cipherbyname(SN_aes_128_cbc);

	EVP_CIPHER_CTX ctx;
	EVP_CIPHER_CTX_init(&ctx);
	EVP_EncryptInit_ex(&ctx, encrypt, NULL, encrypt_key, encrypt_iv);

	int outl = plain->len+ENCRYPT_LEN;
	unsigned char *out = ngx_pcalloc(r->pool, outl);

	int total = 0;
	EVP_EncryptUpdate(&ctx, out, &outl, plain->data, plain->len);
	total+=outl;
	EVP_EncryptFinal(&ctx, out+total, &outl);
	total += outl;

	EVP_CIPHER_CTX_cleanup(&ctx);

	cipher->data = out;
	cipher->len = total;
	
	if (0) {
		ngx_str_t dump;
		dump.len = outl*2;
		dump.data = ngx_pcalloc(r->pool, dump.len);
		ngx_hex_dump(dump.data, out, total);
		ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
				"\e[31m shy log encrypt(%d): %s\e[0m", ENCRYPT_LEN, SN_aes_128_cbc);
		ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
				"\e[31m shy log text(%d): %v\e[0m", plain->len, plain);
		ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
				"\e[31m shy log code(%d): %v\e[0m", total, &dump);


	}

	return NGX_OK;
}
ngx_int_t
ngx_decode_aes(ngx_http_request_t *r, ngx_str_t *plain, ngx_str_t *cipher)
{
	if (cipher->len % ENCRYPT_LEN) {
		return NGX_ERROR;
	}

	const EVP_CIPHER *encrypt = EVP_get_cipherbyname(SN_aes_128_cbc);

	EVP_CIPHER_CTX ctx;
	EVP_CIPHER_CTX_init(&ctx);
	EVP_DecryptInit_ex(&ctx, encrypt, NULL, encrypt_key, encrypt_iv);

	int outl = cipher->len;
	unsigned char *out = ngx_pcalloc(r->pool, outl);

	int total = 0;
	EVP_DecryptUpdate(&ctx, out, &outl, cipher->data, cipher->len);
	total+=outl;
	EVP_DecryptFinal(&ctx, out+total, &outl);
	total += outl;

	EVP_CIPHER_CTX_cleanup(&ctx);

	plain->data = out;
	plain->len = total;

	if (0) {
		ngx_str_t dump;
		dump.len = outl*2;
		dump.data = ngx_pcalloc(r->pool, dump.len);
		ngx_hex_dump(dump.data, cipher->data, cipher->len);
		ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
				"\e[31m shy log encrypt(%d): %s\e[0m", ENCRYPT_LEN, SN_aes_128_cbc);
		ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
				"\e[31m shy log code(%d): %v\e[0m", cipher->len, &dump);
		ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
				"\e[31m shy log text(%d): %v\e[0m", plain->len, plain);


	}

	return NGX_OK;
}
#endif
