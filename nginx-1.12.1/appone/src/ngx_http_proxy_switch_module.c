
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_http_proxy_switch.h"
#include <ngx_http_upstream.h>

typedef struct {
	ngx_str_t		 	proto;
	ngx_str_t		 	mapid;
	struct timeval		up_time;
	ngx_http_upstream_srv_conf_t 	*upstream;
}ngx_http_proxy_switch_dyconfig_t;

typedef struct {
    ngx_str_t                      proto;
    ngx_str_t                      host;
    ngx_str_t                      port;
    ngx_str_t                      server;
    ngx_str_t                      mapid;
} ngx_http_proxy_switch_vars_t;

typedef struct {
	ngx_http_proxy_switch_dyconfig_t	*config;
	ngx_http_proxy_switch_vars_t		vars;
	ngx_str_t 							domain;
}ngx_http_proxy_switch_ctx_t;

static ngx_int_t
ngx_http_proxy_switch_handler(ngx_http_request_t *r);
static char *
ngx_http_proxy_switch(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void *
ngx_http_proxy_switch_create_loc_conf(ngx_conf_t *cf);
static char *
ngx_http_proxy_switch_merge_loc_conf(ngx_conf_t *cf, void *prev, void *conf);

static ngx_int_t
ngx_http_proxy_switch_add_variables(ngx_conf_t *cf);
static ngx_int_t
ngx_http_proxy_switch_proto_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t
ngx_http_proxy_switch_host_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t
ngx_http_proxy_switch_port_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t
ngx_http_proxy_switch_server_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t
ngx_http_proxy_switch_mapid_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t
ngx_http_proxy_switch_set_default_vars(ngx_http_request_t *r);

static ngx_http_proxy_instance_t *
ngx_http_proxy_switch_find_proxy_instance(ngx_http_proxy_switch_loc_conf_t *plcf,
		ngx_str_t *name);

static ngx_http_proxy_switch_dyconfig_t *
ngx_http_proxy_switch_get_config(ngx_http_request_t *r);

static ngx_command_t  ngx_http_proxy_switch_commands[] = {
 
    { ngx_string("proxy_switch"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_TAKE1,
      ngx_http_proxy_switch,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_proxy_switch_module_ctx = {
    ngx_http_proxy_switch_add_variables,   /* preconfiguration */
    NULL,								   /* postconfiguration */

    NULL,									/* create main configuration */
	NULL,									/* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_proxy_switch_create_loc_conf,        /* create location configuration */
    ngx_http_proxy_switch_merge_loc_conf          /* merge location configuration */
};


ngx_module_t  ngx_http_proxy_switch_module = {
    NGX_MODULE_V1,
    &ngx_http_proxy_switch_module_ctx,            /* module context */
    ngx_http_proxy_switch_commands,               /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
	NULL,								   /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_variable_t ngx_http_proxy_switch_vars[] = {
	
	{ ngx_string("proxy_switch_proto"), NULL, ngx_http_proxy_switch_proto_variable, 0,
      NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_NOHASH, 0 },

	{ ngx_string("proxy_switch_server"), NULL, ngx_http_proxy_switch_server_variable, 0,
      NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_NOHASH, 0 },

    { ngx_string("proxy_switch_host"), NULL, ngx_http_proxy_switch_host_variable, 0,
      NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_NOHASH, 0 },

    { ngx_string("proxy_switch_port"), NULL, ngx_http_proxy_switch_port_variable, 0,
      NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_NOHASH, 0 },

    { ngx_string("proxy_switch_mapid"), NULL, ngx_http_proxy_switch_mapid_variable, 0,
      NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_NOHASH, 0 },

    { ngx_null_string, NULL, NULL, 0, 0, 0 }
};


static ngx_int_t
ngx_http_proxy_switch_handler(ngx_http_request_t *r)
{
	ngx_http_proxy_switch_ctx_t			*ctx = NULL;
	ngx_http_proxy_switch_dyconfig_t		*config = NULL;
    	ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "proxy switch handler");

	ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_proxy_switch_ctx_t));
	if(ctx == NULL){
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
				"proxy switch handler palloc error");
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	ngx_http_set_ctx(r, ctx, ngx_http_proxy_switch_module);

	config = ngx_http_proxy_switch_get_config(r);
	if(config == NULL){
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
				"proxy switch get dyconfig error");
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}
	ctx->config = config;

	if (ngx_http_proxy_switch_set_var(r, PROXY_SWITCH_VAR_PROTO, &config->proto) 
			!= NGX_OK){
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
				"proxy switch set var proto error");
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	//set default vars
	if (ngx_http_proxy_switch_set_default_vars(r) != NGX_OK){
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
				"proxy switch set default vars error");
		return NGX_HTTP_INTERNAL_SERVER_ERROR;

	}

	return NGX_OK;
}

static ngx_int_t
ngx_http_proxy_switch_set_default_vars(ngx_http_request_t *r)
{
	ngx_str_t								rvalue = ngx_null_string;

	ngx_str_t								domain_value = ngx_null_string;	//记录配置文件中的静态主机
	ngx_str_t								host_value = ngx_null_string;	//记录欲查询的主机名
	ngx_str_t								media_value = ngx_null_string;	//记录欲查询的主机名+":"
	ngx_str_t								media = ngx_null_string;
	ngx_str_t								delimiter = ngx_string(":");

	ngx_http_variable_value_t				*value = NULL;
	ngx_http_proxy_switch_loc_conf_t		*plcf = NULL;

	plcf = ngx_http_get_module_loc_conf(r, ngx_http_proxy_switch_module);
	//get static host info in config file
	if (plcf->static_host_index != NGX_CONF_UNSET){
		value = ngx_http_get_indexed_variable(r, plcf->static_host_index);
		if(value == NULL || value->not_found){
			return NGX_ERROR;
		}
	}

	domain_value.data = value->data;
	domain_value.len = value->len;

	if (plcf->host_var_index != NGX_CONF_UNSET){
		value = ngx_http_get_indexed_variable(r, plcf->host_var_index);
		if(value == NULL || value->not_found){
			return NGX_ERROR;
		}
	}

	//get host name+":"  which will be switched 
	host_value.data = value->data;
	host_value.len = value->len;

	media_value.len = value->len + delimiter.len;
	media_value.data = ngx_pcalloc(r->pool, media_value.len + 1);
	if (NULL == media_value.data) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
				"proxy switch module: pcalloc failed setting host name:(%V)",
				&host_value);
		return NGX_ERROR;
	}
	ngx_cpystrn(media_value.data, value->data, value->len + 1);
	ngx_cpystrn(media_value.data + value->len, delimiter.data, delimiter.len + 1);

	// find host ip which is associated with host name from static host info 
	media.data = domain_value.data;
	domain_value.data = ngx_strstrn(domain_value.data, 
			(char *)media_value.data, media_value.len - 1);
	if (domain_value.data){
		// get host ip from static host info
		media.len = domain_value.data - media.data;
		domain_value.data += media_value.len;
		domain_value.len = domain_value.len + media.data - domain_value.data;

		value->data = (u_char *)strtok((char *)domain_value.data, ";");
		value->len = ngx_strlen(value->data);

	} 
	rvalue.data = value->data;
	rvalue.len = value->len;

	if (ngx_http_proxy_switch_set_var(r, PROXY_SWITCH_VAR_HOST, &rvalue) 
			!= NGX_OK){
		return NGX_ERROR;
	}

	if (plcf->port_var_index != NGX_CONF_UNSET){
		value = ngx_http_get_indexed_variable(r, plcf->port_var_index);
		if(value == NULL || value->not_found){
			return NGX_ERROR;
		}
	}

	if (r->method & NGX_HTTP_CONNECT){

		rvalue.data = r->connect_port_start;
		rvalue.len = r->connect_port_end - r->connect_port_start;
	}else{

		if (plcf->port_var_index != NGX_CONF_UNSET){
			value = ngx_http_get_indexed_variable(r, plcf->port_var_index);
			if(value == NULL || value->not_found){
				return NGX_ERROR;
			}
		}
		rvalue.data = value->data;
		rvalue.len = value->len;
	}

	if (ngx_http_proxy_switch_set_var(r, PROXY_SWITCH_VAR_PORT, &rvalue)
			!= NGX_OK){
		return NGX_ERROR;
	}

	return NGX_OK;
}


static ngx_http_proxy_switch_dyconfig_t *
ngx_http_proxy_switch_get_config(ngx_http_request_t *r)
{
	ngx_http_proxy_switch_dyconfig_t		*config = NULL;
	ngx_conf_t					cf;
	ngx_str_t					proto = ngx_null_string;
	ngx_str_t					mapid = ngx_null_string;
	ngx_http_conf_ctx_t				*ctx = NULL;

	if(ngx_http_proxy_switch_set_var(r, PROXY_SWITCH_VAR_MAPID, &mapid) 
			!= NGX_OK){
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
				"proxy switch set var mapid error.");
		return NULL;
	}


	//NOTICE: pool
	config = ngx_pcalloc(r->pool, sizeof(ngx_http_proxy_switch_dyconfig_t));
	if(config == NULL){
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
				"upstream create srv conf alloc config failed");
		return NULL;
	}

	config->proto = proto;
	config->mapid = mapid;

	ngx_memzero(&cf, sizeof(ngx_conf_t));
	cf.pool = r->pool;

	ctx = ngx_palloc(r->pool, sizeof(ngx_http_conf_ctx_t));
	if(ctx == NULL){
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
				"upstream create srv conf alloc ctx failed");
		return NULL;
	}

	cf.ctx = ctx;
	ctx->main_conf = r->main_conf;

	return config;
}

static char *
ngx_http_proxy_switch(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_uint_t                  		n = 0;
    ngx_str_t                  			*value = NULL, *proxy_name = NULL;
    ngx_http_core_loc_conf_t   			*clcf = NULL;
    ngx_http_script_compile_t   		sc;
    ngx_http_proxy_switch_loc_conf_t 	*plcf = conf;

	if (plcf->enabled == 1){
		return "is duplicate";
	}

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
	
	clcf->handler = ngx_http_proxy_switch_handler;
	plcf->enabled = 1;

    value = cf->args->elts;
	proxy_name = &value[1];

    n = ngx_http_script_variables_count(proxy_name);

    if (n) {

        ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));

        sc.cf = cf;
        sc.source = proxy_name;
        sc.lengths = &plcf->proxy_lengths;
        sc.values = &plcf->proxy_values;
        sc.variables = n;
        sc.complete_lengths = 1;
        sc.complete_values = 1;

        if (ngx_http_script_compile(&sc) != NGX_OK) {
            return NGX_CONF_ERROR;
        }

        return NGX_CONF_OK;
    }

    plcf->name = *proxy_name;

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_proxy_switch_proto_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_proxy_switch_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_switch_module);

    if (ctx == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->len = ctx->vars.proto.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = ctx->vars.proto.data;

    return NGX_OK;
}

static ngx_int_t
ngx_http_proxy_switch_host_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_proxy_switch_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_switch_module);

    if (ctx == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->len = ctx->vars.host.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = ctx->vars.host.data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_switch_port_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_proxy_switch_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_switch_module);

    if (ctx == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->len = ctx->vars.port.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = ctx->vars.port.data;

    return NGX_OK;
}

static ngx_int_t
ngx_http_proxy_switch_server_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_proxy_switch_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_switch_module);

    if (ctx == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->len = ctx->vars.server.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = ctx->vars.server.data;

    return NGX_OK;
}

static ngx_int_t
ngx_http_proxy_switch_mapid_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_proxy_switch_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_switch_module);

    if (ctx == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->len = ctx->vars.mapid.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = ctx->vars.mapid.data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_switch_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_proxy_switch_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}

static void *
ngx_http_proxy_switch_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_proxy_switch_loc_conf_t  *conf = NULL;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_proxy_switch_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    if (ngx_array_init(&conf->proxy_instances, cf->pool, 4,
                       sizeof(ngx_http_proxy_instance_t *)) != NGX_OK)
    {
        return NULL;
    }

	conf->enabled = NGX_CONF_UNSET;
	conf->proxy = NGX_CONF_UNSET_PTR;

    return conf;
}

static char *
ngx_http_proxy_switch_merge_loc_conf(ngx_conf_t *cf, void *prev, void *conf)
{
	ngx_http_core_loc_conf_t   			*clcf = NULL;
	ngx_http_proxy_switch_loc_conf_t	*plcf = conf;

	clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

	if (plcf->enabled == 1){
		clcf->handler = ngx_http_proxy_switch_handler;
	}

	return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_proxy_switch_add_proxy_instance(ngx_http_proxy_switch_loc_conf_t *plcf, 
	ngx_http_proxy_instance_t *instance)
{
	ngx_http_proxy_instance_t	**instancep = NULL;

	if (ngx_http_proxy_switch_find_proxy_instance(plcf, &instance->name) 
			!= NULL){
		return NGX_ERROR;
	}

	instancep = ngx_array_push(&plcf->proxy_instances);
    if (instancep == NULL) {
        return NGX_ERROR;
    }

	*instancep = instance;
	return NGX_OK;
}

static ngx_http_proxy_instance_t *
ngx_http_proxy_switch_find_proxy_instance(ngx_http_proxy_switch_loc_conf_t *plcf,
		ngx_str_t *name)
{
	ngx_uint_t	 				i = 0;
	ngx_http_proxy_instance_t	**instancep = NULL;

	instancep = plcf->proxy_instances.elts;
	for ( i = 0; i < plcf->proxy_instances.nelts; i++){

		if (instancep[i]->name.len == name->len
				&& ngx_strncasecmp(instancep[i]->name.data, 
					name->data, name->len) == 0)
		{
			return instancep[i];
		}
	}

	return NULL;
}

ngx_int_t
ngx_http_proxy_switch_set_proxy_instance(ngx_conf_t *cf, 
		ngx_http_proxy_instance_t *instance)
{
    ngx_http_core_loc_conf_t  			*clcf = NULL;
	ngx_http_proxy_switch_loc_conf_t	*plcf = NULL;

	if (instance == NULL 
			|| instance->name.len == 0
			|| instance->handler == NULL){

		ngx_conf_log_error(NGX_LOG_ERR, cf, 0, 
				"add proxy instance input param wrong");
		return NGX_ERROR;
	}

   	clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

	plcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_proxy_switch_module);

	if (plcf->enabled == 1 ){

		ngx_conf_log_error(NGX_LOG_DEBUG, cf, 0, "proxy switch enabled");

		if(ngx_http_proxy_switch_add_proxy_instance(plcf, instance) != NGX_OK){
		
			ngx_conf_log_error(NGX_LOG_ERR, cf, 0, 
					"add proxy instance(%V) failed", &instance->name);
			return NGX_ERROR;
		}

		return NGX_OK;
	}

   	clcf->handler = instance->handler;

	return NGX_OK;
}

ngx_int_t
ngx_http_proxy_switch_set_upstream_instance(ngx_conf_t *cf, 
		ngx_http_upstream_conf_t *conf, ngx_str_t *name)
{
	return NGX_OK;
}

ngx_int_t
ngx_http_proxy_switch_set_upstream_srv_conf(ngx_http_request_t *r, 
		ngx_http_upstream_t *u)
{
	ngx_http_proxy_switch_ctx_t			*ctx = NULL;
	ngx_http_proxy_switch_dyconfig_t  	*config = NULL;

	ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_switch_module);

	if (ctx == NULL){

		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "input param wrong");
		return NGX_ERROR;
	}

	config = ctx->config;
	if (config == NULL || config->upstream == NULL){
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "config uscf is null");
		return NGX_ERROR;
	}

	u->upstream = config->upstream;

	return NGX_OK;
}

ngx_int_t
ngx_http_proxy_switch_eval(ngx_http_request_t *r, 
		ngx_array_t *proxy_lengths, ngx_array_t *proxy_values)
{
	u_short				  		port = 80;
    ngx_str_t             		proxy = ngx_null_string;
    ngx_str_t             		proto = ngx_null_string;
	ngx_url_t			  		url;
    ngx_http_upstream_t  		*u = NULL;
	
    u = r->upstream;

    if (ngx_http_script_run(r, &proxy, proxy_lengths->elts, 0,
                            proxy_values->elts)
        == NULL)
    {
        return NGX_ERROR;
    }

	proto.data = proxy.data;
	proxy.data = ngx_strstrn(proxy.data, "://", 2);
	if (proxy.data == NULL){
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
       			"proxy var format wrong.");
		return NGX_ERROR;
	}
	proto.len = proxy.data - proto.data;
	proxy.data += 3;
	proxy.len = proto.data + proxy.len - proxy.data;

    ngx_memzero(&url, sizeof(ngx_url_t));

    url.url = proxy;
    url.default_port = port;
	url.uri_part = 1;
    url.no_resolve = 1;

    if (ngx_parse_url(r->pool, &url) != NGX_OK) {
        if (url.err) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "%s in upstream \"%V\"", url.err, &url.url);
        }

        return NGX_ERROR;
    }

    u->resolved = ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_resolved_t));
    if (u->resolved == NULL) {
		return NGX_ERROR;
	}

	if (url.addrs && url.addrs[0].sockaddr){
		u->resolved->sockaddr = url.addrs[0].sockaddr;
		u->resolved->socklen = url.addrs[0].socklen;
		u->resolved->naddrs = 1;
		u->resolved->host = url.addrs[0].name;

	}else{
		u->resolved->host = url.host;
		u->resolved->port = (in_port_t) (url.no_port ? port : url.port);
		u->resolved->no_port = url.no_port;
	}
    return NGX_OK;
}

ngx_int_t
ngx_http_proxy_switch_set_var(ngx_http_request_t *r, 
		ngx_uint_t var_type, ngx_str_t *value)
{
	ngx_int_t							len = 0;
	ngx_http_proxy_switch_ctx_t			*ctx = NULL;

	ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_switch_module);
	if (ctx == NULL || value == NULL){
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
				"proxy switch set var %s", 
				ctx == NULL ? "ctx is null" : "input value wrong");
		return NGX_ERROR;
	}

	switch (var_type){
		case PROXY_SWITCH_VAR_PROTO:
			ctx->vars.proto = *value;
			break;
		case PROXY_SWITCH_VAR_HOST:
			ctx->vars.host = *value;
			ctx->vars.server = *value;
			break;
		case PROXY_SWITCH_VAR_PORT:
			ctx->vars.port = *value;
			if ((value->len != 0) 
					&& (((ngx_strncmp(ctx->vars.proto.data, "https", 5) == 0) 
							&& ((value->len != 3) 
								|| (ngx_strncmp(value->data, "443", 3) != 0)))
						|| ((ngx_strncmp(ctx->vars.proto.data, "http", 4) == 0)
							&& (ngx_strncmp(ctx->vars.proto.data, "https", 5) != 0)
							&& ((value->len != 2)
								|| (ngx_strncmp(value->data, "80", 2) != 0)))
						|| ((ngx_strncmp(ctx->vars.proto.data, "ftp", 3) == 0)
						|| (ngx_strncmp(value->data, "21", value->len) != 0)))){

				len = ctx->vars.host.len + value->len;
				ctx->vars.server.data = ngx_pcalloc(r->pool, len + 2);
				if (ctx->vars.server.data == NULL){
					ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
							"proxy switch set var pcalloc error");
					return NGX_ERROR;
				}

				ngx_snprintf(ctx->vars.server.data, len + 2 ,"%V:%V", 
						&ctx->vars.host, &ctx->vars.port);
				ctx->vars.server.len  = len + 1;

			}
			break;
		case PROXY_SWITCH_VAR_MAPID:
			ctx->vars.mapid = *value;
			break;
		default :
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
				"proxy switch set var unknown var type");
			return NGX_ERROR;
	}

	return NGX_OK;
}

ngx_int_t
ngx_http_proxy_switch_start(ngx_http_request_t *r)
{
	r->main->count++;
	ngx_http_upstream_init(r);

	return NGX_DONE;
}

