
#ifndef _NGX_HTTP_EXTRA_H_INCLUDE_
#define _NGX_HTTP_EXTRA_H_INCLUDE_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_appcore.h>

/* setof type */
#define NGX_SETOF(type, name) \
	struct { \
		type* 		elts; \
		ngx_uint_t 	nelts; \
	} name;

#define NGX_SETOF_ELTS(name) \
	name.elts
#define NGX_SETOF_NELTS(name) \
	name.nelts

#define NGX_SETOF_SIZE(name) \
	(name.nelts * sizeof(name.elts[0]))


/* http variable extra */
typedef struct {
	uintptr_t				data;
	uintptr_t				extra;
} ngx_http_variable_extra_t;

typedef struct {
	ngx_int_t				value;
	ngx_str_t				text;
} ngx_http_strvalue_t;

typedef struct {
	ngx_int_t				num;
	ngx_http_strvalue_t		*strvalues;
} ngx_http_strmap_t;

#define NGX_HTTP_VARIABLE_ENUM_STR_EXTRA(name, type, member, max) \
static ngx_http_strvalue_t	name##strvalues[max]; \
 \
static ngx_http_strmap_t name##strmap = { \
	.num = max, \
	.strvalues = name##strvalues \
}; \
 \
static ngx_http_variable_extra_t name = { \
	.data = offsetof(type, member), \
	.extra = (uintptr_t)&name##strmap \
}; \
static ngx_http_strvalue_t name##strvalues[max] 

#define NGX_BITOF(v) (1 << (v))

/* ngx http extra api */
ngx_buf_t *ngx_http_conf_read_file(ngx_conf_t *cf, ngx_str_t* name, 
		ngx_int_t istemp);

ngx_buf_t* ngx_http_get_request_body(ngx_http_request_t* r);

ngx_int_t ngx_http_parse_uri_value(ngx_http_request_t *r, 
		ngx_str_t *uri, ngx_uint_t no, ngx_str_t *value, ngx_str_t *rest);

ngx_int_t ngx_http_external_redirect(ngx_http_request_t *r, ngx_str_t *url);

ngx_int_t ngx_http_get_cookie_variable_index(ngx_conf_t *cf, ngx_str_t *name);

#endif

