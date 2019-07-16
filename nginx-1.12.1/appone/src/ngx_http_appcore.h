
#ifndef _NGX_HTTP_APPCORE_H_INCLUDE_
#define _NGX_HTTP_APPCORE_H_INCLUDE_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <ngx_http_extra.h>

#define NGX_HTTP_APPCORE_LICENSE_USERNUM		0x01
#define NGX_HTTP_APPCORE_LICENSE_REMOTEUSERNUM	0x02
#define NGX_HTTP_APPCORE_LICENSE_ALL			0xFF

#define NGX_HTTP_APPCORE_ONE_LICENSE_CONNECTIONS_NUM_MIN 8

typedef struct {
	ngx_str_t 						gateway_version;
	ngx_str_t 						sid_cookie_name;
	ngx_str_t 						uname_cookie_name;
	ngx_str_t 						passwd_cookie_name;
	ngx_str_t 						appid_cookie_name;
	ngx_str_t 						server_cookie_name;
	ngx_str_t 						redirect_cookie_name;
	ngx_int_t 						sid_cookie_var_index;
	ngx_int_t 						appid_cookie_var_index;
	ngx_int_t 						server_cookie_var_index;
	ngx_int_t 						redirect_cookie_var_index;

	ngx_str_t 						appone_version;
	ngx_str_t 						client_version;
} ngx_http_appcore_srv_conf_t;

typedef struct {
	ngx_str_t 						login_default;
	ngx_str_t 						server_name;
	ngx_str_t 						jump_resource_id;
	
	ngx_str_t 						username_setcookie_fmt;
	ngx_array_t 					*username_setcookie_lengths;
	ngx_array_t 					*username_setcookie_values;
	
	ngx_str_t 						password_setcookie_fmt;
	ngx_array_t 					*password_setcookie_lengths;
	ngx_array_t 					*password_setcookie_values;
	
	ngx_str_t 						sid_setcookie_fmt;
	ngx_array_t 					*sid_setcookie_lengths;
	ngx_array_t 					*sid_setcookie_values;

	ngx_str_t 						appid_setcookie_fmt;
	ngx_array_t 					*appid_setcookie_lengths;
	ngx_array_t 					*appid_setcookie_values;

	ngx_str_t 						redirect_setcookie_fmt;
	ngx_array_t 					*redirect_setcookie_lengths;
	ngx_array_t 					*redirect_setcookie_values;

	ngx_str_t 						proxy_addr;

} ngx_http_appcore_loc_conf_t;

extern ngx_module_t ngx_http_appcore_module;

ngx_int_t ngx_http_appcore_get_sid(ngx_http_request_t *r, ngx_str_t *sid);
ngx_int_t ngx_http_appcore_get_servername(ngx_http_request_t *r, ngx_str_t *servername);
ngx_int_t ngx_http_appcore_get_appid_from_uri(ngx_http_request_t *r, 
		ngx_str_t *appid);
ngx_int_t ngx_http_appcore_get_appid_from_referer(ngx_http_request_t *r, 
		ngx_str_t *appid);
ngx_int_t ngx_http_appcore_get_appid_from_cookie(ngx_http_request_t *r, 
		ngx_str_t *appid);
ngx_int_t ngx_http_appcore_get_redirect(ngx_http_request_t *r, ngx_str_t *redirect);

char * ngx_http_appcore_error_itoa(ngx_http_request_t *r, ngx_int_t code, 
		uintptr_t data);

ngx_int_t ngx_http_appcore_license(ngx_conf_t *cf, ngx_int_t license);

ngx_int_t ngx_encode_aes(ngx_http_request_t *r, ngx_str_t *cipher,ngx_str_t *plain);
ngx_int_t ngx_decode_aes(ngx_http_request_t *r, ngx_str_t *plain,ngx_str_t *cipher);
#endif
