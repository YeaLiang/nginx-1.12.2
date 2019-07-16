
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_appcore.h>

ngx_buf_t* 
ngx_http_get_request_body(ngx_http_request_t* r)
{
	size_t		len = 0;
	ngx_chain_t	*cl = NULL;
	ngx_buf_t	*buf = NULL;

	if (r->request_body == NULL
			|| r->request_body->bufs == NULL
			|| r->request_body->temp_file) {
		ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, 
			"request body is invalid.");
		return NULL;
	}

	cl = r->request_body->bufs;
	buf = cl->buf;

	if (cl->next == NULL) {
		//only one chain
		return buf;
	}

	len = buf->last - buf->pos;
	cl = cl->next;

	for ( /* void */ ; cl; cl = cl->next) {
		buf = cl->buf;
		len += buf->last - buf->pos;
	}

	buf = ngx_create_temp_buf(r->pool, len);
	if (NULL == buf) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
			"create temp buf failed.");
		return NULL;
	}

	cl = r->request_body->bufs;

	for (cl = r->request_body->bufs; cl; cl = cl->next) {
		len = cl->buf->last - cl->buf->pos;
		buf->last = ngx_cpymem(buf->last, cl->buf->pos, len);
	}

	return buf;
}

ngx_int_t
ngx_http_parse_uri_value(ngx_http_request_t *r, 
		ngx_str_t *uri, ngx_uint_t no, ngx_str_t *value, ngx_str_t *rest)
{
	ngx_uint_t 	i = 0, len = 0;
	u_char 		*start = NULL, *end = NULL, *tmp = NULL;
	ngx_str_t	*uri_tmp = NULL;
	
	if (uri == NULL){
		uri_tmp = &r->unparsed_uri;
	}else{
		uri_tmp = uri;
	}

//	value->len = 0;
//	rest->len = 0;

	if(uri_tmp->len == 0) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
			"request unparsed uri empty error.");
		return NGX_ERROR;
	}

	start = uri_tmp->data;
	end = start + uri_tmp->len;

	tmp = (u_char*)ngx_strlchr(start,end,' ');
	if (tmp != NULL){
		len = tmp - start;
	}else{
		len = uri_tmp->len;
	}

	if (len <= 0) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
			"request unparsed uri format error.");
		return NGX_ERROR;
	}

	if (no == 0) {
		value->data = start;
		value->len = len;
		return NGX_OK;
	}

	tmp = start;
	for (i = 0; i < no; i ++) {
		tmp = (u_char*)ngx_strchr(tmp,'/');
		if (tmp == NULL || (tmp > start + len)){
			ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, 
				"request unparsed uri no:%d not found error.", no);
			return NGX_ERROR;
		}
		tmp ++;
	}

	value->data = tmp;
	tmp = (u_char*)ngx_strchr(tmp,'/');
	if (tmp == NULL || (tmp > start + len)){
		value->len = start + len - value->data;
		return NGX_OK;
	}

	value->len = tmp - value->data;

	if (rest) {
		rest->data = tmp;
		rest->len = start + len - tmp;
	}

	return NGX_OK;
}

ngx_int_t
ngx_http_external_redirect(ngx_http_request_t *r, ngx_str_t *url)
{
	ngx_table_elt_t	*location = NULL;
	ngx_table_elt_t	*host = NULL;
	ngx_str_t loc = ngx_null_string;
	u_char *p = NULL;

	if (url == NULL || url->len == 0){
		return NGX_ERROR;
	}

	host = r->headers_in.host;

	if (NULL == host 
			|| host->value.len == 0) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
				"not found HOST header");
		return NGX_ERROR;
	}

	loc.len = sizeof("https://") -1 
		+ host->value.len + url->len;
	loc.data = ngx_pcalloc(r->pool, loc.len);
	if (NULL == loc.data) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
				"not found HOST header");
		return NGX_ERROR;	
	}
	p = loc.data;

	if (r->connection->ssl) {
		p = ngx_cpymem(p, "https://", sizeof("https://") - 1);	
	} else {
		p = ngx_cpymem(p, "http://", sizeof("http://") - 1);	
	}
	p = ngx_cpymem(p, host->value.data, host->value.len);
	p = ngx_cpymem(p, url->data, url->len);
	
	loc.len = p - loc.data;

	location = ngx_list_push(&r->headers_out.headers);
	if (NULL == location) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
				"array push for location failed.");
		return NGX_ERROR;
	}
	location->hash = 1;
	ngx_str_set(&location->key, "Location");
	location->value = loc;

	ngx_http_clear_location(r);
	r->headers_out.location = location;
	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
			"redirect Location is %V.", &location->value);

	r->headers_out.status = NGX_HTTP_MOVED_TEMPORARILY;
	r->headers_out.content_length_n = 0;
	r->header_only = 1;

	ngx_http_finalize_request(r, ngx_http_send_header(r));
	return NGX_OK;
}

/* 
 * NOTE: the buf returned is alloc in temp_pool 
 */
ngx_buf_t *
ngx_http_conf_read_file(ngx_conf_t *cf, ngx_str_t* name, ngx_int_t istemp)
{
	ngx_buf_t* b = NULL;
	ngx_file_info_t finfo;
	ngx_file_t file;
	ngx_int_t n = 0;

	if (ngx_file_info(name->data, &finfo) < 0) {
		ngx_conf_log_error(NGX_LOG_ERR, cf, 0, 
				"file info %s failed.", name->data);
		return NULL;
	}

	if (!finfo.st_size) {
		ngx_log_error(NGX_LOG_ERR, cf->log, 0, 
				"file %s size is zero.", name->data);
		return NULL;
	}
#if 0
	if (finfo.st_size > NGX_HTTP_THEME_VARIABLE_TPL_MAX_SIZE) {
		ngx_log_error(NGX_LOG_ERR, cf->log, 0, 
				"file %s size(%d) more than max(%d) size.", name->data, 
				finfo.st_size, NGX_HTTP_THEME_VARIABLE_TPL_MAX_SIZE);
		return NULL;
		
	}
#endif

	if (istemp) {
		b = ngx_create_temp_buf(cf->temp_pool, finfo.st_size);
	} else {
		b = ngx_create_temp_buf(cf->pool, finfo.st_size);
	}
	if (NULL == b) {
		ngx_log_error(NGX_LOG_ERR, cf->log, 0, 
				"create temp buf %d failed.", finfo.st_size);
		return NULL;
	}
	
	ngx_memzero(&file, sizeof(ngx_file_t));

	file.name = *name;
	file.log = cf->log;

	file.fd = ngx_open_file(file.name.data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 
			NGX_FILE_DEFAULT_ACCESS);
	if (NGX_INVALID_FILE == file.fd) {
		ngx_log_error(NGX_LOG_ERR, cf->log, 0, 
				"open file %s failed.", file.name.data);
		return NULL;
	}

	n = ngx_read_file(&file, b->pos, finfo.st_size, 0);	
	if (finfo.st_size != n) {
		ngx_log_error(NGX_LOG_ERR, cf->log, 0, 
				"theme read tpl file %s not enougth size.", file.name.data);
		return NULL;
	}

	b->last = b->pos + finfo.st_size;
	b->last_buf = 1;

	ngx_log_debug2(NGX_LOG_DEBUG_HTTP, cf->log, 0, 
			"file %s content:\n%s", file.name.data, b->pos);

	if (ngx_close_file(file.fd) == NGX_FILE_ERROR) {
		ngx_log_error(NGX_LOG_ALERT, cf->log, 0, 
				"theme close tpl file %s failed.", file.name.data);
	}
	
	return b;
}

ngx_int_t 
ngx_http_get_cookie_variable_index(ngx_conf_t *cf, ngx_str_t *name)
{
	ngx_str_t cookie_name = ngx_null_string;
	u_char *p = NULL;
	size_t size = 0;

	size = sizeof("cookie_") - 1 + name->len;
	p = ngx_pcalloc(cf->temp_pool, size);
	if (NULL == p) {
		ngx_conf_log_error(NGX_LOG_ERR, cf, 0,
				"alloc cookie_name \"%s%V\" failed", 
				"cookie_", name);
		return NGX_ERROR;
	}
	cookie_name.data = p;
	cookie_name.len = size;

	p = ngx_cpymem(p, "cookie_", sizeof("cookie_") - 1);
	ngx_memcpy(p, name->data, name->len);

	return ngx_http_get_variable_index(cf, &cookie_name);
}
