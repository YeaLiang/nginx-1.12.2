#include <ngx_config.h>  
#include <ngx_core.h>  
#include <ngx_http.h>  
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include "cJSON.h"
int ngx_parse_json_get_filename(char *buf, int size, char *filename, int filename_len)
{
	if (!buf)
	{
		return -1;
	}

	cJSON* pRoot = cJSON_Parse(buf);
	cJSON* pgatewayConfig= cJSON_GetObjectItem(pRoot, "GatewayConfig");
	cJSON* ppackagename = cJSON_GetObjectItem(pgatewayConfig, "appName");
	memcpy(filename, ppackagename->valuestring, strlen(ppackagename->valuestring));

	return 1;
}

void ngx_response_fail(ngx_http_request_t *r)
{
	ngx_str_t type = ngx_string("text/html");
	r->headers_out.content_type = tyep;
	r->headers_out.status = NGX_HTTP_OK;

	ngx_str_t content = ngx_string("\
			{\
			\" Type \":1001,\
			\" Value \":{\
			\"result\":1,\
			\"msg\":\"失败\"
			}\
			}");

	r->headers_out.content_length_n = content.len;
	ngx_int_t rc = ngx_http_send_header(r);
	if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {  
		return ;//rc;  
	}  
}

void ngx_response_success(ngx_http_request_t *r)
{
	ngx_str_t type = ngx_string("text/html");
	r->headers_out.content_type = type;  
	r->headers_out.status = NGX_HTTP_OK;
	ngx_str_t content = ngx_string("\
			{\
			\" Type \":1001,\
			\" Value \":{\
			\"result\":0,\
			\"msg\":\"成功\"
			}\
			}");

	r->headers_out.content_length_n = content.len;
	ngx_int_t rc = ngx_http_send_header(r);  
	if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {  
		return ;//rc;  
	}  
	return ;
}

void ngx_http_mytest_body_handler(ngx_http_request_t *r) 
{ 

	if (!r || !r->request_body || !r->request_body->bufs || !r->request_body->bufs->buf)
	{
		return ;
	}

	int size = (r->request_body->bufs->buf->last - r->request_body->bufs->buf->pos);
	char *buf = malloc(size);
	memcpy(buf, r->request_body->bufs->buf->pos, size);
	if (!fp)
	{
		ngx_reponse_fail(r);
		ngx_log_stderr(0, " open hello.txt failured., errno:%d", errno);
	}

	char filename[80] = {0};
	ngx_parse_json_get_filename(buf, sizeof(filename), filename);

	FILE *fp = fopen("hello.txt", "ab+");
	fwrite(buf, size, 1, fp);
	fclose(fp);
	ngx_response_200(r);
	printf("size:%d\n", size);

	printf("handler \n");

} 

static ngx_int_t ngx_http_mytest_handler(ngx_http_request_t *r)
{
	printf("%s:%d ss.\n", __FUNCTION__, __LINE__);
	ngx_http_read_client_request_body(r, ngx_http_mytest_body_handler);
	return NGX_DONE;	
}

#if 0
static ngx_int_t ngx_http_mytest_handler(ngx_http_request_t *r)  
{
#if SRC_XX
	printf("%s:%d", __FUNCTION__, __LINE__);
	printf("%s:%d method:\n", __FUNCTION__, __LINE__);
	ngx_str_t type = ngx_string("text/plain");
	ngx_str_t response = ngx_string("Hello world");
	r->headers_out.status = NGX_HTTP_OK;
	r->headers_out.content_length_n = response.len;  
	r->headers_out.content_type = type;  


	ngx_int_t rc = ngx_http_send_header(r);  
	if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {  
		return rc;  
	}  

	ngx_buf_t *b;  
	b = ngx_create_temp_buf(r->pool, response.len);  
	if (b == NULL) {  
		return NGX_HTTP_INTERNAL_SERVER_ERROR;  
	}  
	ngx_memcpy(b->pos, response.data, response.len);  
	b->last = b->pos + response.len;  
	b->last_buf = 1;  

	ngx_chain_t out;  
	out.buf = b;  
	out.next = NULL;  

	return ngx_http_output_filter(r, &out);  
#else
	//必须是GET或者HEAD方法，否则返回405 Not Allowed
#if 0
	if (!(r->method & (NGX_HTTP_GET | NGX_HTTP_HEAD)))
	{
		return NGX_HTTP_NOT_ALLOWED;
	}
#endif 
	
	// 丢弃请求中的包体
	ngx_int_t rc = ngx_http_discard_request_body(r);
	if (rc != NGX_OK)
	{
		return rc;
	}
	ngx_buf_t *b;
	b = ngx_palloc(r->pool, sizeof(ngx_buf_t));

	u_char filename_arr[100];
	memset(filename_arr, 0, sizeof(filename_arr));
	memcpy(filename_arr, r->uri.data, r->uri.len);
	u_char* filename = (u_char*)"/home/dengjunxing/prefix-nginx/html/index.html";//filename_arr;//(u_char*)"/tmp/test.txt";
	b->in_file = 1;
	b->file = ngx_pcalloc(r->pool, sizeof(ngx_file_t));
	b->file->fd = ngx_open_file(filename, NGX_FILE_RDONLY | NGX_FILE_NONBLOCK, NGX_FILE_OPEN, 0);
	b->file->log = r->connection->log;
	b->file->name.data = filename;
	b->file->name.len = sizeof(filename) - 1;
	if (b->file->fd <= 0)
	{
		return NGX_HTTP_NOT_FOUND;
	}
	r->allow_ranges = 1;
	if (ngx_file_info(filename, &b->file->info) == NGX_FILE_ERROR)
	{
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}
	b->file_pos = 0;
	b->file_last = b->file->info.st_size;
	ngx_pool_cleanup_t* cln = ngx_pool_cleanup_add(r->pool, sizeof(ngx_pool_cleanup_file_t));
	if (cln == NULL)
	{
		return NGX_ERROR;
	}
	cln->handler = ngx_pool_cleanup_file;
	ngx_pool_cleanup_file_t  *clnf = cln->data;
	clnf->fd = b->file->fd;
	clnf->name = b->file->name.data;
	clnf->log = r->pool->log;

	ngx_str_t type = ngx_string("text/plain");
	r->headers_out.status = NGX_HTTP_OK;
	r->headers_out.content_length_n = b->file->info.st_size;
	r->headers_out.content_type = type;
	rc = ngx_http_send_header(r);
	if (rc == NGX_ERROR || rc > NGX_OK || r->header_only)
	{
		return rc;
	}
	ngx_chain_t     out;

	out.buf = b;
	out.next = NULL;
	return ngx_http_output_filter(r, &out);

#endif 
}
#endif

static char* ngx_http_mytest(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	printf("%s:%d", __FUNCTION__, __LINE__);
	ngx_http_core_loc_conf_t *clcf;
	clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
	 /*HTTP框架在处理用户请求进行到NGX_HTTP_CONTENT_PHASE阶段时，
	  * 如果请求的主机域名、URI与mytest配置项所在的配置块相匹配，就将调用我们实现的ngx_http_mytest_handler方法处理这个请求*/
	clcf->handler = ngx_http_mytest_handler;
	return NGX_CONF_OK;

}


static ngx_command_t ngx_http_mytest_commands[] = {
	{
	ngx_string("mytest"), 
	NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LMT_CONF | NGX_CONF_NOARGS,
	ngx_http_mytest, 
	NGX_HTTP_LOC_CONF_OFFSET, 
	0, 
	NULL
	},
	ngx_null_command
};

static ngx_http_module_t ngx_http_mytest_module_ctx = {
	NULL,  
	NULL,  
	NULL,  
	NULL,  
	NULL,  
	NULL,  
	NULL,  
	NULL  
};

ngx_module_t ngx_http_mytest_module = {
	NGX_MODULE_V1,  
	&ngx_http_mytest_module_ctx,  
	ngx_http_mytest_commands,  
	NGX_HTTP_MODULE,  
	NULL,  
	NULL,  
	NULL,  
	NULL,  
	NULL,  
	NULL,  
	NULL,  
	NGX_MODULE_V1_PADDING  

};


