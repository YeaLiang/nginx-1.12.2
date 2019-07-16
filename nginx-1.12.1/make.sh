#!/bin/bash
./configure  --prefix=/home/dengjunxing/prefix-nginx  \
	--with-stream --with-http_stub_status_module \
	--with-http_realip_module \
	--with-http_v2_module \
	--with-debug \
	--add-module=../ngx_devel_kit-master \
	--add-module=./ngx_http_mytest_module
	#--add-module=./ngx_http_myfilter_module

	#--with-http_ssl_module \
	#--with-stream_ssl_module \
	#--add-module=./appone \
	#--with-openssl=/root/fusion/openssl-1.0.2r \
	#--with-pcre=../pcre-8.42 \
	#--add-module=../lua-nginx-module-master \
