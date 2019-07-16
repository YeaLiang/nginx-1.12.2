
default:	build

clean:
	rm -rf Makefile objs

build:
	$(MAKE) -f objs/Makefile

install:
	$(MAKE) -f objs/Makefile install

modules:
	$(MAKE) -f objs/Makefile modules

upgrade:
	/home/dengjunxing/prefix-nginx/sbin/nginx -t

	kill -USR2 `cat /home/dengjunxing/prefix-nginx/logs/nginx.pid`
	sleep 1
	test -f /home/dengjunxing/prefix-nginx/logs/nginx.pid.oldbin

	kill -QUIT `cat /home/dengjunxing/prefix-nginx/logs/nginx.pid.oldbin`
