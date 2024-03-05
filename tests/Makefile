INCLUDE_DIR := /opt/homebrew/include
LIB_DIR := /opt/homebrew/Cellar/openssl@3/3.2.1/lib/

bn_dumps.txt.gz:
	gcc -Wall -o generate_bn_dumps generate_bn_dumps.c -lcrypto -lssl -I$(INCLUDE_DIR) -L$(LIB_DIR)
	./generate_bn_dumps | sort > bn_dumps.txt
	zopfli --gzip --i5000 -v bn_dumps.txt -c > $@
	rm generate_bn_dumps bn_dumps.txt
