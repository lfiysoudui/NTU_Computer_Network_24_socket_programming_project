CC=g++
LOCAL= -I/opt/local/include -L/opt/local/libexec/openssl3/lib/
CFLAGS= -lncurses -lssl -lcrypto

.PHONY: clean

all: server.cpp client.cpp
	$(CC) $(LOCAL) $(CFLAGS) -o server server.cpp
	$(CC) $(LOCAL) $(CFLAGS) -o client client.cpp

test: test.cpp
	$(CC) $(LOCAL) $(CFLAGS) -o test test.cpp

clean:
	rm -f server client