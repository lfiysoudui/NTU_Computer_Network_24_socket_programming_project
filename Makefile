CC=g++
SSLFLAGS= -I/opt/local/include -L/opt/local/libexec/openssl3/lib/ -lssl

CFLAGS= -std=c++11 -lncurses  -lcrypto 

.PHONY: clean

all: server.cpp client.cpp
	$(CC) $(CFLAGS) $(SSLFLAGS)  -o server server.cpp 
	$(CC) $(CFLAGS) $(SSLFLAGS)  -o client client.cpp

clean:
	rm -f server client