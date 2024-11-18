CC=g++
CFLAGS=

.PHONY: clean

all: server.cpp client.cpp
	$(CC) $(CFLAGS) -o server server.cpp
	$(CC) $(CFLAGS) -o client client.cpp

clean:
	rm -f server client