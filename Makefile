CC=g++
SSLFLAGS= -I/opt/local/include -L/opt/local/libexec/openssl3/lib/ -lssl

CVFLAGS= -I/opt/homebrew/Cellar/opencv/4.10.0_15/include/opencv4 -L/opt/homebrew/Cellar/opencv/4.10.0_15/lib -lopencv_core -lopencv_highgui -lopencv_imgcodecs -lopencv_videoio -lopencv_imgproc


CFLAGS= -std=c++11 -lncurses  -lcrypto 

.PHONY: clean

all: server.cpp client.cpp
	$(CC) $(CFLAGS) $(SSLFLAGS)  -o server server.cpp 
	$(CC) $(CFLAGS) $(SSLFLAGS)  -o client client.cpp

test: test.cpp
	$(CC) $(SSLFLAGS) $(CFLAGS) -o test test.cpp

clean:
	rm -f server client