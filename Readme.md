# Computer Network 2024 Socket Programming Final Project

## Overview
This project consists of a server (server.cpp) and a client (client.cpp). It supports:  
- User registration/login  
- File transfer  
- Chat functionality  
- Video streaming (requires ffmpeg on client side)

## Usage
### Server
```bash
./server <optional port>
```
After the server started, it will listen on the specified port.
### Client
```bash
./client <server ip> <server port>
```
The client will connect to the server with the specified ip and port.
After the client connected to the server, please follow the instruction to login or register.

## Features 
### User registration/login
- User can register with a username and password.
- User can login with the registered username and password.
- User can logout.
### File transfer
- User can upload a file to the server and later received by another receiver.
- User can download a file from the server uploaded by another uploader.
### Chat functionality
- User can chat with another logged in online user with a tui inter face.
    - scroll up and down with `up` and `down` arrow keys or scrolling with mouse/ trackpad.
- Quit the chat by typing `quit` and press enter.
### Video streaming
- User can stream any video file saved in the `files/to_stream` directory.
- The user only need to type the filename **without** `.mp4` in the `Please enter the file name:` section.


## Packege Requirements
- g++ (C++11 or later)  
- OpenSSL 3.1.3
- ncurses 0.29.2 
- ffmpeg  4.4.4 (client side only)

## Work Directory Structure when running the program
server.cpp
```bash

files/
    to_stream/
```

client.cpp
```bash
files_to_send
```

## Building
Use the provided Makefile:
```bash
make all
```