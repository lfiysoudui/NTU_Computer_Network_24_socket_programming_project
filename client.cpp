#include <iostream>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <poll.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <ncurses.h>
#undef OK
#include <fstream>
// #include <opencv2/opencv.hpp>

#define ERR_EXIT(a) do { perror(a); exit(1); } while(0)
#define BUFFER_SIZE 65536

typedef struct {
    char* ip; // server's ip
    unsigned short port; // server's port
    int conn_fd; // fd to talk with server
    char buf[BUFFER_SIZE]; // data sent by/to server
    size_t buf_len; // bytes used by buf
    SSL *ssl;
} client;

client cli;
void init_client(char** argv);
void check_login();
void clilogin();
void cliexit();
bool account_action();
bool checkstr(std::string item);
void print(char* buf, int len);
void initialize_openssl();
SSL_CTX *create_context();
void chatroom();
void sendfile();
void recvfile();
void stream_video();
void print(char* buf, int len);

char buffer[BUFFER_SIZE] = {0};

int main(int argc, char** argv){
    
    // Parse args.
    if(argc!=3){
        ERR_EXIT("usage: [ip] [port]");
    }

    // Handling connection
    initialize_openssl();
    SSL_CTX *ctx = create_context();
    init_client(argv);
    cli.ssl = SSL_new(ctx);
    SSL_set_fd(cli.ssl, cli.conn_fd);
    if (SSL_connect(cli.ssl) <= 0) {
        ERR_print_errors_fp(stderr);
    }
    fprintf(stdout, "connect to %s %d\n", cli.ip, cli.port);
    fflush(stdout);

    char choose[4];
    std::string choice_buf;
    int len = 14;
    bool login = false;
    bool online = true;
    online = true;
    while(online){
        if(!login) {
            check_login();
            login = true;
        }
        std::cout << "\nplease choose the action";
        std::cout << "\n1. account";
        std::cout << "\n2. chatroom";
        std::cout << "\n3. send file";
        std::cout << "\n4. receive file";
        std::cout << "\n5. stream video";
        std::cout << "\n6. exit";
        std::cout << std::endl;
        getline(std::cin,choice_buf);
        std::cout << "input: " << choice_buf << std::endl;
        switch (choice_buf[0])
        {
            case '1':
                login = account_action();
                break;
            
            case '2':
                chatroom();
                break;
            
            case '3':
                sendfile();
                break;
            
            case '4':
                recvfile();
                break;
            
            case '5':
                stream_video();
                break;
            
            case '6':
                online = false;
                len = 5;
                strcpy(buffer,"EXIT\0");
                SSL_write(cli.ssl, &len, sizeof(int));
                SSL_write(cli.ssl, buffer, len);
                break;
            
            default:
                std::cout << "error" << std::endl;
                break;
        }
    }
    std::cout << "goodbye" << std::endl;

    SSL_free(cli.ssl);
    close(cli.conn_fd);
    SSL_CTX_free(ctx);
    return 0;
}



void init_client(char** argv){
    
    cli.ip = argv[1];

    if(atoi(argv[2])==0 || atoi(argv[2])>65536){
        ERR_EXIT("Invalid port");
    }
    cli.port=(unsigned short)atoi(argv[2]);

    struct sockaddr_in servaddr;
    cli.conn_fd = socket(AF_INET, SOCK_STREAM, 0);
    if(cli.conn_fd<0){
        ERR_EXIT("socket");
    }

    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(cli.port);

    if(inet_pton(AF_INET, cli.ip, &servaddr.sin_addr)<=0){
        ERR_EXIT("Invalid IP");
    }

    if(connect(cli.conn_fd, (struct sockaddr*)&servaddr, sizeof(servaddr))<0){
        ERR_EXIT("connect");
    }

    return;
}

void check_login () {
    int len = 12;
    strcpy(buffer, "CHECK_LOGIN\0");

    SSL_write(cli.ssl, &len, sizeof(int));
    SSL_write(cli.ssl, buffer, len);
    SSL_read(cli.ssl, &len, sizeof(int));
    SSL_read(cli.ssl, buffer, len);

    if(!strcmp(buffer, "LOGIN_PLS\0")) {
        clilogin();
    }
}

void clilogin(){
    while (1)
    {
        std::cout << "please [L]ogin or [R]egister a new account \n> ";
        std::string input_0;
        std::string input_1;
        getline(std::cin, input_0);
        if (input_0[0] == 'R' || input_0[0] == 'r') {
            std::cout << "Username: ";
            getline(std::cin, input_0);
            std::cout << "Password: ";
            getline(std::cin, input_1);
            if (checkstr(input_0) || checkstr(input_1)) {
                std::cout << "Contain invalid charaters, check if the string contain space?" << std::endl;
                continue;
            }
            if (input_0.length() > 32 || input_1.length() > 32) {
                std::cout << "The length is restricted to 32 characters." << std::endl;
                continue;
            }
            int len = 8;
            strcpy(buffer, "REG_REQ\0");
            strcpy(&buffer[len], input_0.c_str());
            len += input_0.length() + 1;
            strcpy(&buffer[len], input_1.c_str());
            len += input_1.length() + 1;
            SSL_write(cli.ssl, &len, sizeof(int));
            SSL_write(cli.ssl, buffer, len);
            SSL_read(cli.ssl, &len, sizeof(int));
            SSL_read(cli.ssl, buffer, len);

            if (!strcmp(buffer, "REG_SUCCESS")){
                std::cout << "Registered successfully" << std::endl;
                continue;
            }
            else if (!strcmp(buffer, "USRNAME_ERR"))
                std::cout << "The username is used, please retry." << std::endl;

            else if (!strcmp(buffer, "ERR"))
                std::cout << "No empty slot for new user, QQ." << std::endl;

            else 
                std::cout << "Some error has occured, please retry" << std::endl;
        }
        else if (input_0[0] == 'L' || input_0[0] == 'l') {
            std::cout << "Username: ";
            getline(std::cin, input_0);
            std::cout << "Password: ";
            getline(std::cin, input_1);

            int len = 10;
            strcpy(buffer, "LOGIN_REQ\0");
            strcpy(&buffer[len], input_0.c_str());
            len += input_0.length() + 1;
            strcpy(&buffer[len], input_1.c_str());
            len += input_1.length() + 1;
            SSL_write(cli.ssl, &len, sizeof(int));
            SSL_write(cli.ssl, buffer, len);
            SSL_read(cli.ssl, &len, sizeof(int));
            SSL_read(cli.ssl, buffer, len);
            if (!strcmp(buffer, "LOGIN_SUCCESS")){
                std::cout << "Logged in successfully" << std::endl;
                break;
            }
            else if (!strcmp(buffer, "USRNAME_ERR"))
                std::cout << "User not found" << std::endl;

            else if (!strcmp(buffer, "PASSWD_ERR"))
                std::cout << "Password incorect" << std::endl;

            else 
                std::cout << "Some error has occured, please retry" << std::endl;
        }
    }
    

    
}

bool account_action() {
    std::string choice_buf;
    std::cout << "\nplease choose the option";
    std::cout << "\n1. logout";
    std::cout << "\n2. delete accout";
    std::cout << "\n3. return";
    std::cout << "\n> ";
    getline(std::cin,choice_buf);
    int len = 15;
    std::string input;
    switch (choice_buf[0]) {
        case '1':
            len = 7;
            strcpy(buffer,"LOGOUT\0");

            SSL_write(cli.ssl, &len, sizeof(int));
            SSL_write(cli.ssl, buffer, len);
            SSL_read(cli.ssl, &len, sizeof(int));
            SSL_read(cli.ssl, buffer, len);
                        
            if (strcmp(buffer,"LOGOUT_SUCCESS"))
                std::cout << "Some error has occured, please retry" << buffer << std::endl;
            return false;

        case '2':
            std::cout << "password:";
            getline(std::cin, input);
            len = 15;
            strcpy(buffer,"DELETE_ACCOUNT\0");
            strcpy(&buffer[len], input.c_str());
            len += input.length() + 1;

            SSL_write(cli.ssl, &len, sizeof(int));
            SSL_write(cli.ssl, buffer, len);
            SSL_read(cli.ssl, &len, sizeof(int));
            SSL_read(cli.ssl, buffer, len);

            if (!strcmp(buffer,"PASSWD_ERR"))
                std::cout << "The password is wrong" << std::endl;
            if (!strcmp(buffer,"DELETE_SUCCESS")) {
                std::cout << "The account is deleted" << std::endl;
                return false;
            }
            else {
                std::cout << "Some error has occured, please retry" << buffer << std::endl;
                return true;
            }

        case '3':
            break;
        
        default:
            std::cout << "input error";
            break;
    }
    return true;
}

bool checkstr (std::string item) {
    for (int i = 0; i < item.length(); i++)
        if (item[i] < 32) 
            return true;
    return false;
}

void print(char* buf, int len) {
    for(int i = 0; i < len; ++i) {
        printf("%c", buf[i]);
    }
    printf("\n");
    fflush(stdout);
}

void initialize_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

SSL_CTX *create_context() {
    const SSL_METHOD *method = SSLv23_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

void chatroom() {
    strcpy(buffer,"CHATROOM\0");
    int len = 9;

    char snd_header[BUFFER_SIZE];
    int header_len = 0;
    {
        std::string msg_tg;
        std::cout << "Message to:";
        getline(std::cin, msg_tg);
        strcpy(&snd_header[header_len],msg_tg.c_str());
        header_len += msg_tg.length();
        strcpy(&snd_header[header_len],"\0");
        header_len += 1;
    }
    strcpy(&buffer[len],snd_header);
    len += header_len;
    SSL_write(cli.ssl, &len, sizeof(int));
    SSL_write(cli.ssl, buffer, len);
    SSL_read(cli.ssl, &len, sizeof(int));
    SSL_read(cli.ssl, buffer, len);
    if(!strcmp(buffer,"USR_NOT_FOUND\0")) {
        std::cout << "user not found" << std::endl;
        return;
    }
    else if(!strcmp(buffer,"USR_NOT_ONLINE\0")) {
        std::cout << "user not online" << std::endl;
        return;
    }
    else if(strcmp(buffer,"PLEASE_SEND\0") != 0) {
        std::cout << "error" << std::endl;
        print(buffer,len);
        return;
    }
    // initiate sending window
        // Initialize ncurses
    initscr();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    nodelay(stdscr, TRUE);

    int rows, cols;
    getmaxyx(stdscr, rows, cols);

    // Define window dimensions
    int inputHeight = 3;
    int messageHeight = rows - inputHeight;

    // Create windows
    WINDOW *messageWin = newwin(messageHeight, cols, 0, 0);
    WINDOW *inputWin = newwin(inputHeight, cols, messageHeight, 0);

    keypad(inputWin, TRUE);
    nodelay(inputWin, TRUE);

    // Enable scrolling for the message window
    scrollok(messageWin, TRUE);

    // Input and message history
    std::string input;
    std::vector<std::string> messages;

    // Scroll offset
    int scrollOffset = 0;
    int V_TTL_MSG = 0;


    struct pollfd h_poll[1];
    h_poll[0].fd = cli.conn_fd;
    h_poll[0].events = POLLIN;
    int ct = 0;

    while (true) {
        // Display messages
        werase(messageWin);
        int totalMessages = messages.size();
        int visibleMessages = messageHeight;

        // Adjust the scroll offset to stay within bounds
        if (scrollOffset < 0) {
            scrollOffset = 0;
        } else if (scrollOffset > totalMessages + V_TTL_MSG - visibleMessages) {
            scrollOffset = totalMessages + V_TTL_MSG - visibleMessages;
        }
        if (scrollOffset < 0) scrollOffset = 0;

        // Print messages based on scroll offset
        int startLine = scrollOffset;
        int msgn = startLine;
        for (int i = 0; i < visibleMessages; i++) {
            if (msgn < totalMessages) {
                mvwprintw(messageWin, i, 0, "%s", messages[msgn].c_str());
                i += (messages[msgn].length() / cols);
                msgn++;
            }
        }
        wrefresh(messageWin);

        // Display the input bar
        werase(inputWin);
        mvwprintw(inputWin, 1, 1, "> %s", input.c_str());
        wrefresh(inputWin);
        // Handle the message from server
        int ret = poll(h_poll, 1, 100);
        if (ret > 0 && (h_poll[0].revents & POLLIN)) {
            SSL_read(cli.ssl, &len, sizeof(int));
            SSL_read(cli.ssl, buffer, len);
            V_TTL_MSG += (std::string(buffer,len).length()-1)/cols;
            messages.push_back(std::string(buffer,len));
            scrollOffset = totalMessages + V_TTL_MSG - visibleMessages + 1;
            if (scrollOffset < 0) scrollOffset = 0;
            werase(messageWin);
            continue;
        }
        else{
            // Handle input
            int ch = wgetch(inputWin);
            if (ch == 10) { // Enter key
                if (input == "quit") {
                    strcpy(buffer,"LEAVE\0");
                    len = 6;
                    SSL_write(cli.ssl, &len, sizeof(int));
                    SSL_write(cli.ssl, buffer, len);
                    break;
                }
                if (!input.empty()) {
                    // Send the message to server
                    strcpy(buffer,snd_header);
                    len = header_len;
                    strcpy(&buffer[len],input.c_str());
                    len += input.length()+1;
                    std::cout << input << std::endl;
                    buffer[len-1] = '\0';
                    SSL_write(cli.ssl, &len, sizeof(int));
                    SSL_write(cli.ssl, buffer, len);

                    // Add the message to the message history
                    input.insert(0, "You: ");
                    V_TTL_MSG += (input.length()-1)/cols;
                    messages.push_back(input);
                    input.clear();

                    // Reset scroll to show the latest message
                    scrollOffset = totalMessages + V_TTL_MSG - visibleMessages + 1;
                    if (scrollOffset < 0) scrollOffset = 0;
                }
            } else if (ch == KEY_BACKSPACE || ch == 127) { // Backspace
                if (!input.empty()) {
                    input.pop_back();
                }
            } else if (ch == KEY_UP) { // Scroll up
                scrollOffset--;
            } else if (ch == KEY_DOWN) { // Scroll down
                scrollOffset++;
            } else if (isprint(ch)) { // Printable characters
                input.push_back(ch);
            }
        }
    }

    // Cleanup
    delwin(messageWin);
    delwin(inputWin);
    endwin();
}

void sendfile() {
    std::string filename;
    std::string tg_name;
    std::cout << "Please enter the file name: ";
    getline(std::cin, filename);

    // Open the file to send
    std::ifstream infile(filename.c_str(), std::ios::binary);
    if (!infile) {
        std::cout << "Error opening file\n" << std::endl;
        return;
    }

    std::cout << "Please enter the client to send: ";
    getline(std::cin, tg_name);
    strcpy(buffer, "FILE_SEND\0");
    int len = 10;
    strcpy(&buffer[len], tg_name.c_str());
    len += tg_name.length() + 1;
    strcpy(&buffer[len], filename.c_str());
    len += filename.length() + 1;
    SSL_write(cli.ssl, &len, sizeof(int));
    SSL_write(cli.ssl, buffer, len);
    SSL_read(cli.ssl, &len, sizeof(int));
    SSL_read(cli.ssl, buffer, len);
    print(buffer,len);
    std::cout << len << std::endl;
    if(!strcmp(buffer,"USR_NOT_FOUND\0")) {
        std::cout << "user not found" << std::endl;
        return;
    }
    else if(!strcmp(buffer,"PLEASE_SEND\0")) {
        std::cout << "sending file" << std::endl;
        // Send the file length
        infile.seekg(0, std::ios::end);
        long int file_length = infile.tellg();
        infile.seekg(0, std::ios::beg);

        SSL_write(cli.ssl, &file_length, sizeof(long int));
        std::cout << "file length: " << file_length << std::endl;
        // Send the file in chunks
        while (infile.read(buffer, BUFFER_SIZE) || infile.gcount() > 0) {

            SSL_write(cli.ssl,  buffer, infile.gcount());
        }
        std::cout << "File sent successfully\n";
        return;
    }
    else {
        std::cout << "error" << std::endl;
        print(buffer,len);
        return;
    }
}

void recvfile() {
    int len = 10;
    int file_cnt;
    strcpy(buffer, "RECV_FILE\0");
    SSL_write(cli.ssl, &len, sizeof(int));
    SSL_write(cli.ssl, buffer, len);
    SSL_read(cli.ssl, &file_cnt, sizeof(int));
    std::cout << "Received " << file_cnt << " files" << std::endl;
    for (int i = 0; i < file_cnt; i++) {
        SSL_read(cli.ssl, &len, sizeof(int));
        SSL_read(cli.ssl, buffer, len);
        std::string filename(buffer,len);
        std::cout << "Receiving file: " << filename << std::endl;
        std::ofstream outfile(filename.c_str(), std::ios::binary);
        long int file_length;
        SSL_read(cli.ssl, &file_length, sizeof(long int));
        int bytes_received;
        while ((bytes_received = SSL_read(cli.ssl, buffer, BUFFER_SIZE)) > 0) {
            std::cout << "bytes_received: " << bytes_received << std::endl;
            file_length -= bytes_received;
            outfile.write(buffer, bytes_received);
            if (file_length <= 0) break;
        }
    }
    std::cout << "File received successfully\n" << std::endl;
}

void stream_video(){
    std::string filename;
    std::cout << "Please enter the file name: ";
    getline(std::cin, filename);
    strcpy(buffer, "STREAMING\0");
    int len = 10;
    strcpy(&buffer[len], filename.c_str());
    len += filename.length() + 1;
    SSL_write(cli.ssl, &len, sizeof(int));
    SSL_write(cli.ssl, buffer, len);
    SSL_read(cli.ssl, &len, sizeof(int));
    SSL_read(cli.ssl, buffer, len);
    if(!strcmp(buffer,"FILE_NOT_FOUND\0")) {
        std::cout << "file not found" << std::endl;
        return;
    }
    else if(!strcmp(buffer,"FILE_FOUND\0")) {
        int port;
        SSL_read(cli.ssl, &port, sizeof(int));
        std::cout << "streaming in new window" << std::endl;
        std::string stream_command = "ffplay -loglevel quiet udp://127.0.0.1:" + std::to_string(23456) + " &";
        system(stream_command.c_str());
        sleep(1);
        len = 6;
        strcpy(buffer,"READY\0");
        SSL_write(cli.ssl, &len, sizeof(int));
        SSL_write(cli.ssl, buffer, len);
        return;
    }
    else {
        std::cout << "error" << std::endl;
        print(buffer,len);
        return;
    }
}