#include <iostream>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <poll.h>

#define ERR_EXIT(a) do { perror(a); exit(1); } while(0)
#define BUFFER_SIZE 4096

typedef struct {
    char* ip; // server's ip
    unsigned short port; // server's port
    int conn_fd; // fd to talk with server
    char buf[BUFFER_SIZE]; // data sent by/to server
    size_t buf_len; // bytes used by buf

} client;

client cli;
static void init_client(char** argv);
void check_login();
void clilogin();
void cliexit();
bool account_action();
bool checkstr(std::string item);
static void print(char* buf, int len);

char buffer[BUFFER_SIZE] = {0};

int main(int argc, char** argv){
    
    // Parse args.
    if(argc!=3){
        ERR_EXIT("usage: [ip] [port]");
    }

    // Handling connection
    init_client(argv);
    fprintf(stdout, "connect to %s %d\n", cli.ip, cli.port);
    fflush(stdout);
    char choose[4];
    std::string choice_buf;
    int len = 14;
    bool login = false;
    strcpy(buffer ,"HELLO,SERVER\0");
    send(cli.conn_fd, &len, sizeof(int), 0);
    send(cli.conn_fd, buffer, len, 0);
    bool online = true;
    if(recv(cli.conn_fd, &len, sizeof(int), 0) <= 0){
        close(cli.conn_fd);
        online = false;
    }
    else {
        recv(cli.conn_fd, buffer, len, 0);
        online = true;
    }
    while(online){
        if(!login) {
            check_login();
            login = true;
        }
        std::cout << "\nplease choose the action";
        std::cout << "\n1. account";
        std::cout << "\n2. exit";
        std::cout << std::endl;
        getline(std::cin,choice_buf);
        std::cout << "input: " << choice_buf << std::endl;
        switch (choice_buf[0])
        {
            case '1':
                login = account_action();
                break;
            
            case '2':
                online = false;
                len = 5;
                strcpy(buffer,"EXIT\0");
                send(cli.conn_fd, &len, sizeof(int), 0);
                send(cli.conn_fd, buffer, len, 0);
                break;
            
            default:
                std::cout << "error" << std::endl;
                break;
        }
    }
    std::cout << "goodbye" << std::endl;
    return 0;
}



static void init_client(char** argv){
    
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

    send(cli.conn_fd, &len, sizeof(int), 0);
    send(cli.conn_fd, buffer, len, 0);
    recv(cli.conn_fd, &len, sizeof(int), 0);
    recv(cli.conn_fd, buffer, len, 0);

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
            send(cli.conn_fd, &len, sizeof(int), 0);
            send(cli.conn_fd, buffer, len, 0);
            recv(cli.conn_fd, &len, sizeof(int), 0);
            recv(cli.conn_fd, buffer, len, 0);

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
            send(cli.conn_fd, &len, sizeof(int), 0);
            send(cli.conn_fd, buffer, len, 0);
            recv(cli.conn_fd, &len, sizeof(int), 0);
            recv(cli.conn_fd, buffer, len, 0);
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

            send(cli.conn_fd, &len, sizeof(int), 0);
            send(cli.conn_fd, buffer, len, 0);
            recv(cli.conn_fd, &len, sizeof(int), 0);
            recv(cli.conn_fd, buffer, len, 0);
                        
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

            send(cli.conn_fd, &len, sizeof(int), 0);
            send(cli.conn_fd, buffer, len, 0);
            recv(cli.conn_fd, &len, sizeof(int), 0);
            recv(cli.conn_fd, buffer, len, 0);

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

static void print(char* buf, int len) {
    for(int i = 0; i < len; ++i) {
        printf("%c", buf[i]);
    }
    printf("\n");
    fflush(stdout);
}