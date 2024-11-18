#include <iostream>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <iomanip>


#define ERR_EXIT(a) do { perror(a); exit(1); } while(0)
#define LOG_PATH "./server_log"

#define MAX_CLIENTS 20
#define BUFFER_SIZE 4096
#define USRNAME_MAX 64
#define USRPASSWD_MAX 64

typedef struct {
    char hostname[512];  // server's hostname
    unsigned short port;  // port to listen
    int listen_fd;  // fd to wait for a new connection
} server;

typedef struct {
    bool empty;
    char username[32];
    char password[64];
} Client;

class clients{
    private:
        Client *clientlist;
        int client_list_size;
    public:
        clients(){
            client_list_size = MAX_CLIENTS;
            clientlist = (Client*) malloc(client_list_size * sizeof(Client));
            for (int i = 0; i < client_list_size; ++i) clientlist[i].empty = true;
        }

        // 0 for success, 1 for no empty slots, 2 for unavailable username
        int newclient (std::string usrname, std::string passwd) {
            for (int i = 0; i < client_list_size; ++i) {
                if (!clientlist[i].empty && strcmp(usrname.c_str(),clientlist[i].username) == 0) {
                    std::cout << "[CLIENT]\nThe username is same as user <" << i << ">" << std::endl;
                    return 2;
                }
            }
            for (int i = 0; i < client_list_size; ++i) {
                if (clientlist[i].empty) {
                    strcpy(clientlist[i].username, usrname.c_str());
                    strcpy(clientlist[i].password, passwd.c_str());
                    clientlist[i].empty = false;
                    std::cout << "[CLIENT]\nRegistered, user no. <" << i << ">" << std::endl;
                    return 0;
                }
            }
            std::cout << "[CLIENT]\nNo empty slots" << std::endl;
            return 1;
        }

        // userno for success, -1 for wrong password, -2 for user not found
        int login (std::string usrname, std::string passwd) {
            for (int i = 0; i < client_list_size; ++i) {
                if (strcmp(usrname.c_str(), clientlist[i].username) == 0 && !clientlist[i].empty) {
                    if (strcmp(passwd.c_str(), clientlist[i].password) == 0) {
                        std::cout << "[CLIENT]\nLogged in as <" << clientlist[i].username << ">" << std::endl;
                        return i;
                    }
                    else {
                        std::cout << "[CLIENT]\nPassword error when user " << i << " logged in." << std::endl;
                        return -1;
                    }
                }
            }
            std::cout << "[CLIENT]\nCan't find user" << std::endl;
            return -2;
        }
        // 0 for success, 1 for wrong password
        int delclient (int usrno, std::string passwd) {
            if (strcmp(passwd.c_str(), clientlist[usrno].password) == 0) {
                clientlist[usrno].empty = true;
                return 0;
            }
            else {
                return 1;
            }
        }
};

typedef struct {
    int usrno;
    char host[512];  // client's host
    int conn_fd;  // fd to talk with client
    char buf[BUFFER_SIZE];  // data sent by/to client
    size_t buf_len;  // bytes used by buf
    int id;
} request;


//* globlal variables
server svr;  // server
request* requestP = NULL;  // point to a list of requests
int maxfd;  // size of open file descriptor table, size of request list


static void init_server(unsigned short port);

// initailize a request instance
static void init_request(request* reqP);

// free resources used by a request instance
static void free_request(request* reqP);

static void print(char* buf, int len);


//*====================================main function====================================
int main(int argc, char ** argv){
    // open the logfile
    freopen( LOG_PATH, "w", stderr);

    // check if the port is given
    struct sockaddr_in cliaddr;  // used by accept()
    int clilen;

    int conn_fd;  // fd for a new connection with client
    int file_fd;  // fd for file that we open for reading
    char buf[BUFFER_SIZE];
    int buf_len;

    // check if port is provided, initialize server
    if (argc != 2 ) {
        fprintf(stderr,"usage: [port], using default port 40311\n");
        fflush(stderr);
        init_server((unsigned short) 40311);
    }
    else init_server((unsigned short) atoi(argv[1]));
    // Loop for handling connections
    fprintf(stdout, "\nstarting on %.80s, port %d, fd %d, maxconn %d...\n", svr.hostname, svr.port, svr.listen_fd, maxfd);
    fflush(stdout);

    // setup to store client informations
    clients accounts;

    // setup pollfd for polling
    struct pollfd clipoll[MAX_CLIENTS+2];
    char clibuf[MAX_CLIENTS][BUFFER_SIZE];
    for(int i = 0; i < MAX_CLIENTS+2; i++){
        clipoll[i].fd = -1;
        clipoll[i].events = POLLIN;
    }
    clipoll[0].fd = svr.listen_fd; 
    fprintf(stdout, "start listening on fd %d\n", svr.listen_fd);
    fflush(stdout);
    while (1) {
        int pp = poll(clipoll, MAX_CLIENTS+2, -1);
        // Check new connection
        if(clipoll[0].revents == POLLIN){
            fprintf(stdout, "getting new request\n");
            fflush(stdout);
            clilen = sizeof(cliaddr);
            conn_fd = accept(svr.listen_fd, (struct sockaddr*)&cliaddr, (socklen_t*)&clilen);
            if (conn_fd < 0) {
                if (errno == EINTR || errno == EAGAIN) continue;  // try again
                if (errno == ENFILE) {
                    fprintf(stderr, "out of file descriptor table ... (maxconn %d)\n", maxfd);
                    continue;
                }
                ERR_EXIT("accept");
            }
            requestP[conn_fd].conn_fd = conn_fd;
            requestP[conn_fd].usrno = -1;
            strcpy(requestP[conn_fd].host, inet_ntoa(cliaddr.sin_addr));
            fprintf(stdout, "getting a new request... fd %d from %s\n", conn_fd, requestP[conn_fd].host);
            fflush(stdout);
            for(int i = 1; i < MAX_CLIENTS+2; i++){
                if(clipoll[i].fd == -1){
                    clipoll[i].fd = conn_fd;
                    break;
                }
            }
        }
        //check input
        for(int i = 1; i < MAX_CLIENTS + 2; i++){
            if (clipoll[i].revents & POLLIN){
                int len;
                if(recv(clipoll[i].fd, &len, sizeof(int), 0) <= 0){
                    std::cout << "\n[CLI_LEFT][";
                    std::cout << std::setw(3) << i;
                    std::cout << "]"<< std::endl;
                    int fd = clipoll[i].fd;
                    close(requestP[fd].conn_fd);
                    free_request(&requestP[fd]);
                    clipoll[i].fd = -1;
                    continue;
                }
                recv(clipoll[i].fd, requestP[clipoll[i].fd].buf, len, 0);
                std::cout << "\n[MSG_RECV][";
                std::cout << std::setw(3) << i ;
                std::cout << "][usr" ;
                std::cout << std::setw(3) << requestP[clipoll[i].fd].usrno;
                std::cout << "]len: " << len << std::endl;
                print(requestP[clipoll[i].fd].buf,len);

                //if not logged in
                if (requestP[clipoll[i].fd].usrno == -1) {
                    if (!strcmp(requestP[clipoll[i].fd].buf, "REG_REQ")) {
                        len = 8;
                        std::string usrname(&requestP[clipoll[i].fd].buf[len]);
                        len += usrname.length() + 1;
                        std::string passwd(&requestP[clipoll[i].fd].buf[len]);
                        switch (accounts.newclient(usrname, passwd)) {
                            case 0:
                                len = 12;
                                strcpy(buf,"REG_SUCCESS\0");
                                break;
                            case 1:
                                len = 4;
                                strcpy(buf,"ERR\0");
                                break;
                            case 2:
                                len = 12;
                                strcpy(buf,"USRNAME_ERR\0");
                                break;
                            default:
                                len = 10;
                                strcpy(buf,"PLZ_RETRY\0");
                                break;
                        }
                        send(clipoll[i].fd, &len, sizeof(int), 0);
                        send(clipoll[i].fd, buf, len, 0);
                    }
                    else if (!strcmp(requestP[clipoll[i].fd].buf, "LOGIN_REQ")) {
                        len = 10;
                        std::string usrname(&requestP[clipoll[i].fd].buf[len]);
                        len += usrname.length() + 1;
                        std::string passwd(&requestP[clipoll[i].fd].buf[len]);
                        int tmp = accounts.login(usrname, passwd);
                        switch (tmp) {
                            case -1:
                                len = 11;
                                strcpy(buf,"PASSWD_ERR\0");
                                break;
                            case -2:
                                len = 12;
                                strcpy(buf,"USRNAME_ERR\0");
                                break;
                            default:
                                len = 14;
                                requestP[clipoll[i].fd].usrno = tmp;
                                strcpy(buf,"LOGIN_SUCCESS\0");
                                break;
                        }
                        send(clipoll[i].fd, &len, sizeof(int), 0);
                        send(clipoll[i].fd, buf, len, 0);
                    }
                    else {
                        len = 10;
                        strcpy(buf, "LOGIN_PLS\0");
                        send(clipoll[i].fd, &len, sizeof(int), 0);
                        send(clipoll[i].fd, buf, len * sizeof(char), 0);
                    }
                }
                else {
                    if (!strcmp(requestP[clipoll[i].fd].buf, "DELETE_ACCOUNT")) {
                        len = 10;
                        std::string passwd(&requestP[clipoll[i].fd].buf[14]);
                        switch (accounts.delclient(requestP[clipoll[i].fd].usrno, passwd)) {
                            case 1:
                                len = 11;
                                strcpy(buf,"PASSWD_ERR\0");
                                break;
                            default:
                                requestP[clipoll[i].fd].usrno = -1;
                                len = 15;
                                strcpy(buf,"DELETE_SUCCESS\0");
                                break;
                        }
                        print(buf,len);
                        send(clipoll[i].fd, &len, sizeof(int), 0);
                        send(clipoll[i].fd, buf, len, 0);
                    }
                    else if (!strcmp(requestP[clipoll[i].fd].buf, "LOGOUT")) {
                        requestP[clipoll[i].fd].usrno = -1;
                        len = 15;
                        strcpy(buf,"LOGOUT_SUCCESS\0");
                        send(clipoll[i].fd, &len, sizeof(int), 0);
                        send(clipoll[i].fd, buf, len, 0);
                    }
                    else if (!strcmp(requestP[clipoll[i].fd].buf, "EXIT")) {
                        close(requestP[clipoll[i].fd].conn_fd);
                        free_request(&requestP[clipoll[i].fd]);
                        clipoll[i].fd = -1;
                        continue;
                    }
                    else {
                        len = 9;
                        strcpy(buf, "LOGGEDIN\0");
                        send(clipoll[i].fd, &len, sizeof(int), 0);
                        send(clipoll[i].fd, buf, len * sizeof(char), 0);
                    }
                }
            }
        }
    }

}

//*====================================functions====================================
static void init_request(request* reqP) {
    reqP->conn_fd = -1;
    reqP->buf_len = 0;
    reqP->id = 0;
    reqP->usrno = -1;
}

static void free_request(request* reqP) {
    init_request(reqP);
}

static void print(char* buf, int len) {
    for(int i = 0; i < len; ++i) {
        printf("%c", buf[i]);
    }
    printf("\n");
    fflush(stdout);
}

// initailize a server, exit for error
static void init_server(unsigned short port) {
    std::cout << "starting server\n";
    struct sockaddr_in servaddr;
    int tmp;
    
    gethostname(svr.hostname, sizeof(svr.hostname));
    svr.port = port;

    svr.listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (svr.listen_fd < 0) ERR_EXIT("socket");

    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(port);
    tmp = 1;
    if (setsockopt(svr.listen_fd, SOL_SOCKET, SO_REUSEADDR, (void*)&tmp, sizeof(tmp)) < 0) {
        ERR_EXIT("setsockopt");
    }
    if (bind(svr.listen_fd, (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0) {
        ERR_EXIT("bind");
    }
    if (listen(svr.listen_fd, 1024) < 0) {
        ERR_EXIT("listen");
    }

    // Get file descripter table size and initialize request table
    maxfd = getdtablesize();
    requestP = (request*) malloc(sizeof(request) * maxfd);
    if (requestP == NULL) {
        ERR_EXIT("out of memory allocating all requests");
    }
    for (int i = 0; i < maxfd; i++) {
        init_request(&requestP[i]);
    }
    requestP[svr.listen_fd].conn_fd = svr.listen_fd;
    strcpy(requestP[svr.listen_fd].host, svr.hostname);
    fflush(stdout);
    return;
}
