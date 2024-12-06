#include <iostream>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <poll.h>
#include <queue>
#include <iomanip>

#define ERR_EXIT(a) do { perror(a); exit(1); } while(0)
#define LOG_PATH "./server_log"

#define MAX_CLIENTS 10
#define BUFFER_SIZE 4096
#define USRNAME_MAX 64
#define USRPASSWD_MAX 64

//* ==================================== Struct ====================================

typedef struct {
    char hostname[512];  // server's hostname
    unsigned short port;  // port to listen
    int listen_fd;  // fd to wait for a new connection
} server;

typedef struct {
    bool empty;
    char username[32];
    char password[64];
    int confd;
} Client;

class clients{
    private:
        Client *clientlist;
        int client_list_size;
    public:
        clients(){
            client_list_size = MAX_CLIENTS;
            clientlist = (Client*) malloc(client_list_size * sizeof(Client));
            for (int i = 0; i < client_list_size; ++i) {
                clientlist[i].empty = true;
                clientlist[i].confd = -1;
            }
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

        // usrno for success, -1 for wrong password, -2 for user not found
        int login (std::string usrname, std::string passwd, int fd) {
            for (int i = 0; i < client_list_size; ++i) {
                if (strcmp(usrname.c_str(), clientlist[i].username) == 0 && !clientlist[i].empty) {
                    if (strcmp(passwd.c_str(), clientlist[i].password) == 0) {
                        std::cout << "[CLIENT]\nLogged in as <" << clientlist[i].username << ">" << std::endl;
                        clientlist[i].confd = fd;
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
        int logout (int i, int fd) {
            if(clientlist[i].confd == fd){
                std::cout << "[CLIENT]\n<" << clientlist[i].username << "> logged out " << std::endl;
                return 0;
            }
            else {
                std::cout << "[CLIENT]\n<" << clientlist[i].username << "> logout error" << std::endl;
                return -1;
            }
        }
        // 0 for success, 1 for wrong password
        int delclient (int usrno, std::string passwd) {
            if (strcmp(passwd.c_str(), clientlist[usrno].password) == 0) {
                clientlist[usrno].empty = true;
                clientlist[usrno].confd = -1;
                return 1;
            }
            else {
                return 0;
            }
        }
};


typedef struct {
    int conn_fd;        // fd to talk with client
    char host[512];     // client's host
    int usrno;
} request;

//* ==================================== Global Variables ====================================
server svr;
std::queue<request> connection_queue; // Queue to store incoming connections
pthread_mutex_t queue_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t queue_cond = PTHREAD_COND_INITIALIZER;
bool server_running = true;
int maxfd;
clients accounts;

//* ==================================== function declare ====================================
void *worker_thread_func(void *arg);
static void initialize_request(request* reqP);
static void print(char* buf, int len);
void handle_client(request req);
static void init_server(unsigned short port);

//* ==================================== main function ==================================== 
int main(int argc, char **argv) {
    freopen( LOG_PATH, "w", stderr);

    struct sockaddr_in cliaddr;
    int clilen;

    int conn_fd;  // fd for a new connection with client
    int file_fd;  // fd for file that we open for reading
    char buf[BUFFER_SIZE];
    int buf_len;

    if (argc != 2 ) {
        fprintf(stderr,"usage: [port], using default port 40311\n");
        fflush(stderr);
        init_server((unsigned short) 40311);
    }
    else init_server((unsigned short) atoi(argv[1]));

    fprintf(stdout, "\nstarting on %.80s, port %d, fd %d, maxconn %d...\n", svr.hostname, svr.port, svr.listen_fd, maxfd);
    fflush(stdout);

    // Create hello polling
    struct pollfd h_poll[1];
    h_poll[0].fd = svr.listen_fd; 
    h_poll[0].events = POLLIN;

    // Create a thread pool
    pthread_t threads[MAX_CLIENTS];
    for (int i = 0; i < MAX_CLIENTS; ++i) {
        pthread_create(&threads[i], NULL, worker_thread_func, NULL);
    }

    while (server_running) {
        int pp = poll(h_poll, 1, -1);
        // Check new connection
        if(h_poll[0].revents == POLLIN){
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
            request req;
            req.conn_fd = conn_fd;
            strcpy(req.host, inet_ntoa(cliaddr.sin_addr));
            req.usrno = -1;
            fprintf(stdout, "getting a new request... fd %d from %s\n", conn_fd, req.host);
            fflush(stdout);
            pthread_mutex_lock(&queue_mutex);
            connection_queue.push(req);
            pthread_cond_signal(&queue_cond);
            pthread_mutex_unlock(&queue_mutex);
        }
    }

    // Join threads and clean up
    for (int i = 0; i < MAX_CLIENTS; ++i) {
        pthread_join(threads[i], NULL);
    }

    close(svr.listen_fd);
    return 0;
}

//* ==================================== functions ====================================

static void print(char* buf, int len) {
    for(int i = 0; i < len; ++i) {
        if(buf[i] == '\0') printf(" ");
        else printf("%c", buf[i]);
    }
    printf("\n");
    fflush(stdout);
}

void *worker_thread_func(void *arg) {
    while (true) {
        pthread_mutex_lock(&queue_mutex);

        // Wait for a connection if the queue is empty
        while (connection_queue.empty()) {
            pthread_cond_wait(&queue_cond, &queue_mutex);
        }
        // Retrieve the next connection request
        request req = connection_queue.front();
        connection_queue.pop();
        pthread_mutex_unlock(&queue_mutex);
        handle_client(req);
    }
    return NULL;
}

void handle_client(request req) {
    request clireq = req;
    char buffer[BUFFER_SIZE];
    char send_buf[BUFFER_SIZE];
    int conn_fd = clireq.conn_fd;
    int Cond = 0;
    std::cout << "Handling client from " << clireq.host << " on fd " << conn_fd << std::endl;

    struct pollfd clipoll[1];
    clipoll[0].fd = clireq.conn_fd; 
    clipoll[0].events = POLLIN;

    while (true) {
        int pp = poll(clipoll, 1, -1);
        if (clipoll[0].revents & POLLIN){
            int len;

            // Process the client request (simple echo here for demonstration)
            if(recv(clipoll[0].fd, &len, sizeof(int), 0) <= 0){
                std::cout << "\n[CLI_LEFT][";
                std::cout << std::setw(3) << conn_fd;
                std::cout << "]"<< std::endl;
                close(conn_fd);
                break;
            }
            recv(conn_fd, buffer, len, 0);
            std::cout << "\n[MSG_RECV][";
            std::cout << std::setw(3) << conn_fd ;
            std::cout << "][usr" ;
            std::cout << std::setw(3) << clireq.usrno;
            std::cout << "]len: " << len << std::endl;
            print(buffer, len);

            //if not logged in
            if (clireq.usrno == -1) {
                if (!strcmp(buffer, "REG_REQ")) {
                    len = 8;
                    std::string usrname(&buffer[len]);
                    len += usrname.length() + 1;
                    std::string passwd(&buffer[len]);
                    switch (accounts.newclient(usrname, passwd)) {
                        case 0:
                            len = 12;
                            strcpy(send_buf,"REG_SUCCESS\0");
                            break;
                        case 1:
                            len = 4;
                            strcpy(send_buf,"ERR\0");
                            break;
                        case 2:
                            len = 12;
                            strcpy(send_buf,"USRNAME_ERR\0");
                            break;
                        default:
                            len = 10;
                            strcpy(send_buf,"PLZ_RETRY\0");
                            break;
                    }
                    send(conn_fd, &len, sizeof(int), 0);
                    send(conn_fd, send_buf, len * sizeof(char), 0);
                }
                else if (!strcmp(buffer, "LOGIN_REQ")) {
                    std::cout << "loginreq_0" << std::endl;
                    len = 10;
                    std::string usrname(&buffer[len]);
                    len += usrname.length() + 1;
                    std::string passwd(&buffer[len]);
                    int tmp = accounts.login(usrname, passwd, conn_fd);
                    switch (tmp) {
                        case -1:
                            len = 11;
                            strcpy(send_buf,"PASSWD_ERR\0");
                            break;
                        case -2:
                            len = 12;
                            strcpy(send_buf,"USRNAME_ERR\0");
                            break;
                        default:
                            len = 14;
                            clireq.usrno = tmp;
                            strcpy(send_buf,"LOGIN_SUCCESS\0");
                            break;
                    }
                    send(conn_fd, &len, sizeof(int), 0);
                    send(conn_fd, send_buf, len * sizeof(char), 0);
                }
                else {
                    len = 10;
                    strcpy(send_buf, "LOGIN_PLS\0");
                    send(conn_fd, &len, sizeof(int), 0);
                    send(conn_fd, send_buf, len * sizeof(char), 0);
                }
            }
            else {
                if (!strcmp(buffer, "DELETE_ACCOUNT")) {
                    len = 10;
                    std::string passwd(&buffer[14]);
                    switch (accounts.delclient(clireq.usrno, passwd)) {
                        case 1:
                            len = 11;
                            strcpy(send_buf,"PASSWD_ERR\0");
                            break;
                        default:
                            clireq.usrno = -1;
                            len = 15;
                            strcpy(send_buf,"DELETE_SUCCESS\0");
                            break;
                    }
                    print(send_buf,len);
                    send(conn_fd, &len, sizeof(int), 0);
                    send(conn_fd, send_buf, len * sizeof(char), 0);
                }
                else if (!strcmp(buffer, "LOGOUT")) {
                    if(accounts.logout(clireq.usrno, conn_fd)) {
                        clireq.usrno = -1;
                        len = 15;
                        strcpy(send_buf,"LOGOUT_SUCCESS\0");
                    }
                    else {
                        len = 14;
                        strcpy(send_buf,"LOGOUT_FAILED\0");
                    }
                    send(conn_fd, &len, sizeof(int), 0);
                    send(conn_fd, send_buf, len * sizeof(char), 0);
                }
                else if (!strcmp(buffer, "EXIT")) {
                    close(conn_fd);
                    break;
                }
                else {
                    len = 9;
                    strcpy(send_buf, "LOGGEDIN\0");
                    send(conn_fd, &len, sizeof(int), 0);
                    send(conn_fd, send_buf, len * sizeof(char), 0);
                }
            }
        }
    }
    std::cout << "handle_fin" << std::endl;
}

static void initialize_request (request* reqP) {
    reqP->conn_fd = -1;
    reqP->usrno = -1;
}

static void init_server(unsigned short port) {
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
    if (setsockopt(svr.listen_fd, SOL_SOCKET, SO_REUSEADDR, (void *)&tmp, sizeof(tmp)) < 0) {
        ERR_EXIT("setsockopt");
    }
    if (bind(svr.listen_fd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
        ERR_EXIT("bind");
    }
    if (listen(svr.listen_fd, 1024) < 0) {
        ERR_EXIT("listen");
    }
}
