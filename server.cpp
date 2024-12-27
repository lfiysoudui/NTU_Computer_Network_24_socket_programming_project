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
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <fstream>

#define ERR_EXIT(a) do { perror(a); exit(1); } while(0)
#define LOG_PATH "./server_log"

#define MAX_CLIENTS 20
#define MAX_THREADS 10
#define BUFFER_SIZE 65536
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

typedef struct {
    std::queue <std::string> *msg;
    pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
    pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
}Chat_Msg;

typedef struct {
    std::queue <std::string> *filename;
    pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
    pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
}Trans_File;


class clients{
    private:
        Client *clientlist;
        int client_list_size;
        Chat_Msg *chatmsg;
        Trans_File *transfile;
    public:
        clients(){
            client_list_size = MAX_CLIENTS;
            clientlist = (Client*) malloc(client_list_size * sizeof(Client));
            chatmsg = (Chat_Msg*) malloc(client_list_size * sizeof(Chat_Msg));
            transfile = (Trans_File*) malloc(client_list_size * sizeof(Trans_File));
            for (int i = 0; i < client_list_size; ++i) {
                clientlist[i].empty = true;
                clientlist[i].confd = -1;
                chatmsg[i].msg = new std::queue<std::string>();
                transfile[i].filename = new std::queue<std::string>();
            }
        }

        // 0 for success, 1 for no empty slots, 2 for unavailable username
        int newclient (std::string usrname, std::string passwd);

        // usrno for success, -1 for wrong password, -2 for user not found
        int login (std::string usrname, std::string passwd, int fd);

        int logout (int i, int fd);

        // 0 for success, 1 for wrong password
        int delclient (int usrno, std::string passwd);

        void chatroom (int usrno, SSL *cli_ssl, int fd, std::string tg_name);

        void file_trans(SSL *ssl, int fd, std::string tg_name, std::string filename);

        void file_recv(SSL *cli_ssl, int fd, int usrno);

        void streaming(SSL *cli_ssl, int fd, int usrno, std::string filename);
};


typedef struct {
    int conn_fd;        // fd to talk with client
    char host[512];     // client's host
    int usrno;
    SSL *ssl;
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
void initialize_openssl();
SSL_CTX *create_context();
void configure_context(SSL_CTX *ctx);
void *worker_thread_func(void *arg);
void initialize_request(request* reqP);
void print(char* buf, int len);
void handle_client(request req);
void init_server(unsigned short port);

//* ==================================== main function ==================================== 
int main(int argc, char **argv) {
    freopen( LOG_PATH, "w", stderr);

    struct sockaddr_in cliaddr;
    int clilen;

    int conn_fd;  // fd for a new connection with client
    int file_fd;  // fd for file that we open for reading
    char buf[BUFFER_SIZE];
    int buf_len;

    initialize_openssl();
    SSL_CTX *ctx = create_context();
    configure_context(ctx);

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
    pthread_t threads[MAX_THREADS];
    for (int i = 0; i < MAX_THREADS; ++i) {
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
            SSL *ssl = SSL_new(ctx);
            SSL_set_fd(ssl, conn_fd);
            if (SSL_accept(ssl) <= 0) {
                ERR_print_errors_fp(stderr);
            }
            request req;
            req.conn_fd = conn_fd;
            req.ssl = ssl;
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
    for (int i = 0; i < MAX_THREADS; ++i) {
        pthread_join(threads[i], NULL);
    }

    close(svr.listen_fd);
    SSL_CTX_free(ctx);
    return 0;
}


//* ==================================== class functions ====================================
int clients::newclient (std::string usrname, std::string passwd) {
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

int clients::login (std::string usrname, std::string passwd, int fd) {
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

int clients::logout (int i, int fd) {
    if(clientlist[i].confd == fd){
        clientlist[i].confd = -1;
        std::cout << "[CLIENT]\n<" << clientlist[i].username << "> logged out " << std::endl;
        return 0;
    }
    else {
        std::cout << "[CLIENT]\n<" << clientlist[i].username << "> logout error" << std::endl;
        return -1;
    }
}

int clients::delclient (int usrno, std::string passwd) {
    if (strcmp(passwd.c_str(), clientlist[usrno].password) == 0) {
        clientlist[usrno].empty = true;
        clientlist[usrno].confd = -1;
        return 1;
    }
    else {
        return 0;
    }
}

void clients::chatroom (int usrno, SSL *cli_ssl, int fd, std::string tg_name) {
    int tg_no = -1;
    for (int i = 0; i <= client_list_size; ++i) {
        if(i == client_list_size) {
            std::cout << "[CLIENT]\nNo such user" << std::endl;
            char buffer[BUFFER_SIZE];
            int len = 14;
            strcpy(buffer,"USR_NOT_FOUND");
            SSL_write(cli_ssl, &len, sizeof(int));
            SSL_write(cli_ssl, buffer, len);
            return;
        }   
        if (!clientlist[i].empty && !strcmp(clientlist[i].username,tg_name.c_str())) {
            char buffer[BUFFER_SIZE];
            int len = 12;
            std::cout << "target user confd = " << clientlist[i].confd << std::endl;
            if (clientlist[i].confd == -1) {
                std::cout << "[CLIENT]\nUser not online" << std::endl;
                int len = 15;
                strcpy(buffer,"USR_NOT_ONLINE");
                SSL_write(cli_ssl, &len, sizeof(int));
                SSL_write(cli_ssl, buffer, len);
                return;
            }
            len = 12;
            tg_no = i;
            if(usrno == tg_no) {
                std::cout << "[CLIENT]\nsender == receiver" << std::endl;
                char buffer[BUFFER_SIZE];
                int len = 9;
                strcpy(buffer,"USR_SELF\0");
                SSL_write(cli_ssl, &len, sizeof(int));
                SSL_write(cli_ssl, buffer, len);
                return;
            }   
            strcpy(buffer, "PLEASE_SEND\0");
            SSL_write(cli_ssl, &len, sizeof(int));
            SSL_write(cli_ssl, buffer, len);
            break;
        }

    }

    // welcome message
    std::cout << "[CLIENT]\n" << clientlist[usrno].username << " enter Chatroom" << std::endl;
    pthread_mutex_lock(&chatmsg[tg_no].mutex);
    std::string msg = clientlist[usrno].username + std::string(" had enter the Chatroom");
    chatmsg[tg_no].msg->push(msg);
    pthread_cond_signal(&chatmsg[tg_no].cond);
    pthread_mutex_unlock(&chatmsg[tg_no].mutex);
    // start chat
    struct pollfd chat_poll[1];
    chat_poll[0].fd = fd;
    chat_poll[0].events = POLLIN;
    char chat_buffer[BUFFER_SIZE];
    while(true) {
        int req = poll(chat_poll, 1, 0);
        if (chat_poll[0].revents & POLLIN) {
            int len;
            SSL_read(cli_ssl, &len, sizeof(int));
            SSL_read(cli_ssl, chat_buffer, len);
            std::cout << "[MSG_RECV][";
            std::cout << std::setw(3) << fd;
            std::cout << "][usr" ;
            std::cout << std::setw(3) << usrno;
            std::cout << "]len: " << len << std::endl;
            print(chat_buffer, len);
            if(!strcmp(chat_buffer,"LEAVE\0")) {
                pthread_mutex_lock(&chatmsg[tg_no].mutex);
                msg = clientlist[usrno].username + std::string(" had left the Chatroom");
                chatmsg[tg_no].msg->push(msg);
                pthread_cond_signal(&chatmsg[tg_no].cond);
                pthread_mutex_unlock(&chatmsg[tg_no].mutex);
                std::cout << "[CLIENT]\n" << clientlist[usrno].username << " leave Chatroom" << std::endl;
                break;
            }
            else if (!clientlist[tg_no].empty && !strcmp(clientlist[tg_no].username,chat_buffer)) {
                pthread_mutex_lock(&chatmsg[tg_no].mutex);
                std::string msg = clientlist[usrno].username + std::string(": ") + std::string(&chat_buffer[strlen(chat_buffer)]+1);
                chatmsg[tg_no].msg->push(msg);
                pthread_cond_signal(&chatmsg[tg_no].cond);
                pthread_mutex_unlock(&chatmsg[tg_no].mutex);
                std::cout << "[CLIENT]\nmessage add to " << clientlist[tg_no].username << "'s queue" << std::endl;
            }
        }
        // check if there is any message in the queue
        pthread_mutex_lock(&chatmsg[usrno].mutex);
        while(!chatmsg[usrno].msg->empty()) {
            strcpy(chat_buffer,chatmsg[usrno].msg->front().c_str());
            chat_buffer[strlen(chatmsg[usrno].msg->front().c_str())] = '\0';
            chatmsg[usrno].msg->pop();
            std::cout << "[MSG_SEND][";
            std::cout << std::setw(3) << fd;
            std::cout << "][usr" ; 
            std::cout << std::setw(3) << usrno;
            std::cout << "]len: " << strlen(chat_buffer) + 1 << std::endl;
            print(chat_buffer, strlen(chat_buffer) + 1);
            int len = strlen(chat_buffer) + 1;
            SSL_write(cli_ssl, &len, sizeof(int));
            SSL_write(cli_ssl, chat_buffer, len);
        }
        pthread_cond_signal(&chatmsg[usrno].cond);
        pthread_mutex_unlock(&chatmsg[usrno].mutex);
    }
}

void clients::file_trans(SSL *cli_ssl, int fd, std::string tg_name, std::string filename){
    int tg_no = -1;
    int len;
    char send_buf[BUFFER_SIZE];
    char buffer[BUFFER_SIZE]; 

    for (int i = 0; i <= client_list_size; ++i) {
        if(i == client_list_size) {
            std::cout << "[CLIENT]\nNo such user" << std::endl;
            break;
        }   
        if (!clientlist[i].empty && !strcmp(clientlist[i].username,tg_name.c_str())) {
            tg_no = i;
            std::cout << "[CLIENT]\nUser found <" << tg_no << ">" << std::endl;
            break;
        }
    }

    if(tg_no == -1) {
        int len = 14;
        strcpy(send_buf,"USR_NOT_FOUND\0");
        SSL_write(cli_ssl, &len, sizeof(int));
        SSL_write(cli_ssl, send_buf, len);
        return;
    }
    len = 12;
    strcpy(send_buf, "PLEASE_SEND\0");
    SSL_write(cli_ssl, &len, sizeof(int));
    SSL_write(cli_ssl, send_buf, len);

    // Open the file to write the received data
    std::ofstream outfile(filename.c_str(), std::ios::binary);

    // Receive the file in chunks
    long int file_length;
    SSL_read(cli_ssl, &file_length, sizeof(long int));
    int bytes_received;
    // Receive the file in chunks
    if(file_length != 0) {
        while ((bytes_received = SSL_read(cli_ssl, buffer, BUFFER_SIZE)) > 0) {
            std::cout << "bytes_received: " << bytes_received << std::endl;
            file_length -= bytes_received;
            outfile.write(buffer, bytes_received);
            if (file_length <= 0) break;
        }
    }
    outfile.close();
    std::cout << "received, saving " << filename << " into queue\n" << std::endl;
    pthread_mutex_lock(&transfile[tg_no].mutex);
    transfile[tg_no].filename->push(filename);
    pthread_cond_signal(&transfile[tg_no].cond);
    pthread_mutex_unlock(&transfile[tg_no].mutex);
    std::cout << "File received successfully\n" << std::endl;
    outfile.close();
    return;
}

void clients::file_recv(SSL *cli_ssl, int fd, int usrno){
    int tg_no = -1;
    int len;
    char send_buf[BUFFER_SIZE];
    char buffer[BUFFER_SIZE]; 

    int file_cnt = transfile[usrno].filename->size();
    SSL_write(cli_ssl, &file_cnt, sizeof(int));
    len = 12;
    for(int i = file_cnt; i > 0; i--) {
        // grep and send the filename (opening the stream first)
        std::string org_filename = transfile[usrno].filename->front();
        std::string filename = transfile[usrno].filename->front();
        std::ifstream infile(org_filename.c_str(), std::ios::binary);
        std::cout << "sending file: " << filename << std::endl;

        size_t pos = filename.find(std::string("files/"));
        if (pos != std::string::npos)
            filename.erase(pos, std::string("files/").length());
        len = filename.length();
        strcpy(send_buf, filename.c_str());
        SSL_write(cli_ssl, &len, sizeof(int));
        SSL_write(cli_ssl, send_buf, len);
        // Send the file length
        infile.seekg(0, std::ios::end);
        long int file_length = infile.tellg();
        infile.seekg(0, std::ios::beg);
        SSL_write(cli_ssl, &file_length, sizeof(long int));
        
        // Send the file in chunks
        while (infile.read(buffer, BUFFER_SIZE) || infile.gcount() > 0) {

            SSL_write(cli_ssl,  buffer, infile.gcount());
        }
        std::cout << "File sent successfully\n";
        remove(org_filename.c_str());
        transfile[usrno].filename->pop();
        infile.close();
    }

    return;
}

void clients::streaming(SSL *cli_ssl, int fd, int usrno, std::string filename){
    // Open the video capture (from camera or file)
    int port = 12345 + usrno;
    int len;
    char buffer[BUFFER_SIZE];
    std::cout << "reading buffer" << std::endl;
    SSL_read(cli_ssl, &len, sizeof(int));
    SSL_read(cli_ssl, buffer, len);
    if(strcmp(buffer,"READY\0") != 0) {
        std::cout << "error" << std::endl;
        print(buffer,len);
        return;
    }
    std::cout << "buffer checked" << std::endl;
    std::string stream_command = "ffmpeg -loglevel quiet -i " + filename + " -c:v libx264 -f mpegts udp://127.0.0.1:" + std::to_string(port);
    // ffmpeg -loglevel quiet -i input_video.mp4 -c:v libx264 -preset veryfast -b:v 1500k -c:a aac -b:a 128k -f mpegts udp://
    std::cout << "running :" << stream_command << std::endl;
    system(stream_command.c_str());
}

//* ==================================== functions ====================================

void initialize_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

SSL_CTX *create_context() {
    const SSL_METHOD *method = SSLv23_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

void configure_context(SSL_CTX *ctx) {
    // Load server certificate and private key
    if (SSL_CTX_use_certificate_file(ctx, "cert/server.crt", SSL_FILETYPE_PEM) <= 0) {
        perror("certificate not found\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "cert/private.key", SSL_FILETYPE_PEM) <= 0) {
        perror("key not found\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

void print(char* buf, int len) {
    for(int i = 0; i < len; ++i) {
        if(buf[i] == '\0') printf("ø");
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
    int Cond = 0;
    std::cout << "Handling client from " << clireq.host << " on fd " << clireq.conn_fd << std::endl;

    struct pollfd clipoll[1];
    clipoll[0].fd = clireq.conn_fd; 
    clipoll[0].events = POLLIN;

    while (true) {
        int pp = poll(clipoll, 1, -1);
        if (clipoll[0].revents & POLLIN){
            int len;

            // Process the client request (simple echo here for demonstration)
            if(SSL_read(clireq.ssl, &len, sizeof(int)) <= 0){
                accounts.logout(clireq.usrno, clireq.conn_fd);
                std::cout << "\n[CLI_LEFT][";
                std::cout << std::setw(3) << clireq.conn_fd;
                std::cout << "]"<< std::endl;
                close(clireq.conn_fd);
                break;
            }
            SSL_read(clireq.ssl, buffer, len);
            std::cout << "\n[MSG_RECV][";
            std::cout << std::setw(3) << clireq.conn_fd ;
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
                    SSL_write(clireq.ssl, &len, sizeof(int));
                    SSL_write(clireq.ssl, send_buf, len * sizeof(char));
                }
                else if (!strcmp(buffer, "LOGIN_REQ")) {
                    std::cout << "loginreq_0" << std::endl;
                    len = 10;
                    std::string usrname(&buffer[len]);
                    len += usrname.length() + 1;
                    std::string passwd(&buffer[len]);
                    int tmp = accounts.login(usrname, passwd, clireq.conn_fd);
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
                    SSL_write(clireq.ssl, &len, sizeof(int));
                    SSL_write(clireq.ssl, send_buf, len * sizeof(char));
                }
                else {
                    len = 10;
                    strcpy(send_buf, "LOGIN_PLS\0");
                    SSL_write(clireq.ssl, &len, sizeof(int));
                    SSL_write(clireq.ssl, send_buf, len * sizeof(char));
                }
            }
            else {
                if(!strcmp(buffer, "STREAMING\0")) {
                    std::string filename = "files/to_stream/" + std::string(&buffer[10]) + ".mp4";
                    if(access(filename.c_str(), F_OK) == -1) {
                        len = 15;
                        strcpy(send_buf,"FILE_NOT_FOUND\0");
                        SSL_write(clireq.ssl, &len, sizeof(int));
                        SSL_write(clireq.ssl, send_buf, len * sizeof(char));
                        continue;
                    }
                    else {
                        len = 11;
                        strcpy(send_buf,"FILE_FOUND\0");
                        SSL_write(clireq.ssl, &len, sizeof(int));
                        SSL_write(clireq.ssl, send_buf, len * sizeof(char));
                        len = 12345+clireq.usrno;
                        SSL_write(clireq.ssl, &len, sizeof(int));
                    }
                    accounts.streaming(clireq.ssl, clireq.conn_fd, clireq.usrno, filename);
                }
                else if (!strcmp(buffer, "RECV_FILE\0")) {
                    accounts.file_recv(clireq.ssl, clireq.conn_fd, clireq.usrno);
                }
                else if (!strcmp(buffer, "FILE_SEND\0")) {
                    std::string tg_name = std::string(&buffer[10]);
                    std::string filename = "files/" + std::string(&buffer[11+tg_name.length()]);
                    std::cout  << "target user: " << tg_name << "\nfilename: " << filename << std::endl;
                    accounts.file_trans(clireq.ssl, clireq.conn_fd, tg_name, filename);
                }
                else if (!strcmp(buffer, "CHATROOM")) {
                    accounts.chatroom(clireq.usrno, clireq.ssl, clireq.conn_fd, std::string(&buffer[9]));
                }
                else if (!strcmp(buffer, "DELETE_ACCOUNT")) {
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
                    SSL_write(clireq.ssl, &len, sizeof(int));
                    SSL_write(clireq.ssl, send_buf, len * sizeof(char));
                }
                else if (!strcmp(buffer, "LOGOUT")) {
                    if(accounts.logout(clireq.usrno, clireq.conn_fd) == 0) {
                        clireq.usrno = -1;
                        len = 15;
                        strcpy(send_buf,"LOGOUT_SUCCESS\0");
                    }
                    else {
                        len = 14;
                        strcpy(send_buf,"LOGOUT_FAILED\0");
                    }
                    SSL_write(clireq.ssl, &len, sizeof(int));
                    SSL_write(clireq.ssl, send_buf, len * sizeof(char));
                }
                else if (!strcmp(buffer, "EXIT")) {
                    if(clireq.usrno != -1)
                        accounts.logout(clireq.usrno, clireq.conn_fd);
                    close(clireq.conn_fd);
                    break;
                }
                else {
                    std::cout << "error" << std::endl;
                    len = 9;
                    strcpy(send_buf, "LOGGEDIN\0");
                    SSL_write(clireq.ssl, &len, sizeof(int));
                    SSL_write(clireq.ssl, send_buf, len * sizeof(char));
                }
            }
        }
    }
    std::cout << "handle_fin" << std::endl;
}

void initialize_request (request* reqP) {
    reqP->conn_fd = -1;
    reqP->usrno = -1;
}

void init_server(unsigned short port) {
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