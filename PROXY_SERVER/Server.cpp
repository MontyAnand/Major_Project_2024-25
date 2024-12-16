// g++ -std=c++17 proxy.cpp
// g++ -std=c++17 -o Server Server.cpp -lssl -lcrypto

#include <filesystem>
#include <iostream>
#include <fstream>
#include <stdexcept>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <cstring>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>           // For sockaddr_in and SOL_IP
#include <linux/netfilter_ipv4.h> // For SO_ORIGINAL_DST
#include <sys/epoll.h>
#include <fcntl.h>
#include <vector>
#include <map>

#define PROXY_PORT 4433
#define BUFFER_SIZE 1024 * 1024

namespace fs = std::filesystem;

const int MAX_EVENTS = 1000;

std::string current_directory;

std::map<int, int> pair;
std::map<int, SSL *> securePair;
std::map<int,SSL_CTX *>contextMap;

int runCommand(std::string command)
{
    return system(command.c_str());
}

bool searchFolder(const std::string directory, const std::string folderName)
{
    try
    {
        for (const auto &entry : fs::directory_iterator(directory))
        {
            if (entry.is_directory() && entry.path().filename() == folderName)
            {
                return true;
            }
        }
    }
    catch (const fs::filesystem_error &e)
    {
        std::cerr << "Error: " << e.what() << std::endl;
    }
    return false;
}

bool searchFile(const std::string directory, const std::string fileName)
{
    try
    {
        for (const auto &entry : fs::directory_iterator(directory))
        {
            if (entry.is_regular_file() && entry.path().filename() == fileName)
            {
                return true;
            }
        }
        return false;
    }
    catch (const fs::filesystem_error &e)
    {
        std::cerr << "Error: " << e.what() << std::endl;
    }
    return false;
}

void modifyCN(std::string &CN)
{
    for (char &c : CN)
    {
        if (c == '.')
        {
            c = '_';
        }
    }
    return;
}

bool writeVarsFileCA()
{
    std::ofstream file("vars");
    if (!file.is_open())
        return false;

    // Writting contents in vars

    file << "set_var EASYRSA_REQ_COUNTRY    \"IN\" " << std::endl;
    file << "set_var EASYRSA_REQ_PROVINCE   \"West Bemgal\" " << std::endl;
    file << "set_var EASYRSA_REQ_CITY       \"Kolkata\" " << std::endl;
    file << "set_var EASYRSA_REQ_ORG        \"UTM\" " << std::endl;
    file << "set_var EASYRSA_REQ_EMAIL      \"vk2818970@gmail.com\" " << std::endl;
    file << "set_var EASYRSA_REQ_OU         \"Community\" " << std::endl;
    file << "set_var EASYRSA_REQ_CN         \"common.utm.com\"" << std::endl;
    file << "set_var EASYRSA_ALGO           \"ec\" " << std::endl;
    file << "set_var EASYRSA_DIGEST         \"sha512\" " << std::endl;

    file.close();
    return true;
}

bool writeCSRConfFile(std::string modifiedCN)
{
    std::ofstream file((modifiedCN + ".conf").c_str());
    if (!file.is_open())
        return false;

    // Writting contents in configuration file
    file << "[ req ]" << std::endl;
    file << "default_bits       = 2048" << std::endl;
    file << "prompt             = no" << std::endl;
    file << "default_md         = sha256" << std::endl;
    file << "distinguished_name = dn\n"
         << std::endl;

    file << "[ dn ]" << std::endl;
    file << "C = IN" << std::endl;
    file << "ST = West Bengal" << std::endl;
    file << "L = Kolkata" << std::endl;
    file << "O = UTM System" << std::endl;
    file << "OU = IT" << std::endl;

    for (char &x : modifiedCN)
    {
        if (x == '_')
            x = '.';
    }

    file << "CN = " << modifiedCN << std::endl;

    file.close();
    return true;
}

bool prepareCertificate(std::string CN)
{
    modifyCN(CN);
    try
    {
        if (searchFile(current_directory + "/Key", CN + ".key"))
        {
            return true;
        }
        fs::current_path("Key");

        // Generating Private key

        std::string command = "openssl genrsa -out ";
        command += CN;
        command += ".key 2048";

        if (runCommand(command) != 0)
        {
            throw std::runtime_error("Failed to generate Private Key");
        }

        // Writting configuration file for Certificate signing Request

        if (!writeCSRConfFile(CN))
        {
            throw std::runtime_error("Failed to write configuration for CSR");
        }

        // Generate CSR

        command = "openssl req -new -key ";
        command += CN;
        command += ".key -out ";
        command += CN;
        command += ".csr -config ";
        command += CN;
        command += ".conf";

        if (runCommand(command) != 0)
        {
            throw std::runtime_error("Failed to generate CSR");
        }

        // Import CSR for Sign

        fs::current_path(current_directory);
        fs::current_path("CA");

        //./easyrsa import-req /tmp/sammy-server.req sammy-server

        command = "./easyrsa import-req ";
        command += current_directory;
        command += "/Key/";
        command += CN;
        command += ".csr ";
        command += CN;

        if (runCommand(command) != 0)
        {
            throw std::runtime_error("Failed to Import CSR");
        }

        // Sign CSR

        command = "./easyrsa sign-req server ";
        command += CN;

        if (runCommand("echo yes | " + command) != 0)
        {
            throw std::runtime_error("Failed to sign the CSR");
        }

        fs::current_path(current_directory);
        return true;
    }
    catch (const std::exception &e)
    {
        std::cerr << e.what() << '\n';
    }
    fs::current_path(current_directory);
    return false;
}

void ca_setup()
{

    try
    {

        // Creating dedicated directory for Certificate Authority

        if (!fs::create_directory("CA"))
        {
            throw std::runtime_error("Failed to create folder for Cirtificate Authority");
        }

        // Link the created directory with easy-rsa folder
        std::string command = "ln -s /usr/share/easy-rsa/* ";
        command += current_directory;
        command += "/CA/";
        if (runCommand(command) != 0)
        {
            throw std::runtime_error("Failed to add symlink");
        }

        // Change permission to owner only
        command = "chmod 700 ";
        command += current_directory;
        command += "/CA";

        if (runCommand(command) != 0)
        {
            throw std::runtime_error("Failed to change permission");
        }

        // Enter into the directory of CA
        fs::current_path("CA");

        // Initialisation of Public key Infrastructure (PKI)
        if (runCommand("./easyrsa init-pki") != 0)
        {
            throw std::runtime_error("Unable to initilize PKI");
        }

        // Writing vars file which will contain the details of CA
        if (!writeVarsFileCA())
        {
            throw std::runtime_error("Unable to write vars file for CA");
        }

        // Building CA

        if (runCommand("echo 'UTM' | ./easyrsa build-ca nopass") != 0)
        {
            throw std::runtime_error("Unable to build CA");
        }
    }
    catch (const std::exception &e)
    {
        std::cerr << e.what() << '\n';
    }

    fs::current_path(current_directory);
}

int sslContextCallback(SSL *ssl, void *arg)
{
    const char *SNI = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);

    if (SNI == nullptr)
    {
        fprintf(stderr, "No SNI provided.\n");
        return 0;
    }
    std::string CN = SNI;
    if (!prepareCertificate(CN))
    {
        return 0;
    };
    modifyCN(CN);
    std::string path = current_directory;
    // std::cout << path + "/CA/pki/issued/" + CN + ".crt" <<std::endl;
    // std::cout << path + "/Key/" + CN + ".key" << std::endl;

    if (SSL_use_certificate_file(ssl, (path + "/CA/pki/issued/" + CN + ".crt").c_str(), SSL_FILETYPE_PEM) != 1 ||
        SSL_use_PrivateKey_file(ssl, (path + "/Key/" + CN + ".key").c_str(), SSL_FILETYPE_PEM) != 1)
    {
        fprintf(stderr, "Failed to load certificate/key %s\n", SNI);
        return 0; // Failure
    }

    std::cout << path + "/CA/pki/issued/" + CN + ".crt" << std::endl;
    std::cout << path + "/Key/" + CN + ".key" << std::endl;

    return 1;
}

// Initialize OpenSSL
void initialize_openssl()
{
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

// Cleanup OpenSSL
void cleanup_openssl()
{
    EVP_cleanup();
}

// Create SSL context for proxy
SSL_CTX *create_ssl_context(const SSL_METHOD *method)
{
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx)
    {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        return nullptr;
    }
    return ctx;
}

// Retrieve original destination using SO_ORIGINAL_DST
sockaddr_in get_original_destination(int client_sock)
{
    sockaddr_in orig_dst{};
    socklen_t len = sizeof(orig_dst);

    if (getsockopt(client_sock, SOL_IP, SO_ORIGINAL_DST, &orig_dst, &len) < 0)
    {
        perror("getsockopt(SO_ORIGINAL_DST) failed");
        exit(EXIT_FAILURE);
    }
    return orig_dst;
}

// Connect to the original destination
int connect_to_target(const sockaddr_in &orig_dst)
{
    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0)
    {
        perror("Socket creation failed");
        return -1;
    }

    if (connect(server_sock, (struct sockaddr *)&orig_dst, sizeof(orig_dst)) < 0)
    {
        perror("Connection to target server failed");
        close(server_sock);
        return -1;
    }

    return server_sock;
}

void makeNonBlocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1)
    {
        std::cerr << "Unable to get flags for socket" << std::endl;
        return;
    }
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1)
    {
        std::cerr << "Failed to set O_NONBLOCK flag" << std::endl;
    }
    return;
}

void addToEpoll(int epoll_fd, int fd)
{
    struct epoll_event event;
    event.data.fd = fd; // Associate the file descriptor with the event
    event.events = EPOLLIN;

    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &event) == -1)
    {
        std::cerr << "Failed to add socket to epoll" << std::endl;
    }
    return;
}

int addToEvent(int epoll_fd, int fd)
{
    struct epoll_event ev
    {
    };
    ev.events = EPOLLIN;
    ev.data.fd = fd;
    return epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev);
}


void handleNewConnection(int epoll_fd, int listener)
{
    int client_socket = accept(listener, nullptr, nullptr);
    if (client_socket < 0)
    {
        perror("Client accept failed");
        return;
    }
    std::cout << "TCP with client connected"<<std::endl;
    // Create SSL contexts
    SSL_CTX *client_ctx = create_ssl_context(TLS_server_method());
    if (client_ctx == nullptr)
    {
        return;
    }

    std::cout<< "Client context ceated" << std::endl;

    // Adding callback function to Context
    SSL_CTX_set_cert_cb(client_ctx, sslContextCallback, NULL);

    
    SSL *client_ssl = SSL_new(client_ctx);

    if(client_ssl == nullptr){
        std::cerr << "SSL pointer"<< std::endl;
        return;
    }

    std::cout << "Client SSL created" <<std::endl;
    if (SSL_set_fd(client_ssl, client_socket) != 1)
    {
        ERR_print_errors_fp(stderr);
        SSL_free(client_ssl);
        return;
    }
    std::cout << " Socket attached with ssl" <<std::endl;
    if (SSL_accept(client_ssl) <= 0)
    {
        ERR_print_errors_fp(stderr);
        SSL_free(client_ssl);
        close(client_socket);
        return;
    }

    std::cout<<"SSL Accepted" <<std::endl;

    // Retrieve the original destination
    sockaddr_in orig_dst = get_original_destination(client_socket);

    // Connect to the original destination
    int server_socket = connect_to_target(orig_dst);
    if (server_socket < 0)
    {
        SSL_free(client_ssl);
        close(client_socket);
        return;
    }

    // Creating Server Contex
    SSL_CTX *server_ctx = create_ssl_context(TLS_client_method());

    std::cout << "Server contex created " << std::endl;

    // SSL connection with the original server
    SSL *server_ssl = SSL_new(server_ctx);

    if(server_ssl == nullptr){
        std::cerr << "Server SSL pointer"<< std::endl;
        return;
    }

    std::cout<< "Server ssl created" <<std::endl;

    if(SSL_set_fd(server_ssl, server_socket)!=1){
        ERR_print_errors_fp(stderr);
        SSL_free(client_ssl);
        return;
    }

    std::cout<<"Socket with server ssl conneted" <<std::endl;

    if (SSL_connect(server_ssl) <= 0)
    {
        ERR_print_errors_fp(stderr);
        SSL_free(client_ssl);
        SSL_free(server_ssl);
        close(client_socket);
        close(server_socket);
        return;
    }

    std::cout << "Server SSL done" << std::endl; 

    // Initialize pairs
    pair[client_socket] = server_socket;
    pair[server_socket] = client_socket;
    securePair[client_socket] = client_ssl;
    securePair[server_socket] = server_ssl;
    contextMap[client_socket] = client_ctx;
    contextMap[server_socket] = server_ctx;

    // Making sockets non_blocking
    makeNonBlocking(client_socket);
    makeNonBlocking(server_socket);

    // Add sockets to epoll
    addToEvent(epoll_fd, client_socket);
    addToEvent(epoll_fd, server_socket);

    return;
}

void procesIncomingData(int epoll_fd, int fd)
{
    char buffer[BUFFER_SIZE];
    int bytes_read = SSL_read(securePair[fd], buffer, sizeof(buffer));


    if (bytes_read <= 0)
    {
        // Handle when client colsed the connection
        SSL_free(securePair[fd]);
        SSL_free(securePair[pair[fd]]);
        close(fd);
        close(pair[fd]);
        SSL_CTX_free(contextMap[fd]);
        SSL_CTX_free(contextMap[pair[fd]]);
        contextMap.erase(fd);
        contextMap.erase(pair[fd]);
        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, nullptr);
        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, pair[fd], nullptr);
        securePair.erase(pair[fd]);
        securePair.erase(fd);
        pair.erase(pair[fd]);
        pair.erase(fd);
        return;
    }

    std::cout << buffer << std::endl;

    SSL_write(securePair[pair[fd]], buffer, bytes_read);
    return;
}


void eventHandler(int listener)
{
    int epoll_fd = epoll_create1(0);
    if (epoll_fd == -1)
    {
        perror("epoll_create1");
        return;
    }

    // Adding listener socket to epoll
    if (addToEvent(epoll_fd, listener) == -1)
    {
        perror("epoll_ctl Error");
        return;
    }

    // Event Loop
    std::vector<epoll_event> events(MAX_EVENTS);

    while (true)
    {
        int num_events = epoll_wait(epoll_fd, events.data(), MAX_EVENTS, -1);
        if (num_events == -1)
        {
            perror("epoll_wait");
            break;
        }

        for (int i = 0; i < num_events; i++)
        {
            if (events[i].data.fd == listener)
            {
                handleNewConnection(epoll_fd, listener);
            }
            else
            {
                // Process Data
                std::cout<< "Data came to socket" <<std::endl;
                procesIncomingData(epoll_fd, events[i].data.fd);
            }
        }
    }
}

bool initializeServer()
{
    try
    {
        initialize_openssl();
        current_directory = fs::current_path().string();

        if (!searchFolder(current_directory, "CA"))
        {
            ca_setup();
        }

        if (!searchFolder(current_directory, "Key"))
        {
            if (!fs::create_directory("Key"))
            {
                throw std::runtime_error("Failed to create folder for Certificate Authority");
            }
        }
    }
    catch (const std::exception &e)
    {
        std::cerr << e.what() << '\n';
        return false;
    }
    return true;
}

void runServer()
{
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0)
    {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(PROXY_PORT);

    if (bind(listener, (struct sockaddr *)&addr, sizeof(addr)) < 0 ||
        listen(listener, SOMAXCONN) < 0)
    {
        perror("Bind or listen failed");
        exit(EXIT_FAILURE);
    }

    std::cout << "Transparent TLS Proxy listening on port " << PROXY_PORT << std::endl;
    eventHandler(listener);
}

int main()
{
    if (!initializeServer())
    {
        std::cerr << "Unable to setup environment" << std::endl;
        exit(1);
    }
    runServer();
    return 0;
}
