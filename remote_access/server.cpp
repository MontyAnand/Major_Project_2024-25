#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "request_format.h"

void create_table()
{
    sprintf(command, "sudo nft add table inet %s", TABLE_NAME);
    int result = system(command);
    if (result == -1)
    {
        perror("Error during table creation...");
        exit(1);
    }
    return;
}

void create_port_sets()
{

    // Source PORT Set
    sprintf(command, "sudo nft add set inet %s %s '{type inet_service;}'", TABLE_NAME, SRC_PORT_SET);
    int result = system(command);
    if (result == -1)
    {
        perror("Error during creating Set...");
        exit(1);
    }

    // Destination PORT Set
    sprintf(command, "sudo nft add set inet %s %s '{type inet_service;}'", TABLE_NAME, DES_PORT_SET);
    result = system(command);
    if (result == -1)
    {
        perror("Error during creating Set...");
        exit(1);
    }

    return;
}

void create_IP_sets()
{

    // Source IP set
    sprintf(command, "sudo nft add set inet %s %s '{type ipv4_addr; flags interval;}'", TABLE_NAME, SRC_IP_SET);

    int result = system(command);
    if (result == -1)
    {
        perror("Error during creating set...");
        exit(1);
    }

    // Destination IP Set
    sprintf(command, "sudo nft add set inet %s %s '{type ipv4_addr; flags interval;}'", TABLE_NAME, DES_IP_SET);
    result = system(command);
    if (result == -1)
    {
        perror("Error during ceating set...");
        exit(1);
    }
    return;
}

void create_chains()
{
    // Convention : Chain name is same as the Hook's name...

    int result;

    // Ingress Hook

    // Prerouting Hook

    sprintf(command, "sudo nft add chain inet %s prerouting '{type nat hook prerouting priority 0; policy accept;}'", TABLE_NAME);
    result = system(command);
    if (result == -1)
    {
        perror("Error during creating chain...");
        exit(1);
    }

    // Input Hook

    sprintf(command, "sudo nft add chain inet %s input '{type filter hook input priority 0; policy accept;}'", TABLE_NAME);
    result = system(command);
    if (result == -1)
    {
        perror("Error during creating chain...");
        exit(1);
    }

    // Forward Hook

    sprintf(command, "sudo nft add chain inet %s forward '{type filter hook forward priority 0; policy accept;}'", TABLE_NAME);
    result = system(command);
    if (result == -1)
    {
        perror("Error during creating chain...");
        exit(1);
    }

    // Output Hook

    sprintf(command, "sudo nft add chain inet %s output '{type filter hook output priority 0; policy accept;}'", TABLE_NAME);
    result = system(command);
    if (result == -1)
    {
        perror("Error during creating chain...");
        exit(1);
    }

    // Postrouting Hook

    sprintf(command, "sudo nft add chain inet %s postrouting '{type nat hook postrouting priority 0; policy accept;}'", TABLE_NAME);
    result = system(command);
    if (result == -1)
    {
        perror("Error during creating chain...");
        exit(1);
    }

    return;
}

void initial_rules()
{
    int result;

    // Allowing Source Port from the set
    sprintf(command, "sudo nft add rule inet %s input tcp sport @%s drop", TABLE_NAME, SRC_PORT_SET);
    result = system(command);
    if (result == -1)
    {
        perror("Error during Intial rule setup...");
        return;
    }

    // Allowing Destination Port from the set
    sprintf(command, "sudo nft add rule inet %s input tcp dport @%s drop", TABLE_NAME, DES_PORT_SET);
    result = system(command);
    if (result == -1)
    {
        perror("Error during Intial rule setup...");
        return;
    }

    // Allowing Source IP Address from the set
    sprintf(command, "sudo nft add rule inet %s input ip saddr @%s drop", TABLE_NAME, SRC_IP_SET);
    result = system(command);
    if (result == -1)
    {
        perror("Error during Intial rule setup...");
        return;
    }

    // Allowing Destination IP Address from the set
    sprintf(command, "sudo nft add rule inet %s input ip daddr @%s drop", TABLE_NAME, DES_IP_SET);
    result = system(command);
    if (result == -1)
    {
        perror("Error during Intial rule setup...");
        return;
    }

    // Allowing Connection Tracking

    sprintf(command, "sudo nft add rule inet %s input ct state established, related accept", TABLE_NAME);
    result = system(command);
    if (result == -1)
    {
        perror("Error during Initial rule setup...");
        return;
    }

    sprintf(command, "sudo nft add rule inet %s output ct state established, related accept", TABLE_NAME);
    result = system(command);
    if (result == -1)
    {
        perror("Error during Initial rule setup...");
        return;
    }

    // Adding Essential Ports and IP
    // sprintf(command, "sudo nft add element inet %s %s '{8080}'", TABLE_NAME, SRC_PORT_SET);
    // result = system(command);
    // if (result == -1)
    // {
    //     perror("Unable to allow the port...");
    //     return;
    // }

    // sprintf(command, "sudo nft add element inet %s %s '{8080}'", TABLE_NAME, DES_PORT_SET);
    // result = system(command);
    // if (result == -1)
    // {
    //     perror("Unable to allow the port...");
    //     return;
    // }

    // sprintf(command, "sudo nft add element inet %s %s '{127.0.0.1/32}'", TABLE_NAME, SRC_IP_SET);
    // result = system(command);
    // if (result == -1)
    // {
    //     perror("Unable to allow the port...");
    //     return;
    // }

    sprintf(command, "sudo nft add element inet %s %s '{127.0.0.1/32}'", TABLE_NAME, DES_IP_SET);
    result = system(command);
    if (result == -1)
    {
        perror("Unable to allow the port...");
        return;
    }

    return;
}

void init_firewall()
{
    create_table();
    create_port_sets();
    create_IP_sets();
    create_chains();
    initial_rules();
}

void update_port_rules(char *buffer)
{
    struct PortRequest *pr = (struct PortRequest *)buffer;
    int result;

    switch (pr->operation)
    {
    case 0:
    {
        // Port Blocking request
        int port = pr->port;
        switch (pr->type)
        {
        case 0:
        {
            sprintf(command, "sudo nft delete element inet %s %s '{%d}'", TABLE_NAME, SRC_PORT_SET, port);
            result = system(command);
            if (result == -1)
            {
                perror("Unable to allow the port...");
                return;
            }
        }
        case 1:
        {
            sprintf(command, "sudo nft delete element inet %s %s '{%d}'", TABLE_NAME, DES_PORT_SET, port);
            result = system(command);
            if (result == -1)
            {
                perror("Unable to allow the port...");
                return;
            }
        }
        default:
            return;
        }
        return;
    }
    case 1:
    {
        // Port Accepting request
        int port = pr->port;
        switch (pr->type)
        {
        case 0:
        {
            sprintf(command, "sudo nft add element inet %s %s '{%d}'", TABLE_NAME, SRC_PORT_SET, port);
            result = system(command);
            if (result == -1)
            {
                perror("Unable to allow the port...");
                return;
            }
        }
        case 1:
        {
            sprintf(command, "sudo nft add element inet %s %s '{%d}'", TABLE_NAME, DES_PORT_SET, port);
            result = system(command);
            if (result == -1)
            {
                perror("Unable to allow the port...");
                return;
            }
        }
        default:
            return;
        }
        return;
    }
    }

    return;
}

void update_ip_rules(char *buffer)
{
    struct IPAddressRequest *ir = (struct IPAddressRequest *)buffer;
    return;
}

void handle_client(int socket)
{
    char buffer[BUFFER_SIZE] = {0};
    while (true)
    {
        int valread = read(socket, buffer, BUFFER_SIZE);
        if (valread == 0)
        {
            printf("Client closed\n");
            return;
        }
        if (valread == -1)
        {
            perror("Error during reading data...\n");
            return;
        }
        if (int(buffer[0]) == 0)
        {
            update_port_rules(buffer + 1);
            continue;
        }
        if (int(buffer[0]) == 1)
        {
            update_ip_rules(buffer + 1);
            continue;
        }
    }
    return;
}

int main()
{
    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
    char buffer[BUFFER_SIZE] = {0};
    const char *hello = "Hello from server";

    //  Create socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
    {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }

    //  Define the server address with a specific IP
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = inet_addr("127.0.0.1"); // Bind to specific IP
    address.sin_port = htons(PORT);

    // Bind the socket to the specified IP and port
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0)
    {
        perror("Bind failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    // Initialising Firewall
    init_firewall();

    // Start listening for incoming connections
    if (listen(server_fd, 3) < 0)
    {
        perror("Listen");
        close(server_fd);
        exit(EXIT_FAILURE);
    }
    printf("Server is listening on IP 127.0.0.1 port %d...\n", PORT);

    // Accept an incoming connection
    if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen)) < 0)
    {
        perror("Accept");
        close(server_fd);
        exit(EXIT_FAILURE);
    }
    printf("Connection accepted\n");

    handle_client(new_socket);

    // Close the socket
    close(new_socket);
    close(server_fd);

    return 0;
}
