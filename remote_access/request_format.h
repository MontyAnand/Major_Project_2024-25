#include<stdint.h>

#define PORT 8080
#define BUFFER_SIZE 1024
#define TABLE_NAME "Remote_Access"
#define SRC_PORT_SET "src"
#define DES_PORT_SET "des"
#define SRC_IP_SET "sip"
#define DES_IP_SET "dip"

char command[150] = {0};

// Protocol => 0
struct PortRequest{
    uint8_t operation; // Block = 0, Allow = 1
    uint16_t port;
    uint8_t type; // Source = 0, Destination = 1
};

// Protocol => 1
struct IPAddressReuqest{
    uint8_t opration;  // Block = 0, Allow = 1  
    uint32_t IP;
    uint8_t netmask;
    uint8_t type; // Source = 0, Destination = 1
};




