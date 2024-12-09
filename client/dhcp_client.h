#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#include <sys/ioctl.h>
#include <net/if.h>

#define BOOT_REQUEST 0x01
#define BOOT_RESPONSE 0x02
#define ETHERNET 0x01
#define ETHERNET_ADDR_LEN 0x06

#define OPTIONS_MSG_TYPE 0x53

typedef enum {
    DHCP_DISCOVER = 0x1,
    DHCP_OFFER = 0x2,
    DHCP_REQUEST = 0x3,
    DHCP_DECLINE = 0x4,
    DHCP_ACK = 0x5,
    DHCP_NAK = 0x6,
    DHCP_RELEASE = 0x7
} msg_type;

struct dhcp_packet
{
    uint8_t op_code;
    uint8_t hw_type;
    uint8_t hw_address_len;
    uint8_t hops;

    uint32_t xid; // Transaction ID
    uint16_t secs;
    uint16_t flags;

    uint32_t ciaddr; // Client IP Address
    uint32_t yiaddr; // Your IP Address
    uint32_t siaddr; // Server IP Address
    uint32_t giaddr; // Gateway IP Address

    char chaddr[16]; // Client Hardware Address
    char sname[64]; // Server Name

    char file[128];

    uint8_t options[312]; 
};
