#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#include <time.h>

#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if.h>
#include <string.h>

#include "dhcp_server.h"

int assign_mac_address(int sock, const char *interface_name, struct dhcp_packet *packet) {
    struct ifreq ifr;
    
    strcpy(ifr.ifr_name, interface_name);

    if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) {
        perror("IOCTL Error");
        return -1;
    }

    memcpy(packet->chaddr, ifr.ifr_ifru.ifru_hwaddr.sa_data, ETHERNET_ADDR_LEN);

    return 0;
}

void set_dhcp_msg_type(uint8_t *ptr, msg_type type) {
    *ptr++ = OPTIONS_MSG_TYPE;
    *ptr++ = 1;
    *ptr++ = type;
}

void set_discover_options(struct dhcp_packet *packet) {
    uint8_t *options_ptr = packet->options;

    *(uint32_t *)options_ptr = htonl(0x63825363);
    options_ptr += 4;

    set_dhcp_msg_type(options_ptr, DHCP_DISCOVER);

    // Add DHCP Option 55: Parameter Request List
    *options_ptr++ = 55;  // Option code for Parameter Request List
    *options_ptr++ = 3;   // Length of option data
    *options_ptr++ = 1;   // Subnet Mask
    *options_ptr++ = 3;   // Router
    *options_ptr++ = 6;   // DNS Server

    *options_ptr++ = 255; // End Option
}

void dhcp_discover(const char *interface) {
    srand(time(NULL));

    struct dhcp_packet *packet;

    packet = malloc(sizeof(struct dhcp_packet));

    packet->op_code = BOOT_REQUEST;
    packet->hw_type = ETHERNET;
    packet->hw_address_len = ETHERNET_ADDR_LEN;
    packet->hops = 0;
    packet->xid = htonl((rand() << 16) | rand());
    
    packet->secs = 0;
    packet->flags = htons(0x8000);

    packet->ciaddr = 0;
    packet->yiaddr = 0;
    packet->siaddr = 0;
    packet->giaddr = 0;

    int sock;
    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    
    if(sock < 0){
        perror("Cannot create socket");
        exit(EXIT_FAILURE);
    }

    int mac_err = assign_mac_address(sock, interface, packet);

    if(mac_err < 0){
        perror("Cannot copy MAC Address");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in dest_addr;

    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(67);
    dest_addr.sin_addr.s_addr = INADDR_BROADCAST;

    int enabled = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, (char*) &enabled, sizeof(sock)) < 0) {
        perror("Error setting broadcast option");
        close(sock);
        exit(EXIT_FAILURE);
    }

    set_discover_options(packet);



    int packet_len = sizeof(struct dhcp_packet);
    int send_err = sendto(sock, packet, packet_len, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));

    if(send_err < 0) {
        printf("err num %d", send_err);
        perror("Failed sendto");
        close(sock);
        exit(EXIT_FAILURE);
    }

    printf("DHCP Discover packet sent successfully\n");
    printf("XID: %x \n", htonl(packet->xid));

    close(sock);

    free(packet);
}

int main() {
    const char *interface = "wlp2s0";

    dhcp_discover(interface);

    return 0;
}