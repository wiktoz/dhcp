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
#include <sys/time.h>

#include "dhcp_client.h"

#define DHCP_SERVER_PORT 67
#define DHCP_CLIENT_PORT 68

const char *interface = "wlp2s0";

void assign_mac_address(int sock, const char *interface_name, struct dhcp_packet *packet) {
    struct ifreq ifr;
    
    strcpy(ifr.ifr_name, interface_name);

    if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) {
        perror("IOCTL Error");
        exit(EXIT_FAILURE);
    }

    memcpy(packet->chaddr, ifr.ifr_ifru.ifru_hwaddr.sa_data, ETHERNET_ADDR_LEN);
}

uint8_t* set_dhcp_msg_type(uint8_t *ptr, msg_type type) {
    *ptr++ = 53;
    *ptr++ = 1;
    *ptr++ = 1;

    return ptr;
}

void set_discover_options(struct dhcp_packet *packet) {
    uint8_t *options_ptr = packet->options;

    *(uint32_t *)options_ptr = htonl(0x63825363);
    options_ptr += 4;

    options_ptr = set_dhcp_msg_type(options_ptr, DHCP_DISCOVER);

    // Add DHCP Option 55: Parameter Request List
    *options_ptr++ = 55;  // Option code for Parameter Request List
    *options_ptr++ = 3;   // Length of option data
    *options_ptr++ = 1;   // Subnet Mask
    *options_ptr++ = 3;   // Router
    *options_ptr++ = 6;   // DNS Server

    *options_ptr++ = 255; // End Option
}

void dhcp_discover(int sock, const char *interface) {
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

    set_discover_options(packet);

    assign_mac_address(sock, interface, packet);

    struct sockaddr_in dest_addr;

    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(DHCP_SERVER_PORT);
    dest_addr.sin_addr.s_addr = INADDR_BROADCAST;

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

    free(packet);
}

void listen_dhcp_offer(int sock) {
    uint8_t buffer[1024];
    struct sockaddr_in from;
    socklen_t from_len = sizeof(from);

    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(sock, &readfds);

    printf("Listening for DHCP Offer...\n");

    while (1) {
        struct timeval timeout;
        timeout.tv_sec = 10;  // 10 seconds timeout
        timeout.tv_usec = 0;

        // Wait for 10 seconds or until a packet is received
        int ret = select(sock + 1, &readfds, NULL, NULL, &timeout);

        if (ret == -1) {
            perror("select");
            exit(EXIT_FAILURE);
        } else if (ret == 0) {
            // Timeout, no packet received in 10 seconds
            printf("Timeout: No DHCP Offer received in 10 seconds. Resending DHCP Discover...\n");
            dhcp_discover(sock, interface);

            continue;
        }

        // Receive the packet if select indicates it's ready
        ssize_t len = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&from, &from_len);
        if (len < 0) {
            perror("recvfrom");
            exit(EXIT_FAILURE);
        }

        // Cast the buffer to a DHCP packet structure for easier parsing
        struct dhcp_packet *packet = (struct dhcp_packet *)buffer;

        // Check for DHCP Offer
        uint8_t *options = packet->options + 4; // Skip magic cookie
        while (*options != 255) {
            if (*options == 53 && options[1] == 1 && options[2] == DHCP_OFFER) {
                printf("Received DHCP Offer from server.\n");
                return;
            }
            options += 2 + options[1]; // Move to next option
        }

        printf("No valid DHCP Offer found in the received packet.\n");
    }
}


int main() {
    int sock;
    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    
    if(sock < 0){
        perror("Cannot create socket");
        exit(EXIT_FAILURE);
    }

    int enabled = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, (char*) &enabled, sizeof(sock)) < 0) {
        perror("Error setting broadcast option");
        close(sock);
        exit(EXIT_FAILURE);
    }

    // Bind the socket to DHCP client port
    struct sockaddr_in client_addr = {0};
    client_addr.sin_family = AF_INET;
    client_addr.sin_port = htons(DHCP_CLIENT_PORT);
    client_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sock, (struct sockaddr *)&client_addr, sizeof(client_addr)) < 0) {
        perror("bind");
        exit(EXIT_FAILURE);
    }

    dhcp_discover(sock, interface);
    listen_dhcp_offer(sock);

    close(sock);

    return 0;
}