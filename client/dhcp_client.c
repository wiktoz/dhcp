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

#include <unistd.h>
#include <netinet/in.h>
#include <linux/route.h>

#include "dhcp_client.h"

#define DHCP_SERVER_PORT 67
#define DHCP_CLIENT_PORT 68
#define BUFFER_SIZE 1024

const char *interface = "ens4";

// Function to set the IP address
int set_ip_address(int sock, const char *interface, uint32_t ip_address) {
    struct ifreq ifr;

    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);
    struct sockaddr_in *addr = (struct sockaddr_in *)&ifr.ifr_addr;
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = ip_address;

    if (ioctl(sock, SIOCSIFADDR, &ifr) < 0) {
        perror("Failed to set IP address");
        return -1;
    }

    return 0;
}

// Function to set the subnet mask
int set_subnet_mask(int sock, const char *interface, uint32_t subnet_mask) {
    struct ifreq ifr;

    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);
    struct sockaddr_in *addr = (struct sockaddr_in *)&ifr.ifr_netmask;
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = subnet_mask;

    if (ioctl(sock, SIOCSIFNETMASK, &ifr) < 0) {
        perror("Failed to set subnet mask");
        return -1;
    }

    return 0;
}

// Function to set the default gateway
int set_gateway(int sock, uint32_t gateway_ip) {
    struct rtentry route;

    memset(&route, 0, sizeof(route));
    struct sockaddr_in *addr = (struct sockaddr_in *)&route.rt_gateway;
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = gateway_ip;

    addr = (struct sockaddr_in *)&route.rt_dst;
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = INADDR_ANY;

    addr = (struct sockaddr_in *)&route.rt_genmask;
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = INADDR_ANY;

    route.rt_flags = RTF_UP | RTF_GATEWAY;

    if (ioctl(sock, SIOCADDRT, &route) < 0) {
        perror("Failed to set default gateway");
        return -1;
    }

    return 0;
}

void get_mac_address(int sock, const char *interface_name, char *chaddr) {
    struct ifreq ifr;
    
    strcpy(ifr.ifr_name, interface_name);

    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        perror("IOCTL Error");
        exit(EXIT_FAILURE);
    }

    memcpy(chaddr, ifr.ifr_ifru.ifru_hwaddr.sa_data, ETHERNET_ADDR_LEN);
}

uint8_t* set_dhcp_msg_type_discover(uint8_t *ptr) {
    *ptr++ = 53;
    *ptr++ = 1;
    *ptr++ = 1;

    return ptr;
}

uint8_t* set_dhcp_msg_type_request(uint8_t *ptr) {
    *ptr++ = 53;
    *ptr++ = 1;
    *ptr++ = 3;

    return ptr;
}

void set_discover_options(struct dhcp_packet *packet) {
    uint8_t *options_ptr = packet->options;

    *(uint32_t *)options_ptr = htonl(0x63825363);
    options_ptr += 4;

    options_ptr = set_dhcp_msg_type_discover(options_ptr);

    // Add DHCP Option 55: Parameter Request List
    *options_ptr++ = 55;  // Option code for Parameter Request List
    *options_ptr++ = 3;   // Length of option data
    *options_ptr++ = 1;   // Subnet Mask
    *options_ptr++ = 3;   // Router
    *options_ptr++ = 6;   // DNS Server

    *options_ptr++ = 255; // End Option
}

void set_request_options(struct dhcp_packet *packet, uint32_t *requested_ip, uint32_t *server_ip) {
    uint8_t *options_ptr = packet->options;

    *(uint32_t *)options_ptr = htonl(0x63825363);
    options_ptr += 4;

    options_ptr = set_dhcp_msg_type_request(options_ptr);

    *options_ptr++ = 50;  // Option code for Requested IP
    *options_ptr++ = 4;   // Length of IP addr
    memcpy(options_ptr, requested_ip, 4);
    options_ptr += 4;

    *options_ptr++ = 54;
    *options_ptr++ = 4;
    memcpy(options_ptr, server_ip, 4);
    options_ptr += 4;

    *options_ptr++ = 255; // End Option
}

void dhcp_request(int sock, char *chaddr, uint32_t *xid, uint32_t *requested_ip, uint32_t *server_ip) {
    struct dhcp_packet *packet;

    packet = malloc(sizeof(struct dhcp_packet));

    packet->op_code = BOOT_REQUEST;
    packet->hw_type = ETHERNET;
    packet->hw_address_len = ETHERNET_ADDR_LEN;
    packet->hops = 0;
    packet->xid = *xid;

    packet->secs = 0;
    packet->flags = htons(0x8000);

    packet->ciaddr = 0;
    packet->yiaddr = 0;
    packet->siaddr = 0;
    packet->giaddr = 0;

    memcpy(&packet->chaddr, chaddr, 16);

    set_request_options(packet, requested_ip, server_ip);

    int packet_len = sizeof(struct dhcp_packet);
    struct sockaddr_in server_addr = {0};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(DHCP_SERVER_PORT);
    server_addr.sin_addr.s_addr = INADDR_BROADCAST;
    int send_err = sendto(sock, packet, packet_len, 0, (struct sockaddr *)&server_addr, sizeof(server_addr));

    if(send_err < 0) {
        printf("err num %d", send_err);
        perror("Failed sendto");
        close(sock);
        exit(EXIT_FAILURE);
    }

    printf("DHCP Request packet sent successfully\n");
    printf("XID: %x \n", htonl(packet->xid));

    free(packet);
}

int32_t dhcp_discover(int sock, char *chaddr) {
    int32_t xid = htonl((rand() << 16) | rand());
    struct dhcp_packet *packet;

    packet = malloc(sizeof(struct dhcp_packet));

    packet->op_code = BOOT_REQUEST;
    packet->hw_type = ETHERNET;
    packet->hw_address_len = ETHERNET_ADDR_LEN;
    packet->hops = 0;
    packet->xid = xid;
    
    packet->secs = 0;
    packet->flags = htons(0x8000);

    packet->ciaddr = 0;
    packet->yiaddr = 0;
    packet->siaddr = 0;
    packet->giaddr = 0;

    memcpy(&packet->chaddr, chaddr, 16);

    set_discover_options(packet);

    int packet_len = sizeof(struct dhcp_packet);

    struct sockaddr_in server_addr = {0};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(DHCP_SERVER_PORT);
    server_addr.sin_addr.s_addr = INADDR_BROADCAST;

    int send_err = sendto(sock, packet, packet_len, 0, (struct sockaddr *)&server_addr, sizeof(server_addr));

    if(send_err < 0) {
        printf("err num %d", send_err);
        perror("Failed sendto");
        close(sock);
        exit(EXIT_FAILURE);
    }

    printf("DHCP Discover packet sent successfully\n");
    printf("XID: %x \n", htonl(packet->xid));

    free(packet);

    return xid;
}

void listen_dhcp_offer(int sock, uint32_t *requested_ip, uint32_t *server_ip) {
    uint8_t buffer[BUFFER_SIZE];
    struct sockaddr_in from;
    socklen_t from_len = sizeof(from);

    printf("Waiting for DHCP Offer...\n");

    ssize_t len = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&from, &from_len);
    if (len < 0) {
        perror("recvfrom");
        exit(EXIT_FAILURE);
    }

    struct dhcp_packet *packet = (struct dhcp_packet *)buffer;

    uint8_t *options = packet->options + 4;
    while (*options != 255) {
        if (*options == 53 && options[1] == 1 && options[2] == DHCP_OFFER) {
            printf("Received DHCP Offer from server.\n");
            memcpy(requested_ip, &packet->yiaddr, 4);
            memcpy(server_ip, &packet->siaddr, 4);
            return;
        }
        options += 2 + options[1]; // Move to next option
    }

    printf("No valid DHCP Offer found in the received packet.\n");
}

void listen_dhcp_ack(int sock) {
    uint8_t buffer[BUFFER_SIZE];
    struct sockaddr_in from;
    socklen_t from_len = sizeof(from);

    printf("Waiting for DHCP ACK...\n");

    ssize_t len = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&from, &from_len);
    if (len < 0) {
        perror("recvfrom");
        exit(EXIT_FAILURE);
    }

    struct dhcp_packet *packet = (struct dhcp_packet *)buffer;

    printf("Received DHCP ACK from server.\n");

    // Set IP Address (yiaddr)
    uint32_t ip_addr = ntohl(packet->yiaddr);
    printf("Assigned IP: %s\n", inet_ntoa(*(struct in_addr *)&packet->yiaddr));
    set_ip_address(sock, interface, htonl(ip_addr));

    // Parse DHCP Options
    uint8_t *options = packet->options + 4; // Skip magic cookie
    while (*options != 255) {
        uint8_t option_type = *options;
        uint8_t option_len = *(options + 1);

        if (option_type == 1 && option_len == 4) { // Subnet Mask
            uint32_t subnet_mask;
            memcpy(&subnet_mask, options + 2, 4);
            printf("Subnet Mask: %s\n", inet_ntoa(*(struct in_addr *)&subnet_mask));
            set_subnet_mask(sock, interface, subnet_mask);
        } else if (option_type == 3 && option_len == 4) { // Default Gateway
            uint32_t gateway;
            memcpy(&gateway, options + 2, 4);
            printf("Gateway: %s\n", inet_ntoa(*(struct in_addr *)&gateway));
            system("sudo ip route del default");
            set_gateway(sock, gateway);
        } else if (option_type == 53 && option_len == 1 && *(options + 2) == DHCP_ACK) { // DHCP Message Type
            printf("DHCP ACK received.\n");
        }

        options += 2 + option_len; // Move to the next option
    }
}


int main() {
    srand(time(NULL));

    char chaddr[16];
    uint32_t xid;

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

    struct sockaddr_in my_addr = {0};
    my_addr.sin_family = AF_INET;
    my_addr.sin_port = htons(DHCP_CLIENT_PORT);
    my_addr.sin_addr.s_addr = INADDR_ANY;
    

    int result = bind(sock, (struct sockaddr*)&my_addr, sizeof(my_addr));

    if(result < 0){
        perror("Cannot bind");
        exit(EXIT_FAILURE);
    }

    get_mac_address(sock, interface, chaddr);
    

    xid = dhcp_discover(sock, chaddr);

    uint32_t requested_ip;
    uint32_t server_ip;

    while (1) {
        struct timeval timeout;
        timeout.tv_sec = 10;
        timeout.tv_usec = 0;

        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(sock, &readfds);

        int ret = select(sock + 1, &readfds, NULL, NULL, &timeout);

        if (ret == -1) {
            perror("select");
            close(sock);
            exit(EXIT_FAILURE);
        } else if (ret == 0) {
            printf("Timeout: No DHCP Offer received in 10 seconds. Resending DHCP Discover...\n");
            xid = dhcp_discover(sock, chaddr);
            continue;
        }

        // Call listen_dhcp_offer if the socket is ready
        if (FD_ISSET(sock, &readfds)) {
            listen_dhcp_offer(sock, &requested_ip, &server_ip);
            break;
        }
    }

    dhcp_request(sock, chaddr, &xid, &requested_ip, &server_ip);

    listen_dhcp_ack(sock);

    printf("Success!\n");

    close(sock);

    return 0;
}