#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "dhcp_client.h"

#define DHCP_SERVER_PORT 67
#define BUFFER_SIZE 1024

const uint8_t DHCP_MAGIC_COOKIE[4] = {0x63, 0x82, 0x53, 0x63};

int main() {
    int sockfd;
    struct sockaddr_in server_addr, client_addr;
    char buffer[BUFFER_SIZE];
    socklen_t client_len = sizeof(client_addr);

    // Create a UDP socket
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Bind the socket to port 67
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY; // Listen on all interfaces
    server_addr.sin_port = htons(DHCP_SERVER_PORT);

    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    printf("Listening for DHCP packets on port %d...\n", DHCP_SERVER_PORT);

    // Wait for incoming packets
    while (1) {
        ssize_t recv_len = recvfrom(sockfd, buffer, BUFFER_SIZE, 0,
                                    (struct sockaddr *)&client_addr, &client_len);
        if (recv_len < 0) {
            perror("recvfrom failed");
            continue;
        }

        printf("Received packet from %s:%d\n",
               inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
        printf("Packet size: %ld bytes\n", recv_len);

        struct dhcp_packet *packet = (struct dhcp_packet *)buffer;

        if (memcmp(packet->options, DHCP_MAGIC_COOKIE, 4) != 0) {
            printf("Invalid DHCP magic cookie\n");
            return 0;
        }
        printf("Valid DHCP packet received. Transaction ID: 0x%x\n", ntohl(packet->xid));


    }

    close(sockfd);
    return 0;
}
