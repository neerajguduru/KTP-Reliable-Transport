/*
Mini Project 1 Submission
Group Details:
Member 1 Name: Guduru Neeraj Reddy 
Member 1 Roll number: 23CS10022
Member 2 Name: Gampa Reshwik
Member 2 Roll number: 23CS30020
*/

#include "ksocket.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

int main(int argc, char *argv[]) {
    struct in_addr src_ip, dst_ip;
    inet_pton(AF_INET, "127.0.0.1", &src_ip);
    inet_pton(AF_INET, "127.0.0.1", &dst_ip);
    
    int sockfd = k_socket(AF_INET, SOCK_KTP, 0);
    if (sockfd < 0) {
        printf("k_socket failed\n");
        return 1;
    }
    
    // Bind: Local port 8081, Remote target port 8080
    if (k_bind(sockfd, src_ip, 8081, dst_ip, 8080) < 0) {
        printf("k_bind failed\n");
        return 1;
    }
    
    char buffer[MSG_PAYLOAD_SIZE];
    struct sockaddr_in src_addr;
    socklen_t addrlen = sizeof(src_addr);

    const char* filename = "output.txt";
    FILE *fp = fopen(filename, "wb");
    if (!fp) {
        perror("Failed to open output file");
        return 1;
    }

    printf("========================================\n");
    printf("[User 2] KTP File Receiver Ready.\n");
    printf("Waiting for file data, writing to '%s'...\n", filename);
    printf("========================================\n");

    int chunks_received = 0;

    while (1) {
        ssize_t recvd = k_recvfrom(sockfd, buffer, MSG_PAYLOAD_SIZE, 0, (struct sockaddr *)&src_addr, &addrlen);
        
        if (recvd < 0) {
            if (ktp_error == ENOMESSAGE) {
                usleep(10000); // Sleep 10ms if buffer is empty and check again
                continue;
            } else {
                printf("Receive failed with error code: %d\n", ktp_error);
                break;
            }
        }

        // Check for EOF packet
        if (strncmp(buffer, "<KTP_EOF>", 9) == 0) {
            printf("\n[User 2] EOF received. File transfer complete.\n");
            break;
        }

        // Write the full 512-byte payload to the file
        fwrite(buffer, 1, MSG_PAYLOAD_SIZE, fp);
        
        chunks_received++;
        if (chunks_received % 20 == 0) {
            printf("[User 2] Received and wrote %d chunks...\n", chunks_received);
        }
    }

    printf("[User 2] Total data chunks written: %d\n", chunks_received);
    fclose(fp);

    printf("[User 2] Waiting a few seconds to ACK any dropped final packets...\n");
    sleep(6); 

    k_close(sockfd);
    printf("[User 2] Clean exit.\n");
    return 0;
}