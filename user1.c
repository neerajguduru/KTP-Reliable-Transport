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

void ensure_test_file(const char* filename) {
    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        printf("[User 1] '%s' not found. Generating a 100 KB dummy file...\n", filename);
        fp = fopen(filename, "wb");
        if (!fp) {
            perror("Failed to create dummy file");
            exit(EXIT_FAILURE);
        }
        char block[1024];
        memset(block, 'A', 1024); // Fill with dummy data
        for (int i = 0; i < 100; i++) {
            fwrite(block, 1, 1024, fp);
        }
        fclose(fp);
    } else {
        fclose(fp);
    }
}

int main(int argc, char *argv[]) {
    struct in_addr src_ip, dst_ip;
    inet_pton(AF_INET, "127.0.0.1", &src_ip);
    inet_pton(AF_INET, "127.0.0.1", &dst_ip);
    
    int sockfd = k_socket(AF_INET, SOCK_KTP, 0);
    if (sockfd < 0) {
        printf("k_socket failed\n");
        return 1;
    }
    
    // Bind: Local port 8080, Remote target port 8081
    if (k_bind(sockfd, src_ip, 8080, dst_ip, 8081) < 0) {
        printf("k_bind failed\n");
        return 1;
    }

    const char* filename = "input.txt";
    ensure_test_file(filename);

    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        perror("Failed to open input file");
        return 1;
    }

    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_addr = dst_ip;
    dest.sin_port = htons(8081);

    printf("========================================\n");
    printf("[User 1] KTP File Sender Ready.\n");
    printf("Sending '%s' (100 KB) in chunks...\n", filename);
    printf("========================================\n");

    char buffer[MSG_PAYLOAD_SIZE];
    int chunks_sent = 0;
    size_t bytes_read;

    while ((bytes_read = fread(buffer, 1, MSG_PAYLOAD_SIZE, fp)) > 0) {
        if (bytes_read < MSG_PAYLOAD_SIZE) {
            memset(buffer + bytes_read, 0, MSG_PAYLOAD_SIZE - bytes_read);
        }

        // Retry limit extended enough to outlast maximum T timeouts (15 seconds buffer)
        int retries = 30000; 
        while (1) {
            ssize_t sent = k_sendto(sockfd, buffer, MSG_PAYLOAD_SIZE, 0, (struct sockaddr *)&dest, sizeof(dest));
            
            if (sent < 0) {
                if (ktp_error == ENOSPACE) {
                    if (--retries == 0) {
                        printf("[User 1] Receiver stopped responding. Exiting safely.\n");
                        fclose(fp);
                        k_close(sockfd);
                        return 1;
                    }
                    usleep(10000); 
                    continue;
                } else {
                    printf("Send failed with error code: %d\n", ktp_error);
                    fclose(fp);
                    return 1;
                }
            }
            break; 
        }
        chunks_sent++;
        if (chunks_sent % 20 == 0) {
            printf("[User 1] Queued %d chunks...\n", chunks_sent);
        }
    }
    fclose(fp);

    // Send EOF indicator
    memset(buffer, 0, MSG_PAYLOAD_SIZE);
    strcpy(buffer, "<KTP_EOF>");
    
    int eof_retries = 30000;
    while (k_sendto(sockfd, buffer, MSG_PAYLOAD_SIZE, 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        if (--eof_retries == 0) break;
        usleep(10000);
    }
    chunks_sent++;

    printf("\n[User 1] File read complete. Total messages queued: %d.\n", chunks_sent);
    
    k_close(sockfd);
    printf("[User 1] Clean exit.\n");
    return 0;
}