#ifndef KSOCKET_H
#define KSOCKET_H

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <pthread.h>

// Custom socket type identifier
#define SOCK_KTP 256
#define T 5
#define P_DROP 0.35
// Maximum number of simultaneous active KTP sockets 
#define MAX_KTP_SOCKETS 10
#define MSG_PAYLOAD_SIZE 512
#define WINDOW_SIZE 10
#define SEND_BUFFER_SIZE 20
// Path used with ftok to generate the shared memory key
#define SHM_PATH "/tmp"
#define SHM_ID 'L'

// Global error variable set by KTP functions on failure
extern int ktp_error;
// Error: no free slot in shared memory or no space in send buffer
#define ENOSPACE 1
// Error: socket not yet bound before a send or receive was attempted
#define ENOTBOUND 2
// Error: receive buffer is empty, no message available yet
#define ENOMESSAGE 3

// Message type indicating this packet carries payload data
#define MSG_DATA 1
// Message type indicating this packet is an acknowledgement 
#define MSG_ACK 2

// Format for all KTP packets, both data and ACK types
typedef struct {
    uint8_t seq_no;                
    uint8_t type;           
    uint8_t ack_num;               
    uint8_t rwnd_size;            
    char payload[MSG_PAYLOAD_SIZE]; 
} ktp_message_t;

// A single slot in the receive buffer, holding sequence number and payload
typedef struct {
    uint8_t seq_no;                
    char payload[MSG_PAYLOAD_SIZE]; 
} ktp_recv_slot_t;

// Sender window tracking base, next sequence to send, and current size
typedef struct {
    uint8_t window_size; 
    uint8_t base;        
    uint8_t next_seq;    
} sender_window_t;

// Receiver window tracking expected base sequence and available buffer space
typedef struct {
    uint8_t window_size; 
    uint8_t base_seq;   
} receiver_window_t;

// One entry per KTP socket
typedef struct {
    bool is_allotted;
    pid_t pid;
    int udp_sockfd;

    struct sockaddr_in local_addr;
    struct sockaddr_in remote_addr;
    bool is_bound;

    char send_buffer[SEND_BUFFER_SIZE][MSG_PAYLOAD_SIZE];
    struct timespec send_ts[SEND_BUFFER_SIZE];

    int send_head;
    int send_tail;
    int send_count;

    sender_window_t swnd;
    receiver_window_t rwnd;
    ktp_recv_slot_t recv_buffer[WINDOW_SIZE];
    bool recv_filled[WINDOW_SIZE];
    int recv_buf_head;
    int recv_buf_count;

    bool nospace;
    pthread_mutex_t mutex;
    pthread_mutexattr_t mutex_attr;
} ktp_socket_entry_t;

// Pointer to the shared memory array 
extern ktp_socket_entry_t *SM;

int k_socket(int domain, int type, int protocol);

int k_bind(int sockfd, struct in_addr src_ip, int src_port, struct in_addr dst_ip, int dst_port);

ssize_t k_sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen);

ssize_t k_recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen);

int k_close(int sockfd);

bool dropMessage(float p);

#endif 
