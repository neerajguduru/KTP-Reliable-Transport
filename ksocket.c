// KTP socket library
#include "ksocket.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

// Shared memory pointer, set once on first attach 
ktp_socket_entry_t *SM = NULL;
// Global error code set by library functions to indicate failure reason
int ktp_error = 0;
// Flag ensuring shared memory is attached at most once per process
static bool shm_attached = false;

static int attach_shm() {
    // Skip attachment if this process already has a valid SM pointer
    if (shm_attached) return 0;
    key_t shm_key = ftok(SHM_PATH, SHM_ID);
    if (shm_key == -1) return -1;

    // Look up the existing shared memory segment
    int shm_id = shmget(shm_key, MAX_KTP_SOCKETS * sizeof(ktp_socket_entry_t), 0666);
    if (shm_id == -1) return -1;

    SM = (ktp_socket_entry_t *)shmat(shm_id, NULL, 0);
    if (SM == (void *)-1) return -1;
    shm_attached = true;
    return 0;
}

// Acquire the per-slot mutex 
static void lock_ktp(int i) {
    pthread_mutex_lock(&SM[i].mutex);
}

// Release the per-slot mutex 
static void unlock_ktp(int i) {
    pthread_mutex_unlock(&SM[i].mutex);
}

// Allocate a free KTP socket slot 
int k_socket(int domain, int type, int protocol) {
    if (type != SOCK_KTP) { errno = EINVAL; return -1; }
    if (attach_shm() < 0) return -1;
    int free_idx = -1;

    // Scan all slots to find the first one not currently owned by a process
    for (int i = 0; i < MAX_KTP_SOCKETS; i++) {
        lock_ktp(i);
        if (!SM[i].is_allotted) {
            // Mark slot as owned and record this process's PID
            SM[i].is_allotted = true;
            SM[i].pid = getpid();

            // UDP socket will be created by daemon after k_bind is called
            SM[i].udp_sockfd = -1;
            SM[i].is_bound = false;
            SM[i].send_head = 0;
            SM[i].send_tail = 0;
            SM[i].send_count = 0;

            // Clear receive buffer slot flags and reset head index
            memset(SM[i].recv_filled, 0, sizeof(SM[i].recv_filled));
            SM[i].recv_buf_head = 0;
            SM[i].recv_buf_count = 0;
            SM[i].nospace = false;

            // Set both windows to maximum initial size and first sequence number
            SM[i].swnd.window_size = WINDOW_SIZE;
            SM[i].rwnd.window_size = WINDOW_SIZE;
            SM[i].swnd.base = 1;
            SM[i].swnd.next_seq = 1;
            SM[i].rwnd.base_seq = 1;

            free_idx = i;
            unlock_ktp(i);
            break;
        }
        unlock_ktp(i);
    }

    // No free slot found
    if (free_idx == -1) { ktp_error = ENOSPACE; return -1; }
    return free_idx;
}

// Store local and remote addresses in SM
int k_bind(int sockfd, struct in_addr src_ip, int src_port, struct in_addr dst_ip, int dst_port) {
    if (sockfd < 0 || sockfd >= MAX_KTP_SOCKETS) return -1;
    lock_ktp(sockfd);

    // Refuse to bind a slot that hasn't been allocated by k_socket
    if (!SM[sockfd].is_allotted) { unlock_ktp(sockfd); return -1; }

    // Fill in local address that the daemon will bind the UDP socket to
    SM[sockfd].local_addr.sin_family = AF_INET;
    SM[sockfd].local_addr.sin_addr = src_ip;
    SM[sockfd].local_addr.sin_port = htons(src_port);

    // Store remote peer address for validating outgoing and incoming packets
    SM[sockfd].remote_addr.sin_family = AF_INET;
    SM[sockfd].remote_addr.sin_addr = dst_ip;
    SM[sockfd].remote_addr.sin_port = htons(dst_port);

    // Signal daemon 
    SM[sockfd].is_bound = true;
    unlock_ktp(sockfd);
    return 0;
}

// Enqueue one 512-byte message into the send buffer
ssize_t k_sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen) {
    if (sockfd < 0 || sockfd >= MAX_KTP_SOCKETS) return -1;
    lock_ktp(sockfd);

    if (!SM[sockfd].is_allotted || !SM[sockfd].is_bound) { ktp_error = ENOTBOUND; unlock_ktp(sockfd); return -1; }

    const struct sockaddr_in *dest_in = (const struct sockaddr_in *)dest_addr;

    // Destination must match the peer address recorded 
    if (dest_in->sin_addr.s_addr != SM[sockfd].remote_addr.sin_addr.s_addr ||
        dest_in->sin_port != SM[sockfd].remote_addr.sin_port) {
        ktp_error = ENOTBOUND; unlock_ktp(sockfd); return -1;
    }

    // Reject oversized payloads or writes when the send buffer is full
    if (len > MSG_PAYLOAD_SIZE || SM[sockfd].send_count == SEND_BUFFER_SIZE) {
        ktp_error = ENOSPACE; unlock_ktp(sockfd); return -1;
    }

    // Zero-pad tail slot before copying to avoid leaking stale bytes
    memset(SM[sockfd].send_buffer[SM[sockfd].send_tail], 0, MSG_PAYLOAD_SIZE);
    memcpy(SM[sockfd].send_buffer[SM[sockfd].send_tail], buf, len);
    // Advance tail pointer circularly and increment the pending message count
    SM[sockfd].send_tail = (SM[sockfd].send_tail + 1) % SEND_BUFFER_SIZE;
    SM[sockfd].send_count++;
    unlock_ktp(sockfd);

    // Return full payload size since KTP is message-oriented
    return MSG_PAYLOAD_SIZE;
}

// Return the next in-order message from the receive buffer to the caller
ssize_t k_recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen) {
    if (sockfd < 0 || sockfd >= MAX_KTP_SOCKETS) return -1;
    lock_ktp(sockfd);
    if (!SM[sockfd].is_allotted) { unlock_ktp(sockfd); return -1; }

    // Return immediately if no in-order message is ready at the head slot
    if (!SM[sockfd].recv_filled[SM[sockfd].recv_buf_head]) { ktp_error = ENOMESSAGE; unlock_ktp(sockfd); return -1; }

    // Copy the smaller of requested length and fixed message payload size
    size_t copy_len = (len < MSG_PAYLOAD_SIZE) ? len : MSG_PAYLOAD_SIZE;
    memcpy(buf, SM[sockfd].recv_buffer[SM[sockfd].recv_buf_head].payload, copy_len);

    // Clear the slot and advance head to expose the next buffered message
    SM[sockfd].recv_filled[SM[sockfd].recv_buf_head] = false;
    SM[sockfd].recv_buf_head = (SM[sockfd].recv_buf_head + 1) % WINDOW_SIZE;

    // Advance expected base sequence number now that this message is consumed
    SM[sockfd].rwnd.base_seq++;
    SM[sockfd].recv_buf_count--;

    // One slot freed, increase receiver window to let sender transmit more
    SM[sockfd].rwnd.window_size++;

    // Return the sender's address to the caller if buffer provided
    if (src_addr != NULL && addrlen != NULL) {
        *addrlen = sizeof(struct sockaddr_in);
        memcpy(src_addr, &SM[sockfd].remote_addr, *addrlen);
    }

    unlock_ktp(sockfd);
    return copy_len;
}

// Wait for send buffer to drain
int k_close(int sockfd) {
    if (sockfd < 0 || sockfd >= MAX_KTP_SOCKETS) return -1;

    printf("[KTP] Closing socket %d. Waiting for pending packets to flush...\n", sockfd);
    // Allow up to 15 seconds for in-flight messages to be acknowledged
    int max_retries = 3000;

    while (max_retries > 0) {
        lock_ktp(sockfd);

        // If socket was freed by daemon or another call, stop waiting
        if (!SM[sockfd].is_allotted) {
            unlock_ktp(sockfd);
            return -1;
        }

        // All messages sent and acknowledged
        if (SM[sockfd].send_count == 0 &&
            SM[sockfd].swnd.base == SM[sockfd].swnd.next_seq) {
            SM[sockfd].is_allotted = false;
            unlock_ktp(sockfd);
            printf("[KTP] Socket %d flushed and closed cleanly.\n", sockfd);
            return 0;
        }

        unlock_ktp(sockfd);
        // Poll every 100ms to check if all pending messages are acknowledged
        usleep(100000);
        max_retries--;
    }

    // Timeout reached
    printf("[KTP] Socket %d flush timeout. Force closing.\n", sockfd);

    lock_ktp(sockfd);
    if (SM[sockfd].is_allotted) {
        SM[sockfd].is_allotted = false;
    }
    
    unlock_ktp(sockfd);
    return 0;
}

bool dropMessage(float p) {
    // Initialize seed from clock and thread ID 
    static __thread unsigned int seed = 0;
    if (seed == 0) {
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        seed = ts.tv_nsec ^ (unsigned int)pthread_self() ^ getpid();
    }

    float r = (float)rand_r(&seed) / (float)RAND_MAX;
    return r < p;
}