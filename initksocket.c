// Daemon process: Runs threads R and S for all KTP sockets
#include "ksocket.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/types.h>
#include <sys/select.h>
#include <signal.h>
#include <errno.h>

// Shared memory segment ID needed to detach and destroy on shutdown
int shm_id = -1;
// PID of the garbage collector child process 
pid_t gc_pid = -1;
int total_transmissions = 0;

// Clean up all resources when SIGINT or SIGTERM is received by daemon
void handle_shutdown(int signo) {
    printf("\n[Daemon] Caught signal %d. Shutting down...\n", signo);
    printf("[Daemon] *** TOTAL TRANSMISSIONS: %d ***\n", total_transmissions);

    if (gc_pid > 0) kill(gc_pid, SIGKILL);
    if (SM != (void *)-1 && SM != NULL) shmdt(SM);
    if (shm_id != -1) shmctl(shm_id, IPC_RMID, NULL);

    exit(0);
}

// Build and transmit a KTP ACK packet over the given UDP socket
static void send_ack(int sockfd, struct sockaddr_in *dest, uint8_t ack_num, uint8_t rwnd_size) {
    ktp_message_t msg;
    memset(&msg, 0, sizeof(msg));

    // Mark packet as ACK type and fill in cumulative acknowledgement number
    msg.type = MSG_ACK;
    msg.ack_num = ack_num;
    // Piggyback current receiver window size 
    msg.rwnd_size = rwnd_size;
    sendto(sockfd, &msg, sizeof(msg), 0, (struct sockaddr *)dest, sizeof(*dest));
}

// Build and transmit a KTP data packet with the given sequence number
static void send_data(int sockfd, struct sockaddr_in *dest, uint8_t seq_no, const char *payload) {
    ktp_message_t msg;
    memset(&msg, 0, sizeof(msg));

    // Assign sequence number and mark as data type before sending
    msg.seq_no = seq_no;
    msg.type = MSG_DATA;
    memcpy(msg.payload, payload, MSG_PAYLOAD_SIZE);
    sendto(sockfd, &msg, sizeof(msg), 0, (struct sockaddr *)dest, sizeof(*dest));
}

// Thread R: receive messages from all UDP sockets using select and dispatch
void *thread_R(void *arg) {
    fd_set read_fds;
    struct timeval tv;

    while (1) {
        FD_ZERO(&read_fds);
        int max_fd = -1;

        // Iterate all slots to handle cleanup, socket creation, and fd-set build
        for (int i = 0; i < MAX_KTP_SOCKETS; i++) {
            pthread_mutex_lock(&SM[i].mutex);

            if (!SM[i].is_allotted && SM[i].udp_sockfd >= 0) {
                close(SM[i].udp_sockfd);

                // Preserve mutex across memset so other threads aren't broken
                pthread_mutex_t temp_mutex = SM[i].mutex;
                pthread_mutexattr_t temp_attr = SM[i].mutex_attr;
                memset(&SM[i], 0, sizeof(ktp_socket_entry_t));
                SM[i].mutex = temp_mutex;
                SM[i].mutex_attr = temp_attr;

                SM[i].udp_sockfd = -1;
                SM[i].swnd.window_size = WINDOW_SIZE;
                SM[i].rwnd.window_size = WINDOW_SIZE;
                SM[i].swnd.base = 1;
                SM[i].swnd.next_seq = 1;
                SM[i].rwnd.base_seq = 1;
            }

            // Create the UDP socket now that k_bind has recorded the local address
            if (SM[i].is_allotted && SM[i].is_bound && SM[i].udp_sockfd == -1) {
                int fd = socket(AF_INET, SOCK_DGRAM, 0);
                if (fd >= 0) {
                    // Bind to the local address the user registered via k_bind
                    if (bind(fd, (struct sockaddr *)&SM[i].local_addr, sizeof(SM[i].local_addr)) == 0) {
                        SM[i].udp_sockfd = fd;
                    } else close(fd);
                }
            }

            // Add active bound socket to the fd_set for select monitoring
            if (SM[i].is_allotted && SM[i].is_bound && SM[i].udp_sockfd >= 0) {
                FD_SET(SM[i].udp_sockfd, &read_fds);
                if (SM[i].udp_sockfd > max_fd) max_fd = SM[i].udp_sockfd;
            }

            pthread_mutex_unlock(&SM[i].mutex);
        }

        // Use 100ms timeout so new sockets are picked up without long delay
        tv.tv_sec = 0;
        tv.tv_usec = 100000;
        int ready = select(max_fd + 1, &read_fds, NULL, NULL, &tv);
 
        if (ready < 0) {
            if (errno == EINTR) continue;
            sleep(1);
            continue;
        }
 
        // On timeout, check if any receiver was blocked on a full buffer
        if (ready == 0) {
            for (int i = 0; i < MAX_KTP_SOCKETS; i++) {
                pthread_mutex_lock(&SM[i].mutex);
                if (SM[i].is_allotted && SM[i].is_bound && SM[i].udp_sockfd >= 0) {
                    // Space is now free; send wake-up ACK to unblock the sender
                    if (SM[i].nospace && SM[i].rwnd.window_size > 0) {
                        int fd = SM[i].udp_sockfd;
                        struct sockaddr_in dest = SM[i].remote_addr;
                        uint8_t last_acked = (uint8_t)(SM[i].rwnd.base_seq - 1);
                        uint8_t wnd = SM[i].rwnd.window_size;
                        // Clear flag before unlock to avoid duplicate wake-up ACKs
                        SM[i].nospace = false;
                        pthread_mutex_unlock(&SM[i].mutex);
                        send_ack(fd, &dest, last_acked, wnd);
                        continue;
                    }
                }
                pthread_mutex_unlock(&SM[i].mutex);
            }
            continue;
        }
 
        for (int i = 0; i < MAX_KTP_SOCKETS; i++) {
            int fd_to_read = -1;
            pthread_mutex_lock(&SM[i].mutex);
 
            if (SM[i].is_allotted && SM[i].is_bound &&
                SM[i].udp_sockfd >= 0 &&
                FD_ISSET(SM[i].udp_sockfd, &read_fds)) {
                fd_to_read = SM[i].udp_sockfd;
            }
 
            // Release lock before recvfrom to allow other threads access
            pthread_mutex_unlock(&SM[i].mutex);
 
            if (fd_to_read != -1) {
                ktp_message_t msg;
                struct sockaddr_in sender_addr;
                socklen_t addr_len = sizeof(sender_addr);
 
                ssize_t bytes = recvfrom(fd_to_read, &msg, sizeof(ktp_message_t), 0, (struct sockaddr *)&sender_addr, &addr_len);
 
                // Simulate packet loss; discard if dropMessage returns true
                if (bytes > 0 && !dropMessage(P_DROP)) {
                    pthread_mutex_lock(&SM[i].mutex);
 
                    // Verify packet came from the expected remote peer address
                    if (SM[i].is_allotted && SM[i].is_bound &&
                        sender_addr.sin_addr.s_addr == SM[i].remote_addr.sin_addr.s_addr &&
                        sender_addr.sin_port == SM[i].remote_addr.sin_port) {
 
                        if (msg.type == MSG_DATA) {
                            // Offset of incoming packet relative to receive window base
                            int offset = ((int)msg.seq_no - (int)SM[i].rwnd.base_seq + 256) % 256;
 
                            // Accept packet only if sequence number is within rwnd
                            if (offset < SM[i].rwnd.window_size) {
                                int target_slot = (SM[i].recv_buf_head + offset) % WINDOW_SIZE;
 
                                if (!SM[i].recv_filled[target_slot]) {
                                    SM[i].recv_buffer[target_slot].seq_no = msg.seq_no;
                                    memcpy(SM[i].recv_buffer[target_slot].payload, msg.payload, MSG_PAYLOAD_SIZE);
                                    SM[i].recv_filled[target_slot] = true;
                                    SM[i].recv_buf_count++;
                                    SM[i].rwnd.window_size--;
 
                                    // Walk from head to find latest contiguous ACK point
                                    uint8_t ack_seq = (uint8_t)(SM[i].rwnd.base_seq - 1);
                                    int s = SM[i].recv_buf_head;
                                    uint8_t seq = SM[i].rwnd.base_seq;
                                    int contiguous = 0;
 
                                    while (SM[i].recv_filled[s]) {
                                        ack_seq = seq;
                                        seq++;
                                        s = (s + 1) % WINDOW_SIZE;
                                        contiguous++;
                                    }
 
                                    // Send ACK only if packet extends the contiguous run
                                    if (offset < contiguous) {
                                        int fd = SM[i].udp_sockfd;
                                        struct sockaddr_in dest = SM[i].remote_addr;
                                        uint8_t wnd = SM[i].rwnd.window_size;
                                        // Set nospace flag if buffer is completely filled
                                        if (wnd == 0) SM[i].nospace = true;
                                        pthread_mutex_unlock(&SM[i].mutex);
                                        send_ack(fd, &dest, ack_seq, wnd);
                                        continue;
                                    }
                                    if (SM[i].rwnd.window_size == 0) SM[i].nospace = true;
                                }
 
                            } else {
                                // Duplicate packet; ACK last known sequence to unblock sender
                                uint8_t last_ack = (uint8_t)(SM[i].rwnd.base_seq - 1);
                                int dup_diff = ((int)last_ack - (int)msg.seq_no + 256) % 256;
                                if (dup_diff < WINDOW_SIZE) {
                                    int fd = SM[i].udp_sockfd;
                                    struct sockaddr_in dest = SM[i].remote_addr;
                                    uint8_t wnd = SM[i].rwnd.window_size;
                                    pthread_mutex_unlock(&SM[i].mutex);
                                    send_ack(fd, &dest, last_ack, wnd);
                                    continue;
                                }
                            }
 
                        } else if (msg.type == MSG_ACK) {
                            // Compute how many messages this ACK advances the send window
                            int ack_diff = ((int)msg.ack_num - (int)SM[i].swnd.base + 256) % 256;
 
                            if (ack_diff < WINDOW_SIZE) {
                                int num_acked = ack_diff + 1;
                                if (num_acked > SM[i].send_count) num_acked = SM[i].send_count;
                                // Slide send buffer head past newly acknowledged messages
                                SM[i].send_head = (SM[i].send_head + num_acked) % SEND_BUFFER_SIZE;
                                SM[i].send_count -= num_acked;
                                SM[i].swnd.base = msg.ack_num + 1;
                            }
                            // Update send window size from piggybacked receiver window
                            SM[i].swnd.window_size = msg.rwnd_size;
                        }
                    }
                    pthread_mutex_unlock(&SM[i].mutex);
                }
            }
        }
    }
    return NULL;
}
 
// Thread S: retransmit timed-out messages and send new ones from send buffer
void *thread_S(void *arg) {
    struct timespec sleep_req;
    sleep_req.tv_sec = T / 2;
    sleep_req.tv_nsec = (T & 1) ? 500000000L : 0L;
 
    while (1) {
        nanosleep(&sleep_req, NULL);
 
        for (int i = 0; i < MAX_KTP_SOCKETS; i++) {
            pthread_mutex_lock(&SM[i].mutex);
 
            if (SM[i].is_allotted && SM[i].is_bound && SM[i].udp_sockfd >= 0) {
                // Skip sending if receiver has no room; wait for wake-up ACK
                if (SM[i].swnd.window_size == 0) {
                    pthread_mutex_unlock(&SM[i].mutex);
                    continue;
                }
 
                int in_flight = SM[i].swnd.next_seq - SM[i].swnd.base;
                if (in_flight < 0) in_flight += 256;
 
                struct timespec now;
                clock_gettime(CLOCK_MONOTONIC, &now);
 
                // Go-Back-N - checks only the base, retransmits entire window on timeout
                if (in_flight > 0) {
                    int base_idx = SM[i].send_head % SEND_BUFFER_SIZE;
                    double elapsed =
                        (now.tv_sec  - SM[i].send_ts[base_idx].tv_sec) +
                        (now.tv_nsec - SM[i].send_ts[base_idx].tv_nsec) / 1e9;

                    if (elapsed >= T) {
                        for (int j = 0; j < in_flight; j++) {
                            int idx = (SM[i].send_head + j) % SEND_BUFFER_SIZE;
                            uint8_t seq = (uint8_t)(SM[i].swnd.base + j);
                            int fd = SM[i].udp_sockfd;
                            struct sockaddr_in dest = SM[i].remote_addr;
                            SM[i].send_ts[idx] = now;   // reset clock for all retransmitted msgs
                            send_data(fd, &dest, seq, SM[i].send_buffer[idx]);
                            total_transmissions++;
                        }
                    }
                }
 
                // Send new messages from buffer while window and buffer permit
                while (in_flight < SM[i].swnd.window_size && in_flight < SM[i].send_count) {
                    uint8_t new_seq = SM[i].swnd.next_seq;
                    int buffer_idx = (SM[i].send_head + in_flight) % SEND_BUFFER_SIZE;
                    int fd = SM[i].udp_sockfd;
                    struct sockaddr_in dest = SM[i].remote_addr;
                    SM[i].send_ts[buffer_idx] = now;
                    SM[i].swnd.next_seq++;
                    in_flight++;
                    send_data(fd, &dest, new_seq, SM[i].send_buffer[buffer_idx]);
                    total_transmissions++;
                }
            }
            pthread_mutex_unlock(&SM[i].mutex);
        }
    }
    return NULL;
}
 
// Garbage collector: periodically free slots whose owner process has died
void garbage_collector() {
    while (1) {
        sleep(10);
        for (int i = 0; i < MAX_KTP_SOCKETS; i++) {
            if (SM[i].is_allotted) {
                // kill(pid, 0) checks process existence without sending a signal
                if (kill(SM[i].pid, 0) == -1 && errno == ESRCH) {
                    pthread_mutex_lock(&SM[i].mutex);
                    SM[i].is_allotted = false;
                    pthread_mutex_unlock(&SM[i].mutex);
                }
            }
        }
    }
}
 
// Entry point
int main() {
    key_t shm_key;
    pthread_t tid_R, tid_S;
 
    printf("Starting KTP Daemon...\n");
 
    signal(SIGINT, handle_shutdown);
    signal(SIGTERM, handle_shutdown);
 
    // Generate IPC key, must match the key used in ksocket.c's attach_shm
    if ((shm_key = ftok(SHM_PATH, SHM_ID)) == -1) {
        perror("ftok failed"); exit(EXIT_FAILURE);
    }
 
    size_t shm_size = MAX_KTP_SOCKETS * sizeof(ktp_socket_entry_t);
    if ((shm_id = shmget(shm_key, shm_size, 0666 | IPC_CREAT)) == -1) {
        perror("shmget failed"); exit(EXIT_FAILURE);
    }
 
    if ((SM = (ktp_socket_entry_t *)shmat(shm_id, NULL, 0)) == (void *)-1) {
        perror("shmat failed"); exit(EXIT_FAILURE);
    }
 
    // Zero-initialize every slot and configure process-shared mutexes
    for (int i = 0; i < MAX_KTP_SOCKETS; i++) {
        memset(&SM[i], 0, sizeof(ktp_socket_entry_t));
        SM[i].is_allotted = false;
        SM[i].udp_sockfd = -1;
        SM[i].swnd.window_size = WINDOW_SIZE;
        SM[i].rwnd.window_size = WINDOW_SIZE;
        pthread_mutexattr_init(&SM[i].mutex_attr);
        // PTHREAD_PROCESS_SHARED allows other processes to lock this mutex
        pthread_mutexattr_setpshared(&SM[i].mutex_attr, PTHREAD_PROCESS_SHARED);
        pthread_mutex_init(&SM[i].mutex, &SM[i].mutex_attr);
    }
 
    // Fork garbage collector
    gc_pid = fork();
    if (gc_pid < 0) {
        perror("Fork failed for GC"); handle_shutdown(SIGTERM);
    } else if (gc_pid == 0) {
        garbage_collector();
        exit(EXIT_SUCCESS);
    }
 
    pthread_create(&tid_R, NULL, thread_R, (void *)SM);
    pthread_create(&tid_S, NULL, thread_S, (void *)SM);
 
    printf("KTP Daemon running. Press Ctrl+C to terminate.\n");
 
    // Daemon blocks here; signal handler handles all cleanup on exit
    while (1) pause();
 
    return 0;
}