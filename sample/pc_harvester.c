/*
 * pc_harvester.c
 *
 * Minimal QUIC client derived from the structure of picoquic's sample_client.c.
 *
 * This program is not intended to behave as a complete QUIC application client.
 * In particular, it does not open application streams, does not exchange useful
 * HTTP/3 data, and does not try to implement a complete migration-capable client.
 *
 * It is an experimental tool designed to test the oracle's access to the peer's
 * secure random source through QUIC path validation.
 *
 * Goal:
 *   Its purpose is to maintain one valid QUIC connection on a main local path A,
 *   then send valid 1-RTT QUIC packets from additional local UDP ports in order
 *   to make the server validate these apparent new paths. The server validation
 *   responses are inspected to extract the 8-byte unpredictable value carried in
 *   PATH_CHALLENGE frames.
 *
 * Principle:
 *   - Establish one normal picoquic client connection to the server from the
 *     main local UDP port A.
 *   - Keep this main path alive by periodically sending QUIC PING frames on A.
 *   - Open a pool of additional local UDP sockets, called the migration pool.
 *   - Quickly and on a loop, queue a QUIC PING frame and ask picoquic to prepare
 *     a valid 1-RTT packet for the existing connection.
 *   - Send that prepared packet through one socket of the migration pool instead
 *     of the main socket A.
 *   - From the server point of view, the packet belongs to the same QUIC
 *     connection but comes from a new client address/port tuple.
 *   - This should trigger server-side path validation and cause the server to
 *     send PATH_CHALLENGE frames to the corresponding migration-pool port.
 *   - The program passively receives packets on the migration-pool sockets,
 *     decrypts their 1-RTT payload, scans the contained frames, extracts
 *     PATH_CHALLENGE values, and saves them.
 *
 * Contraints and design choises:
 *   - Packets received on the main path A are processed normally by picoquic using
 *     picoquic_incoming_packet(...), because they drive the real connection state.
 *     Packets received on the migration-pool sockets are only sniffed for
 *     PATH_CHALLENGE frames. They are not injected as normal incoming packets into
 *     picoquic, in order to keep the experiment focused on passive extraction.
 *
 *   - To trigger a path validation, a QUIC packet must contain a non-probing QUIC
 *     frame. PING frame are used because it is simple, valid in 1-RTT, and does not
 *     deliver arbitrary application HTTP/3 bytes to nghttp3. Sending such a packet
 *     from a new local port makes the packet look like active migration traffic and
 *     can cause the peer to validate the new path.
 *
 * Assumptions about the modified picoquic tree:
 *   picoquic_parse_header_and_decrypt(...) is available to parse a received QUIC
 *   packet and expose its decrypted payload;
 *
 * Assumptions about the OS running this client:
 *   PCH_UDP_BUFFER_SIZE is used to set the UDP receive and send buffer sizes
 *   for each port. However, the OS imposes limits to these values, and you may
 *   want to increases them.
 *
 *   On Linux, the current maximum values can be checked from the CLI with:
 *      sysctl net.core.rmem_max net.core.wmem_max
 *
 *   They can then be changed with:
 *     sudo sysctl -w net.core.rmem_max=$((16*1024*1024))
 *     sudo sysctl -w net.core.wmem_max=$((16*1024*1024))
 *
 * For better performances do not forget to compile with the Release flag:
 *      cmake -B build-release -DCMAKE_BUILD_TYPE=Release -DPICOQUIC_FETCH_PTLS=Y
 *      make -j"$(nproc)"
 *
 * Use of AI:
 *   ChatGPT was used throughout the development of this program to support
 *   understanding, help create an initial framework, speed up debugging, review
 *   the code, and improve defensive programming practices. In other words, AI was
 *   used as a powerful supporting tool throughout the development process.
 *   However, it was not used to replace the author’s own work or expertise. The
 *   author remained responsible for the technical choices, the understanding of
 *   the implemented mechanisms, the validation of the results, and the
 *   interpretation presented in this thesis.
 *
 * Abbreviations:
 *   - PCH: Path Challenge Harvester
 *   - cnx: connection 
 *   - ctx: context
 *   - pkt: packet
 *   - st_: structure_
 *   - _t: _type
 *   - us: microseconds
 *   - cb: callback
 *   - fn: function
 *   - bw: bandwidth
 *   - pc: path challenge
 *   - mp: migration pool
 */

/*********************************
 * INCLUDE
 *********************************/

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "picoquic.h"
#include "picoquic_internal.h"
#include "picoquic_utils.h"
#include <picosocks.h>

/*********************************
 * DEFINE CONSTANT VALUE
 *********************************/

#define PCH_ALPN              "h3"                   // HTTP/3 as Application Protocol
#define PCH_SNI               "localhost"            // DNS Server Name used for TLS SNI
#define PCH_LOCAL_IPV4        "127.0.0.1"            // Default local IPv4 (client)
#define PCH_LOCAL_IPV6        "::1"                  // Default local IPv6 (client)
#define PCH_OUTPUT_FILE       "path_challenges.txt"  // Output file to save harvested PATH_CHALLENGE values
#define PCH_OUTPUT_BUFFER     ((size_t)(1024*1024))  // Size of the buffer used to save random numbers
#define PCH_BURST_SIZE        ((uint32_t)1)          // Default max number of probes sent at each loop
#define PCH_TARGET_PC         UINT64_C(0)            // Default number of PATH_CHALLENGE values to harvest, 0=infinite
#define PCH_PING_PERIOD_US    UINT64_C(2000)         // Default period between PING frames on the main path, in us
#define PCH_MAIN_PORT         ((uint16_t)50000)      // Local UDP port for the validated main path
#define PCH_FIRST_PORT_MP     ((uint16_t)50001)      // First local UDP port of the migration pool
#define PCH_MAX_PKT_SIZE      ((size_t)1536)         // Max size of  QUIC packet, received or sent
#define PCH_UDP_BUFFER_SIZE   (8*1024*1024)          // Receiving and sending UDP buffer size for each port
#define PCH_MP_SIZE           ((uint32_t)16)         // Size of the migration pool of local UDP ports
#define PCH_MAX_MP_SIZE       ((uint32_t)256)        // Max size of the migration pool of local UDP ports
#define PCH_PC_SIZE           ((size_t)8)            // Number of unpredictable bytes in one PATH_CHALLENGE
#define PCH_STATS_PERIOD_US   UINT64_C(1000000)      // Period between statistics reports in us

/*********************************
 * TYPES
 *********************************/

/* Type: custom global context structure */
typedef struct st_pch_ctx_t {
    picoquic_quic_t* quic;                // global picoquic context
    picoquic_cnx_t* cnx;                  // cnx picoquic
    const char* sni;                      // Server name requested
    const char* alpn;                     // Application protocol requested
    struct sockaddr_storage server_addr;  // Server address
    struct sockaddr_storage local_a;      // Local address (local_ip + main port)
    struct sockaddr_storage mp_addrs[PCH_MAX_MP_SIZE]; // Migration pool paths
    int sock_a;                           // Main path socket UDP
    int mp_socks[PCH_MAX_MP_SIZE];        // Migration pool sockets UDP
    int ready;                            // The cnx on the main path is ready (handshake finished)
    int stop;                             // The program must stop (Ctrl+C)
    FILE* out;                            // Output file to save harvested pc
    uint64_t target_pc;                   // Number of PATH_CHALLENGE values to harvest, 0=infinite
    uint64_t ping_period_us;              // Period between PING frames on the main path, in us
    uint32_t burst_size;                  // Max number of probes sent at each loop
    uint32_t mp_size;                     // Size of the migration pool of local UDP port
    uint32_t next_mp_port;                // Next UDP port to use for triggering path validation
    uint64_t mp_ping_sent;                // Number of Ping sent from mp
    uint64_t pc_recv;                     // Path challenge received
    uint64_t udp_rx_datagrams;            // Number of UDP datagrams received
    uint64_t udp_rx_bytes;                // Number of UDP payloads bytes received
    uint64_t pc_pkt_mult_pc;              // Number of packets with several pc
    uint64_t last_main_ping_time;         // Last time a ping was sent on the main path
    uint64_t start_time;                  // Start time for measures, when the cnx is ready (handshake finished)
    uint64_t last_stats_time;             // Last time stats was displayed
    uint64_t last_stats_pc;               // Value of pc_recv at last_stats_time
} pch_ctx_t;

/*********************************
 * STATIC VARIABLES
 *********************************/

/* Global flag to indicate that the test termination is request */
static volatile sig_atomic_t g_stop_flag = 0;

/*********************************
 * STATIC FUNCTIONS
 *********************************/

/* SIGINT signal handler (Ctrl+C): clean program termination */
static void on_sigint(int sig) {
    (void)sig;
    g_stop_flag = 1;
}

/* Convert 'len' binary bytes from 'bytes' into a hexadecimal string in 'out' */
static void bytes_to_hex(const uint8_t* bytes, size_t len, char* out, size_t out_size) {
    if (out == NULL) return;
    if ((len > 0 && bytes == NULL) || out_size < 2 * len + 1) {
        if (out_size > 0) out[0] = '\0';
        return;
    }

    static const char* hex = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[2 * i] = hex[(bytes[i] >> 4) & 0x0f];
        out[2 * i + 1] = hex[bytes[i] & 0x0f];
    }
    out[2 * len] = '\0';
}

/* Print the statistics (values and derived values of stats) in the standard output,
 * if PCH_STATS_PERIOD_US elapsed since the last print, or force != 0.
 */
static void pch_print_stats(pch_ctx_t* ctx, uint64_t now, int force) {
    if (ctx == NULL || ctx->start_time == 0) return;
    if (!force && now < ctx->last_stats_time + PCH_STATS_PERIOD_US) return;

    double elapsed_s;
    double window_s;
    double random_avg_kib_s = 0.0;
    double random_int_kib_s = 0.0;
    uint64_t delta_pc;

    elapsed_s = (double)(now - ctx->start_time) / 1000000.0;
    window_s = (double)(now - ctx->last_stats_time) / 1000000.0;
    delta_pc = ctx->pc_recv - ctx->last_stats_pc;
    if (elapsed_s > 0.0) random_avg_kib_s = ((double)ctx->pc_recv * (double)PCH_PC_SIZE) / (1024.0 * elapsed_s);
    if (window_s > 0.0) random_int_kib_s = ((double)delta_pc * (double)PCH_PC_SIZE) / (1024.0 * window_s);

    fprintf(stdout,
        "[Elapsed=%.3f s]"
        " random_int=%.1f KiB/s"
        " ; random_avg=%.1f KiB/s"
        " ; pc_recv=%" PRIu64 "/%" PRIu64
        " ; mp_ping_sent=%" PRIu64
        " ; udp_rx=%" PRIu64 " datagrams / %" PRIu64 " bytes"
        " ; pkt_multi_pc=%" PRIu64 "\n",
        elapsed_s,
        random_int_kib_s,
        random_avg_kib_s,
        ctx->pc_recv,
        ctx->target_pc,
        ctx->mp_ping_sent,
        ctx->udp_rx_datagrams,
        ctx->udp_rx_bytes,
        ctx->pc_pkt_mult_pc);

    ctx->last_stats_time = now;
    ctx->last_stats_pc = ctx->pc_recv;
}

/* Record the pc value in hexadecimal txt, via the buffer linked to the output file */
static void pch_record_pc(pch_ctx_t* ctx, const uint8_t challenge[8]) {
    if (ctx == NULL || ctx->out == NULL || challenge == NULL) return;

    char hex[17];

    bytes_to_hex(challenge, 8, hex, sizeof(hex));
    ctx->pc_recv++;
    fprintf(ctx->out, "%s\n", hex); // print in the buffer until the next auto fflush()
}

/* Returns the size of the socket address structure sa,
 * depending on whether it contains an IPv4 or IPv6 address
 */
static socklen_t pch_sockaddr_len(const struct sockaddr* sa) {
    if (sa == NULL) return 0;

    if (sa->sa_family == AF_INET) return (socklen_t)sizeof(struct sockaddr_in);
    if (sa->sa_family == AF_INET6) return (socklen_t)sizeof(struct sockaddr_in6);
    return 0;
}

/* Set the file descriptor fd (like sockets UDP) in non-blocking mode */
static int pch_set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;

    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) return -1;
    return 0;
}

/* Build an IPv4 or IPv6 local sockaddr_storage address for the given port. */
static int pch_build_local_sockaddr(int af, uint16_t port, const char* local_ip, struct sockaddr_storage* out) {
    if (out == NULL) return -1;

    memset(out, 0, sizeof(*out));
    if (af == AF_INET) {
        struct sockaddr_in* s4 = (struct sockaddr_in*)out;
        const char* ip = (local_ip != NULL) ? local_ip : PCH_LOCAL_IPV4;

        s4->sin_family = AF_INET;
        s4->sin_port = htons(port);
        if (inet_pton(AF_INET, ip, &s4->sin_addr) != 1) return -1; // ip converted in binary sin_addr
    }
    else if (af == AF_INET6) {
        struct sockaddr_in6* s6 = (struct sockaddr_in6*)out;
        const char* ip = (local_ip != NULL) ? local_ip : PCH_LOCAL_IPV6;

        s6->sin6_family = AF_INET6;
        s6->sin6_port = htons(port);
        if (inet_pton(AF_INET6, ip, &s6->sin6_addr) != 1) return -1;
    }
    else return -1;
    
    return 0;
}

/* Open a non-blocking UDP socket bound to the given local address. */
static int pch_open_bound_udp_socket(const struct sockaddr_storage* local_addr) {
    if (local_addr == NULL) return -1;

    int fd;
    int one = 1;
    int buf_size = PCH_UDP_BUFFER_SIZE;

    fd = socket(local_addr->ss_family, SOCK_DGRAM, 0); // Socket UDP creation
    if (fd < 0) return -1;

    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &buf_size, sizeof(buf_size));
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof(buf_size));

    /* Link the socket fd to a specific local address */
    if (bind(fd,
        (const struct sockaddr*)local_addr,
        pch_sockaddr_len((const struct sockaddr*)local_addr)) != 0) {
        close(fd);
        return -1;
    }

    if (pch_set_nonblocking(fd) != 0) {
        close(fd);
        return -1;
    }

    return fd;
}

/* Cnx loop callback: Handle picoquic connection events */
static int pch_client_cb(
    picoquic_cnx_t* cnx,
    uint64_t stream_id,
    uint8_t* bytes,
    size_t length,
    picoquic_call_back_event_t event,
    void* callback_ctx,
    void* v_stream_ctx)
{
    pch_ctx_t* ctx = (pch_ctx_t*)callback_ctx;
    if (ctx == NULL) return -1;

    /* Parameters not used: No applicatives data (streams, http request, ...) */
    (void)cnx;
    (void)stream_id;
    (void)bytes;
    (void)length;
    (void)v_stream_ctx;

    switch (event) {
    case picoquic_callback_ready:
        fprintf(stdout, "[PCH] Connection ready\n");
        ctx->ready = 1;

        uint64_t now = picoquic_current_time();
        ctx->start_time = now;
        ctx->last_stats_time = now;
        ctx->last_stats_pc = ctx->pc_recv;
        ctx->last_main_ping_time = now;
        break;

    case picoquic_callback_close:
        fprintf(stdout, "[PCH] Transport close by peer\n");
        ctx->stop = 1;
        break;

    case picoquic_callback_application_close:
        fprintf(stdout, "[PCH] Application close by peer\n");
        ctx->stop = 1;
        break;

    case picoquic_callback_stateless_reset:
        fprintf(stdout, "[PCH] Stateless reset by peer\n");
        ctx->stop = 1;
        break;

    default:
        break;
    }

    return 0;
}

/* Drain all pending UDP datagrams from the main socket and forwards them to picoquic */
static void pch_drain_main_socket(pch_ctx_t* ctx, int fd, struct sockaddr_storage* local_addr) {
    for (;;) {
        uint8_t buffer[PCH_MAX_PKT_SIZE];
        struct sockaddr_storage peer_addr;
        socklen_t peer_len = sizeof(peer_addr);
        ssize_t recv_bytes;  // Size bytes received
        uint64_t now = picoquic_current_time();

        recv_bytes = recvfrom(fd, buffer, sizeof(buffer), 0, (struct sockaddr*)&peer_addr, &peer_len);
        if (recv_bytes <= 0) break;

        ctx->udp_rx_datagrams++;
        ctx->udp_rx_bytes += (uint64_t)recv_bytes;

        /* Forward towards picoquic to maintain normal cnx processing on the main path */
        (void)picoquic_incoming_packet(
            ctx->quic,
            buffer,
            (size_t)recv_bytes,
            (struct sockaddr*)&peer_addr,
            (struct sockaddr*)local_addr,
            0,
            0,
            now);
    }
}

/* Decrypt a QUIC packet and extract PATH_CHALLENGE frames from its 1-RTT payload */
static size_t pch_sniff_pc_frames(
    pch_ctx_t* ctx,
    const uint8_t* packet,
    size_t packet_len,
    struct sockaddr* addr_from,
    uint64_t now)
{
    uint8_t payload[PCH_MAX_PKT_SIZE];
    size_t payload_length = 0;
    picoquic_packet_header ph;
    picoquic_cnx_t* pcnx = NULL;
    size_t consumed = 0;
    int new_context_created = 0;
    int ret;
    const uint8_t* p;  // Pointer to navigate through the decrypted payload
    size_t remaining;  // Remaining bytes to analyse
    size_t pc_found = 0;

    memset(&ph, 0, sizeof(ph));  // Initialize ph to 0

    /* Call the custon wrapper of picoquic_parse_header_and_decrypt function */
    ret = picoquic_parse_header_and_decrypt_to_payload(
        ctx->quic,
        packet,
        packet_len,
        packet_len,
        (const struct sockaddr*)addr_from,
        now,
        payload,
        sizeof(payload),
        &payload_length,
        &ph,
        &pcnx,
        &consumed,
        &new_context_created);

    if (ret != 0) return 0;
    if (pcnx != ctx->cnx) return 0;  // Only pkt link to the main cnx
    if (ph.epoch != picoquic_epoch_1rtt) return 0;  // Only 1-RTT pkt
    if (payload_length == 0) return 0;

    p = payload;
    remaining = payload_length;

    while (remaining > 0) {
        if (*p == picoquic_frame_type_padding) {
            p++;
            remaining--;
            continue;
        }

        if (*p == picoquic_frame_type_path_challenge) {
            if (remaining < 1 + PCH_PC_SIZE) return pc_found;

            pch_record_pc(ctx, p + 1);
            pc_found++;
            p += 1 + PCH_PC_SIZE;
            remaining -= 1 + PCH_PC_SIZE;
            continue;
        }

        size_t consumed_frame = 0;
        int pure_ack = 0;

        /* Other frames than PC are skipped using the picoquic function dedicated */
        int sret = picoquic_skip_frame(p, remaining, &consumed_frame, &pure_ack);
        if (sret != 0 || consumed_frame == 0) return pc_found;
        p += consumed_frame;
        remaining -= consumed_frame;
    }

    return pc_found;
}

/* Drain all pending UDP datagrams from a mp socket and sniff them for PC frames */
static void pch_drain_mp_socket(pch_ctx_t* ctx, int fd) {
    for (;;) {
        uint8_t buffer[PCH_MAX_PKT_SIZE];
        struct sockaddr_storage peer_addr;
        socklen_t peer_len = sizeof(peer_addr);
        ssize_t recv_bytes;
        uint64_t now = picoquic_current_time();

        recv_bytes = recvfrom(fd, buffer, sizeof(buffer), 0, (struct sockaddr*)&peer_addr, &peer_len);
        if (recv_bytes < 0) break;

        ctx->udp_rx_datagrams++;
        ctx->udp_rx_bytes += (uint64_t)recv_bytes;

        size_t pc_found;
        pc_found = pch_sniff_pc_frames(
            ctx,
            buffer,
            (size_t)recv_bytes,
            (struct sockaddr*)&peer_addr,
            now);

        if (pc_found > 1) ctx->pc_pkt_mult_pc++;
    }
}

/* Queue a PING frame on the active connection, if ready.
 * The creation of a valid pkt with the PING frame is managed by picoquic.
 */
static int pch_queue_ping_frame(pch_ctx_t* ctx, const char* label) {
    if (ctx == NULL || ctx->cnx == NULL || !ctx->ready) return 0;

    const uint8_t ping_frame[1] = { picoquic_frame_type_ping };
    int ret;

    /* A ping frame is prepared and queued to be send at the next call */
    ret = picoquic_queue_misc_frame(
        ctx->cnx,
        ping_frame,
        sizeof(ping_frame),
        0,
        picoquic_packet_context_application);
    if (ret != 0) {
        fprintf(stderr, "[PCH] Could not queue PING frame for %s: %d\n",
            (label == NULL) ? "path" : label,
            ret);
        return -1;
    }

    return 1;
}

/* Ask picoquic to build the next outgoing pkt, then send it through the UDP socket fd */
static int pch_send_prepared_pkt(pch_ctx_t* ctx, int fd) {
    uint8_t send_buffer[PCH_MAX_PKT_SIZE];
    struct sockaddr_storage addr_to;
    struct sockaddr_storage addr_from;
    const struct sockaddr* dest;
    socklen_t dest_len;
    size_t send_length = 0;
    int if_index = 0;
    int ret;
    ssize_t sent;
    uint64_t now = picoquic_current_time();

    /* Initialize the addresses */
    memset(&addr_to, 0, sizeof(addr_to));
    memset(&addr_from, 0, sizeof(addr_from));

    ret = picoquic_prepare_packet(
        ctx->cnx,
        now,
        send_buffer,
        sizeof(send_buffer),
        &send_length,
        &addr_to,
        &addr_from,
        &if_index);
        
    if (ret != 0) {
        fprintf(stderr, "[PCH] Failed to prepare QUIC packet: %d\n", ret);
        return -1;
    }
    
    /* Unused variables */
    (void)addr_from;
    (void)if_index;

    if (send_length == 0) return 0;  // Nothing to send currently

    dest = (const struct sockaddr*)&ctx->server_addr;
    dest_len = pch_sockaddr_len(dest);
    sent = sendto(fd,
        send_buffer,
        send_length,
        0,
        dest,
        dest_len);

    if (sent < 0) return -1;

    return 1;
}

/* Send all packets currently pending for the main path */
static int pch_flush_main_path(pch_ctx_t* ctx) {
    for (;;) {
        int rc = pch_send_prepared_pkt(ctx, ctx->sock_a);
        if (rc < 0) return rc;
        if (rc == 0) break;
    }

    return 0;
}

/* Queue and send a PING from the main path */
static int pch_send_ping_main_path(pch_ctx_t* ctx, uint64_t now) {
    int ret;

    ret = pch_queue_ping_frame(ctx, "Main path");
    if (ret <= 0) return ret;

    ret = pch_flush_main_path(ctx);
    if (ret != 0) return ret;

    ctx->last_main_ping_time = now;

    return 0;
}

/* Queue and send a PING from the next migration-pool socket to trigger server path validation. */
static int pch_send_next_ping_mp(pch_ctx_t* ctx) {
    if (!ctx->ready || (ctx->target_pc != 0 && ctx->pc_recv >= ctx->target_pc)) return 0;
    if (ctx->cnx == NULL) return -1;
    if (ctx->mp_size == 0) {
        fprintf(stderr, "[PCH] Empty probe pool\n");
        return -1;
    }

    uint32_t slot;  // Port index in the mp
    int chosen_fd;
    int ret;

    slot = ctx->next_mp_port;
    ctx->next_mp_port = (ctx->next_mp_port + 1) % ctx->mp_size;

    chosen_fd = ctx->mp_socks[slot];
    if (chosen_fd < 0) {
        fprintf(stderr, "[PCH] Invalid mp socket slot %u\n", slot);
        return -1;
    }

    ret = pch_queue_ping_frame(ctx, "migration pool");
    if (ret <= 0) return ret;

    ret = pch_send_prepared_pkt(ctx, chosen_fd);
    if (ret < 0) return ret;
    if (ret == 0) return 0;

    ctx->mp_ping_sent++;
    return 1;
}

/* Release all resources allocated */
static void pch_cleanup(pch_ctx_t* ctx) {
    uint32_t i;

    if (ctx == NULL) return;

    /* Delete the active cnx */
    if (ctx->cnx != NULL) {
        picoquic_delete_cnx(ctx->cnx);
        ctx->cnx = NULL;
    }

    /* Freed the quic ctx */
    if (ctx->quic != NULL) {
        picoquic_free(ctx->quic);
        ctx->quic = NULL;
    }

    /* Close the main path socket */
    if (ctx->sock_a >= 0) {
        close(ctx->sock_a);
        ctx->sock_a = -1;
    }

    /* Close the mp sockets */
    for (i = 0; i < PCH_MAX_MP_SIZE; i++) {
        if (ctx->mp_socks[i] >= 0) {
            close(ctx->mp_socks[i]);
            ctx->mp_socks[i] = -1;
        }
    }

    /* Close the file (Remaining values in the buffer are saved before) */
    if (ctx->out != NULL) {
        fclose(ctx->out);
        ctx->out = NULL;
    }
}

/* Print command-line usage information. */
static void pch_usage(const char* prog) {
    fprintf(stderr,
        "Usage: %s <server_name> <server_port> [mp_size]"
        " [target_pc] [burst_size] [ping_period_us] [local_ip]\n"
        "\n"
        "Default values: \n"
        "   mp_size=%u \n"
        "   target_pc=%" PRIu64 "\n"
        "   burst_size=%u \n"
        "   ping_period_us=%" PRIu64 "\n"
        "   local_ip= IPv4 %s - IPv6 %s\n"
        "Examples:\n"
        "   %s 127.0.0.1 4443 16\n"
        "   %s 192.168.0.4 4443 16 10000 10 5000 192.168.0.12\n"
        "   %s ::1 4443 16 10000 10 5000 ::1\n",
        prog,
        PCH_MP_SIZE,
        PCH_TARGET_PC,
        PCH_BURST_SIZE,
        PCH_PING_PERIOD_US,
        PCH_LOCAL_IPV4,
        PCH_LOCAL_IPV6,
        prog, prog, prog);
}

/* Initialize pch_ctx_t : sockets, output file, picoquic ctx, client cnx, and stats counters */
static int pch_init(
    pch_ctx_t* ctx,
    const char* server_name,
    int server_port,
    uint32_t mp_size,
    const char* local_ip)
{
    int is_name = 0;  // server_name is a DNS name (0), or a IP (1)
    int ret;
    uint32_t i;
    uint16_t port_a = PCH_MAIN_PORT;
    uint16_t first_port_mp = PCH_FIRST_PORT_MP;

    memset(ctx, 0, sizeof(*ctx));  // Initialize ctx to 0

    /* For proper initialization, because fd 0 = stdin */
    ctx->sock_a = -1;
    ctx->ping_period_us = PCH_PING_PERIOD_US;
    for (i = 0; i < PCH_MAX_MP_SIZE; i++) {
        ctx->mp_socks[i] = -1;
    }

    ctx->alpn = PCH_ALPN;
    ctx->sni = PCH_SNI;

    if (mp_size == 0 || mp_size > PCH_MAX_MP_SIZE) {
        fprintf(stderr, "Migration pool size must be between 1 and %u\n", PCH_MAX_MP_SIZE);
        return -1;
    }
    if ((uint32_t)first_port_mp + mp_size - 1u > UINT16_MAX) {
        fprintf(stderr, "MP port range exceeds UDP port 65535\n");
        return -1;
    }
    ctx->mp_size = mp_size;

    ctx->out = fopen(PCH_OUTPUT_FILE, "a");
    if (ctx->out == NULL) {
        perror("fopen(output_file)");
        return -1;
    }
    if (setvbuf(ctx->out, NULL, _IOFBF, PCH_OUTPUT_BUFFER) != 0) {
        fclose(ctx->out);
        ctx->out = NULL;
        return -1;
    }

    ret = picoquic_get_server_address(server_name, server_port, &ctx->server_addr, &is_name);
    if (ret != 0) {
        fprintf(stderr, "Cannot resolve server address for %s:%d\n", server_name, server_port);
        return -1;
    }
    if (is_name) ctx->sni = server_name;

    /* Build the main address and bind of its socket */
    if (pch_build_local_sockaddr(ctx->server_addr.ss_family, port_a, local_ip, &ctx->local_a) != 0) {
        fprintf(stderr, "Cannot build local address for the main path.\n");
        return -1;
    }
    ctx->sock_a = pch_open_bound_udp_socket(&ctx->local_a);
    if (ctx->sock_a < 0) return -1;

    /* Build the mp addresses and bind of their sockets */
    for (i = 0; i < ctx->mp_size; i++) {
        uint16_t p = (uint16_t)(first_port_mp + i);
        if (pch_build_local_sockaddr(ctx->server_addr.ss_family, p, local_ip, &ctx->mp_addrs[i]) != 0) {
            fprintf(stderr, "Cannot build mp address for port %u\n", (unsigned)p);
            return -1;
        }
        ctx->mp_socks[i] = pch_open_bound_udp_socket(&ctx->mp_addrs[i]);
        if (ctx->mp_socks[i] < 0) {
            fprintf(stderr, "Cannot bind mp port %u\n", (unsigned)p);
            return -1;
        }
    }

    /* Create picoquic ctx */
    ctx->quic = picoquic_create(
        8,
        NULL,
        NULL,
        NULL,
        ctx->alpn,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        picoquic_current_time(),
        NULL,
        NULL,
        NULL,
        0);
    if (ctx->quic == NULL) {
        fprintf(stderr, "Could not create picoquic context\n");
        return -1;
    }

    picoquic_set_null_verifier(ctx->quic);  // Deactivate TLS certificate verification
    picoquic_set_key_log_file_from_env(ctx->quic);  // Activate key log TLS (used be Wireshark)

    /* Creation of the picoquic client cnx */
    ctx->cnx = picoquic_create_cnx(
        ctx->quic,
        picoquic_null_connection_id,
        picoquic_null_connection_id,
        (struct sockaddr*)&ctx->server_addr,
        picoquic_current_time(),
        0,
        ctx->sni,
        ctx->alpn,
        1);
    if (ctx->cnx == NULL) {
        fprintf(stderr, "Could not create connection context\n");
        return -1;
    }

    picoquic_set_callback(ctx->cnx, pch_client_cb, ctx);  // Associate the custom cnx cb

    /* Set the local address of the main path */
    if (picoquic_set_local_addr(ctx->cnx, (struct sockaddr*)&ctx->local_a) != 0) {
        fprintf(stderr, "Could not set initial local address A\n");
        return -1;
    }

    // A custom PING method is implemented instead of:
    // picoquic_enable_keep_alive(ctx->cnx, 0);

    /* Start the client cnx */
    ret = picoquic_start_client_cnx(ctx->cnx);
    if (ret != 0) {
        fprintf(stderr, "Could not start client connection: %d\n", ret);
        return -1;
    }

    return 0;
}

/* Main event loop:
 *   - Receive packets
 *   - Update stats
 *   - Handle the QUIC handshake
 *   - Maintain the main path
 *   - Send migration-pool pings
 */
static int pch_loop(pch_ctx_t* ctx) {
    /* While the target is not reached and stop not requested, the harvest continues */
    while (!ctx->stop && !g_stop_flag) {
        uint64_t now = picoquic_current_time();
        unsigned i;

        /* Drain and process all received UDP datagrams: On the main socket, then all mp sockets */
        pch_drain_main_socket(ctx, ctx->sock_a, &ctx->local_a);
        for (i = 0; i < ctx->mp_size; i++) {
            pch_drain_mp_socket(ctx, ctx->mp_socks[i]);
        }
        if (ctx->stop || g_stop_flag) break;

        now = picoquic_current_time();
        pch_print_stats(ctx, now, 0);

        /* Check if target_pc is reached */
        if (ctx->target_pc != 0 && ctx->pc_recv >= ctx->target_pc) {
            fprintf(stdout, "[PCH] Path Challenge target reached: %" PRIu64 "\n", ctx->pc_recv);
            break;
        }

        if (!ctx->ready) { // Handshake not finished, pkt sent on the main path
            if (pch_flush_main_path(ctx) != 0) return -1;
        }
        else {  // Handshake finished, the cnx is ready to harvest pc

            /* The main path is kept alive with regular pings */
            if (now - ctx->last_main_ping_time >= ctx->ping_period_us) {
                if (pch_send_ping_main_path(ctx, now) != 0) return -1;
            }

            /* Ping are sent from the migration pool */
            for (i = 0; i < ctx->burst_size; i++) {
                int rc = pch_send_next_ping_mp(ctx);
                if (rc < 0) return -1;
                if (rc == 0) break;
            }
        }
    }

    return 0;
}

/*********************************
 * MAIN FUNCTION
 *********************************/

int main(int argc, char** argv) {
    pch_ctx_t ctx;
    const char* server_name;
    const char* local_ip = NULL;
    char* end = NULL;
    long server_port;
    uint32_t mp_size;
    uint64_t end_time;
    int ret;

    if (argc < 3 || argc > 8) {
        pch_usage(argv[0]);
        return EXIT_FAILURE;
    }

    signal(SIGINT, on_sigint);  // Ctrl+C handler

    /* Mandatory parameters */
    server_name = argv[1];
    server_port = strtol(argv[2], &end, 10);

    /* Optional parameters used in pch_init */
    mp_size = (argc >= 4) ? (uint32_t)strtoul(argv[3], NULL, 10) : PCH_MP_SIZE;
    if (argc == 8) local_ip = argv[7];

    /* Pch initialization */
    ret = pch_init(&ctx, server_name, server_port, mp_size, local_ip);
    if (ret != 0) {
        pch_cleanup(&ctx);
        return EXIT_FAILURE;
    }

    /* Optional parameters set after pch_init */
    ctx.target_pc = (argc >= 5) ? strtoull(argv[4], NULL, 10) : PCH_TARGET_PC;
    ctx.burst_size = (argc >= 6) ? (uint32_t)strtoul(argv[5], NULL, 10) : PCH_BURST_SIZE;
    ctx.ping_period_us = (argc >= 7) ? strtoull(argv[6], NULL, 10) : PCH_PING_PERIOD_US;

    if (ctx.burst_size == 0) ctx.burst_size = PCH_BURST_SIZE;
    if (ctx.ping_period_us == 0) ctx.ping_period_us = PCH_PING_PERIOD_US;

    /* The harvest may starts: Display of the optional parameters (by default or chosen) */
    fprintf(stdout,
        "[PCH] Start: mp_size=%u target_pc=%" PRIu64 " burst_size=%u ping_period_us=%" PRIu64 "\n",
        ctx.mp_size,
        ctx.target_pc,
        ctx.burst_size,
        ctx.ping_period_us);

    /* Stats counters initialization */
    ctx.start_time = 0;
    ctx.last_stats_time = 0;
    ctx.last_stats_pc = 0;

    /* The harvest starts: The main loop is launch */
    ret = pch_loop(&ctx);

    /* Harvest finished (target reached or stop requested): Print the results */
    end_time = picoquic_current_time();
    fprintf(stdout, "[PCH] Finished:\n");
    pch_print_stats(&ctx, end_time, 1);

    pch_cleanup(&ctx);

    return (ret == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
