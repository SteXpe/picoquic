/*
 * sr_harvester.c
 *
 * Standalone Harvester of QUIC Stateless Reset.
 *
 * This program is not intended to behave as a complete QUIC endpoint or as a
 * normal QUIC application client.
 *
 * It is an experimental tool designed to test the oracle's access to a peer's
 * secure random source through QUIC Stateless Reset generation.
 *
 * Goal:
 *   Its purpose is to send many QUIC short-header-like UDP probes to a QUIC
 *   server, using Destination Connection IDs for which the server has no
 *   corresponding active connection state. When the server decides to answer with
 *   a Stateless Reset, the program extract and record the unpredictable bits field.
 *
 * Principle:
 *   - Create one connected, non-blocking UDP socket toward the target server.
 *   - Preallocate TX and RX batches so that Linux sendmmsg() and recvmmsg() can
 *     send and receive several UDP datagrams per system call.
 *   - Build short-header-like probes: first byte compatible with a QUIC short
 *     header fixed bit, followed by a configurable DCID and padding bytes.
 *   - Send probes at maximum speed, or under an optional packet-per-second rate
 *     limit.
 *   - Drain all currently available UDP responses in non-blocking batches.
 *   - Identify received Stateless Reset candidates by checking the short-header
 *     form and the minimum size, then split the datagram into:
 *          [unpredictable prefix][16-byte Stateless Reset Token]
 *   - Count the unpredictable contribution as prefix_size * 8 - 2 bits.
 *   - Record each harvested prefix in a binary output file using the format:
 *          [uint32_t prefix_size][prefix bytes]
 *   - Stop when the requested number of Stateless Reset packets has been
 *     harvested, or when the user interrupts the program with Ctrl+C.
 *
 * Constraints and design choices:
 *   - The program intentionally avoids a full QUIC stack. It only relies on UDP
 *     socket I/O and on the structure of short-header-like packets.
 *   - The UDP socket is connected to reduce per-packet destination handling and
 *     to receive only datagrams coming from the selected server address/port.
 *   - The main loop drains RX, sends one TX batch, and prints periodic statistics.
 *   - The hot path uses non-blocking sendmmsg()/recvmmsg().
 *   - The output file is fully buffered to avoid making disk I/O a bottleneck.
 *
 * Assumptions about the OS running this client:
 *   - This program is made for GNU/Linux.
 *   - SRH_UDP_SOCKET_BUF is used to set the UDP receive and send buffer sizes
 *   for each port. However, the OS imposes limits to these values. On Linux,
 *   the current maximum values can be checked from the CLI with:
 *      sysctl net.core.rmem_max net.core.wmem_max
 *   and increased with:
 *      sudo sysctl -w net.core.rmem_max=$((16*1024*1024))
 *      sudo sysctl -w net.core.wmem_max=$((16*1024*1024))
 *
 * Compilation CLI:
 *   Classic:
 *      gcc -std=c11 -O3 -Wall -Wextra -Wpedantic sr_harvester.c -o sr_harvester
 *   Optimised for the local CPU:
 *      gcc -std=c11 -O3 -march=native -DNDEBUG sr_harvester.c -o sr_harvester
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
 *   - SRH: Stateless Reset Harvester
 *   - SR: Stateless Reset
 *   - DCID: Destination Connection ID
 *   - pkt: packet
 *   - cfg: configuration
 *   - ctx: context
 *   - st_: structure_
 *   - _t: _type
 *   - def: default
 *   - buf: buffer
 *   - tx: transmission/transmitted
 *   - rx: reception/received
 *   - pps: packets per second
 *   - us: microseconds
 *   - ns: nanoseconds
 *   - fn: function
 */

/*********************************
 * ENVIRONMENT CONSTANT
 *********************************/

#define _GNU_SOURCE              // Expose GNU/Linux extensions such as sendmmsg() and recvmmsg()
#define _DEFAULT_SOURCE          // Expose default glibc/BSD/POSIX interfaces
#define _POSIX_C_SOURCE 200809L  // Request POSIX.1-2008 interfaces

/*********************************
 * INCLUDE
 *********************************/

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <inttypes.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

/*********************************
 * DEFINE CONSTANT VALUE
 *********************************/

#define SRH_SERVER_IP        "127.0.0.1"              // Default server IP address
#define SRH_OUTPUT_FILE      "sr.bin"                 // Default output file to save SR harvested
#define SRH_SERVER_PORT      ((uint16_t)4433)         // Default server port
#define SRH_DEF_LOC_PORT     ((uint16_t)0)            // Default local port (ephemeral)
#define SRH_DEF_TARGET_SR    ((size_t)0)              // Number of Stateless Reset to harvest (infinite)
#define SRH_MAX_PROBE_SIZE   ((size_t)1600)           // Max probe size, in bytes (UDP payload sent)
#define SRH_MIN_PROBE_SIZE   ((size_t)21)             // Min probe size, in bytes
#define SRH_MIN_SR_SIZE       ((size_t)21)            // Min sr size, in bytes (UDP payload received)
#define SRH_DEF_PROBE_SIZE   ((size_t)43)             // Probe size by default
#define SRH_MAX_DCID_SIZE    ((size_t)20)             // Max DCID size, in bytes
#define SRH_DEF_DCID_SIZE    ((size_t)18)             // DCID size by default
#define SRH_MAX_UDP_BATCH    ((uint32_t)256)          // Max number of UDP datagrams per sendmmsg/recvmmsg call
#define SRH_DEF_UDP_BATCH    ((uint32_t)64)           // Default number of UDP datagrams per sendmmsg/recvmmsg call
#define SRH_OUTPUT_BUFFER    ((size_t)(8*1024*1024))  // Buffer size for binary output, in bytes
#define SRH_TOKEN_SIZE       ((size_t)16)             // SR Token size, in bytes
#define SRH_STATS_PERIOD_US  UINT64_C(1000000)        // Period between statistics reports, in us
#define SRH_DEF_PROBE_RATE   UINT64_C(0)              // Default rate of probe sent per second (unlimited)
#define SRH_UDP_SOCKET_BUF   ((size_t)(8*1024*1024))  // Buffer size for the UDP Socket
#define SRH_DEF_FIXED_DCID   true                     // By default, DCIDs in probe are fixed

/*********************************
 * TYPES
 *********************************/

/* Type: application configuration */
typedef struct st_srh_config_t {
    int family;                // Address family: AF_INET or AF_INET6
    const char *server_ip;     // Server IP address or hostname
    uint16_t server_port;      // Server UDP port
    uint16_t local_port;       // Local UDP port
    size_t dcid_size;          // DCID size, in bytes
    size_t tx_probe_size;      // Size of the probes size sent, in bytes
    uint64_t target_sr;        // Target number of SR to harvest (0 = infinite)
    unsigned int udp_batch;    // sendmmsg/recvmmsg batch size
    uint64_t stats_period_us;  // Period between statistics reports, in us (0 = disabled)
    const char *out;           // Binary output file to save unpredictable bits harvested
    uint64_t target_tx_pps;    // Target probe per second to sent (0 = unlimited)
    bool fixed_dcid;           // True: const DCID in probes, False: increment DCIDs
} srh_config_t;

/* Type: test statistics */
typedef struct st_srh_stats_t {
    uint64_t probe_count;               // Number of probes sent
    uint64_t send_calls;                // Number of sendmmsg() calls that sent at least one datagram
    uint64_t recv_calls;                // Number of recvmmsg() calls that received at least one datagram
    uint64_t udp_rx_count;              // Number of UDP datagrams received
    uint64_t udp_rx_bytes;              // Total UDP payload bytes received
    uint64_t sr_count;                  // Number of SR received
    uint64_t unpredictable_bits;        // Number of unpredictable bits harvested
} srh_stats_t;

/* Type: template for generated short-header-like probes (1-RTT pkt) */
typedef struct st_srh_probe_t {
    uint8_t data[SRH_MAX_PROBE_SIZE];  // UDP payload: 1-RTT like
    size_t size;                    // Payload size actually sent, in bytes
    size_t dcid_off;                // DCID offset inside data
    size_t after_dcid;                  // Packet number offset inside data
} srh_probe_t;

/* Type: template view of a received SR */
typedef struct st_srh_sr_view_t {
    const uint8_t *prefix;  // Pointer to the SR prefix
    size_t prefix_size;     // Prefix size
    const uint8_t *token;   // Pointer to the SR Token
    size_t token_size;      // Token size
} srh_sr_view_t;

/* Type: preallocated TX batch used by sendmmsg() and recvmsg(). Each entry msg[i]
 * describes one UDP datagram. It points to iov[i], which points to buf[i].
 */
typedef struct st_srh_udp_batch_t {
    struct mmsghdr msg[SRH_MAX_UDP_BATCH];  // Message descriptors passed to sendmmsg()/recvmsg()
    struct iovec   iov[SRH_MAX_UDP_BATCH];  // Data buffer descriptor for each datagram
    uint8_t        buf[SRH_MAX_UDP_BATCH][SRH_MAX_PROBE_SIZE];  // UDP payload buffers
} srh_udp_batch_t;

/* Type: global application context */
typedef struct st_srh_ctx_t {
    srh_config_t cfg;               // Application configuration
    srh_probe_t probe;              // Short-header-like probe template
    srh_udp_batch_t *tx;            // TX batch used by sendmmsg()
    srh_udp_batch_t *rx;            // RX batch used by recvmmsg()
    srh_stats_t stats;              // Test statistics
    int fd;                         // UDP socket descriptor
    FILE *output;               // Binary output file to save unpredictable bits
    char *coutput_buf;        // Buffer used for binary output file
    uint64_t start_time_us;         // Start time of the test, in us
    uint64_t last_stats_time_us;    // Last time statistics were displayed, in us
    uint64_t last_stats_unpr_bits;  // Number of unpredictable bits at last statistics report
} srh_ctx_t;

/*********************************
 * STATIC VARIABLES
 *********************************/

/* Global flag set asynchronously by the SIGINT handler */
static volatile sig_atomic_t g_stop_flag = 0;

/*********************************
 * STATIC FUNCTIONS
 *********************************/

/* SIGINT signal handler (Ctrl+C): request clean program termination */
static void on_sigint(int sig) {
    (void)sig;
    g_stop_flag = 1;
}

/* System errors */
static void die_perror(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

/* Application errors */
static void die_msg(const char *msg) {
    fprintf(stderr, "%s\n", msg);
    exit(EXIT_FAILURE);
}

/* Return current time in ns, from a monotonic clock */
static uint64_t now_ns(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) die_perror("clock_gettime");
    return (uint64_t)ts.tv_sec * UINT64_C(1000000000) + (uint64_t)ts.tv_nsec;
}

/* Return current time in us, from a monotonic clock */
static uint64_t now_us(void) {
    return now_ns() / UINT64_C(1000);
}

/* Print command-line usage information. */
static void srh_usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s [options]\n"
        "\n"
        "Options:\n"
        "  -a <addr>      Server IP address or hostname (default:%s)\n"
        "  -p <port>      Server UDP port (default:%u)\n"
        "  -l <port>      Local UDP port (default:0 = ephemeral)\n"
        "  -d <size>      DCID size in bytes (default:%zu, max:%zu)\n"
        "  -t <size>      Probe size in bytes (default:%zu, max:%zu)\n"
        "  -n <count>     Number of Stateless Reset to harvest (default:0 = infinite)\n"
        "  -b <count>     TX/RX Batch size for sendmmsg/recvmmsg (default:%u, max:%u)\n"
        "  -r <pps>       Target send rate in packets/sec (default:0 = unlimited)\n"
        "  -s <us>        Statistics report period in us (default:%" PRIu64 ", 0 = disabled)\n"
        "  -o <file>      Binary output file of Stateless Reset prefixes (default:sr.bin)\n"
        "  -i             Increment DCID for each transmitted probe (default: fixed DCIDs)\n"
        "  -h             Show this help\n"
        "\n"
        "Output file format (-o):\n"
        "  repeated records: [uint32_t prefix_size][prefix bytes]\n",
        prog,
        SRH_SERVER_IP,
        (unsigned int)SRH_SERVER_PORT,
        SRH_DEF_DCID_SIZE,
        SRH_MAX_DCID_SIZE,
        SRH_DEF_PROBE_SIZE,
        SRH_MAX_PROBE_SIZE,
        (unsigned int)SRH_DEF_UDP_BATCH,
        (unsigned int)SRH_MAX_UDP_BATCH,
        SRH_STATS_PERIOD_US
    );
}

/* Parse an integer string and check that it is within the given uint64_t range. */
static int parse_u64(const char *s, uint64_t min_value, uint64_t max_value, uint64_t *out) {
    if (s == NULL || *s == '\0' || out == NULL) return -1;

    char *end = NULL;
    unsigned long long value;

    errno = 0;
    value = strtoull(s, &end, 10);
    if (errno != 0 || end == s || *end != '\0') return -1;
    if ((uint64_t)value < min_value || (uint64_t)value > max_value) return -1;

    *out = (uint64_t)value;
    return 0;
}

/* Parse command-line options and set the validated values in srh_config */
static void srh_parse_args(int argc, char **argv, srh_config_t *cfg) {
    int opt;
    uint64_t value;

    while ((opt = getopt(argc, argv, "a:p:l:d:t:n:b:r:s:o:ih")) != -1) {
        switch (opt) {
        case 'a':
            cfg->server_ip = optarg;
            break;

        case 'p':
            if (parse_u64(optarg, 0, UINT16_MAX, &value) != 0) {
                die_msg("Invalid server port");
            }
            cfg->server_port = (uint16_t)value;
            break;

        case 'l':
            if (parse_u64(optarg, 0, UINT16_MAX, &value) != 0) {
                die_msg("Invalid local port");
            }
            cfg->local_port = (uint16_t)value;
            break;

        case 'd':
            if (parse_u64(optarg, 0, SRH_MAX_DCID_SIZE, &value) != 0) {
                die_msg("Invalid DCID length");
            }
            cfg->dcid_size = (size_t)value;
            break;

        case 't':
            if (parse_u64(optarg, SRH_MIN_PROBE_SIZE, SRH_MAX_PROBE_SIZE, &value) != 0) {
                die_msg("Invalid Probe size");
            }
            cfg->tx_probe_size = (size_t)value;
            break;

        case 'n':
            if (parse_u64(optarg, 0, UINT64_MAX, &value) != 0) {
                die_msg("Invalid Number of Stateless Reset to harvest");
            }
            cfg->target_sr = value;
            break;

        case 'b':
            if (parse_u64(optarg, 1, SRH_MAX_UDP_BATCH, &value) != 0) {
                die_msg("Invalid TX/RX batch size");
            }
            cfg->udp_batch = (unsigned int)value;
            break;

        case 'r':
            if (parse_u64(optarg, 0, UINT64_MAX, &value) != 0) {
                die_msg("Invalid target_tx_pps");
            }
            cfg->target_tx_pps = value;
            break;

        case 's':
            if (parse_u64(optarg, 0, UINT64_MAX, &value) != 0) {
                die_msg("Invalid statistics period");
            }
            cfg->stats_period_us = value;
            break;

        case 'o':
            cfg->out = optarg;
            break;

        case 'i':
            cfg->fixed_dcid = false;
            break;

        case 'h':
            srh_usage(argv[0]);
            exit(EXIT_SUCCESS);

        default:
            srh_usage(argv[0]);
            exit(EXIT_FAILURE);
        }
    }

    if (cfg->tx_probe_size < (1 + cfg->dcid_size + 1)) {
        die_msg("TX length too small for first byte + DCID + variable bytes");
    }
}

/* Resolve the server IP/hostname and UDP port into an IPv4 or IPv6 sockaddr_storage */
/** Written by ChatGPT **/
static int make_peer_addr(srh_config_t *cfg, struct sockaddr_storage *ss, socklen_t *sslen) {
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    struct addrinfo *it;
    char port[16];
    int rc;

    if (!cfg || !ss || !sslen) return -1;

    memset(ss, 0, sizeof(*ss));  // Initialization at 0
    memset(&hints, 0, sizeof(hints));

    hints.ai_family = AF_UNSPEC;  // Automatically accept IPv4 or IPv6.
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;

    /* Port number format conversion: 'uint16_t' -> 'char*' */
    snprintf(port, sizeof(port), "%u", (unsigned int)cfg->server_port);

    /* Resolve the server IP address or hostname */
    rc = getaddrinfo(cfg->server_ip, port, &hints, &res);
    if (rc != 0) {
        fprintf(stderr, "getaddrinfo(%s): %s\n", cfg->server_ip, gai_strerror(rc));
        return -1;
    }

    /* Select the first address (IPv4 or IPv6) in res, and set it in ss */
    for (it = res; it != NULL; it = it->ai_next) {
        if ((it->ai_family == AF_INET || it->ai_family == AF_INET6) &&
            it->ai_addrlen <= sizeof(*ss)) {
            memcpy(ss, it->ai_addr, it->ai_addrlen);
            *sslen = (socklen_t)it->ai_addrlen;
            cfg->family = it->ai_family;
            freeaddrinfo(res);
            return 0;
        }
    }

    freeaddrinfo(res);
    return -1;
}

/* Create the connected UDP socket used to send probes and receive Stateless Reset */
/** Written by ChatGPT **/
static int make_udp_socket_connected(
    const srh_config_t *cfg,
    const struct sockaddr *dst,
    socklen_t dstlen)
{
    int fd;
    int flags;
    int one = 1;
    int bufsize = SRH_UDP_SOCKET_BUF;

    fd = socket(cfg->family, SOCK_DGRAM, 0);  // Creation of the socket
    if (fd < 0) return -1;

    flags = fcntl(fd, F_GETFL, 0);  // Get the socket flags
    if (flags < 0) {
        close(fd);
        return -1;
    }

    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) { // Set in non-blocking mode
        close(fd);
        return -1;
    }

    /* Anabled SO_REUSEADDR and set the TX and RX buffer size at SRH_UDP_SOCKET_BUF */
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) != 0) {
        fprintf(stderr, "[WARN] setsockopt(SO_REUSEADDR) failed: %s\n", strerror(errno));
    }
    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize)) != 0) {
        fprintf(stderr, "[WARN] setsockopt(SO_SNDBUF) failed: %s\n", strerror(errno));
    }
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize)) != 0) {
        fprintf(stderr, "[WARN] setsockopt(SO_RCVBUF) failed: %s\n", strerror(errno));
    }

    if (cfg->family == AF_INET) {  // Bind IPv4
        struct sockaddr_in local;
        memset(&local, 0, sizeof(local));
        local.sin_family = AF_INET;
        local.sin_port = htons(cfg->local_port);
        local.sin_addr.s_addr = htonl(INADDR_ANY);

        if (bind(fd, (const struct sockaddr *)&local, sizeof(local)) != 0) {
            close(fd);
            return -1;
        }
    } else if (cfg->family == AF_INET6) {  // Bind IPv6
        struct sockaddr_in6 local6;
        memset(&local6, 0, sizeof(local6));
        local6.sin6_family = AF_INET6;
        local6.sin6_port = htons(cfg->local_port);
        local6.sin6_addr = in6addr_any;

        if (bind(fd, (const struct sockaddr *)&local6, sizeof(local6)) != 0) {
            close(fd);
            return -1;
        }
    } else {  // Address family not supported
        close(fd);
        errno = EAFNOSUPPORT;
        return -1;
    }

    if (connect(fd, dst, dstlen) != 0) {  // UDP socket connection
        close(fd);
        return -1;
    }

    return fd;
}

/* Return a random DCID */
static void srh_random_dcid(uint8_t *dcid, size_t dcid_size) {
    if (!dcid || dcid_size == 0) return;

    ssize_t n;

    n = getrandom(dcid, dcid_size, 0);
    if (n != (ssize_t)dcid_size) {
        die_perror("getrandom");
    }
}

/* Initialize srh_config with default values. */
static void srh_init_default_cfg(srh_config_t *cfg) {
    if (cfg == NULL) return;

    memset(cfg, 0, sizeof(*cfg));  // initialize to 0
    cfg->family = AF_UNSPEC;
    cfg->server_ip = SRH_SERVER_IP;
    cfg->server_port = SRH_SERVER_PORT;
    cfg->local_port = SRH_DEF_LOC_PORT;
    cfg->dcid_size = SRH_DEF_DCID_SIZE;
    cfg->tx_probe_size = SRH_DEF_PROBE_SIZE;
    cfg->target_sr = SRH_DEF_TARGET_SR;
    cfg->udp_batch = SRH_DEF_UDP_BATCH;
    cfg->stats_period_us = SRH_STATS_PERIOD_US;
    cfg->out = SRH_OUTPUT_FILE;
    cfg->target_tx_pps = SRH_DEF_PROBE_RATE;
    cfg->fixed_dcid = SRH_DEF_FIXED_DCID;
}

/* Initialize the probe template: short-header-like QUIC packet */
static void srh_init_tx_template(srh_probe_t *probe, const srh_config_t *cfg) {
    size_t i;

    memset(probe, 0, sizeof(*probe));  // Initialize to 0
    probe->size = cfg->tx_probe_size;
    probe->dcid_off = 1;
    probe->after_dcid = 1 + cfg->dcid_size;

    /* First byte of a plausible QUIC short header:
     *   bit 7 = 0 -> Short Header
     *   bit 6 = 1 -> fixed bit
     */
    probe->data[0] = 0x40;

    /* Fill the remaining probe bits with a simple deterministic pattern */
    for (i = probe->after_dcid; i < probe->size; i++) {
        probe->data[i] = (uint8_t)(0xA5u ^ (uint8_t)(29u * i));
    }
}

/* Initialize the preallocated TX batch used to send probes with sendmmsg() */
static void srh_init_tx_batch(
    srh_udp_batch_t *tx,
    unsigned int batch_size,
    const srh_probe_t *probe,
    const srh_config_t *cfg)
{
    if (tx == NULL || probe == NULL || cfg == NULL) die_msg("Invalid TX batch initialization");
    unsigned int i;

    memset(tx, 0, sizeof(*tx));
    for (i = 0; i < batch_size; i++) {
        memcpy(tx->buf[i], probe->data, probe->size);

        /* DCID is initialized randomly only once. Then, only the last 8 bytes
         * are incremented with each new probe */
        srh_random_dcid(tx->buf[i] + probe->dcid_off, cfg->dcid_size);

        tx->iov[i].iov_base = tx->buf[i];
        tx->iov[i].iov_len = probe->size;
        tx->msg[i].msg_hdr.msg_iov = &tx->iov[i];
        tx->msg[i].msg_hdr.msg_iovlen = 1;
    }
}

/* Initialize the preallocated RX batch used by recvmmsg() */
static void srh_init_rx_batch(srh_udp_batch_t *rx, unsigned int batch_size) {
    if (rx == NULL) die_msg("Invalid RX batch initialization");
    unsigned int i;

    memset(rx, 0, sizeof(*rx));
    for (i = 0; i < batch_size; i++) {
        rx->iov[i].iov_base = rx->buf[i];
        rx->iov[i].iov_len = sizeof(rx->buf[i]);
        rx->msg[i].msg_hdr.msg_iov = &rx->iov[i];
        rx->msg[i].msg_hdr.msg_iovlen = 1;
    }
}

/* Extract a view of a received Stateless Reset */
static int srh_extract_sr_view(const uint8_t *buf, size_t size, srh_sr_view_t *out) {
    if (!buf || !out) return -1;
    if (size < SRH_MIN_SR_SIZE) return 0;  // Minimum size of a short-header QUIC pkt
    if ((buf[0] & 0xC0u) != 0x40u) return 0;  // First two bits = 0x40

    out->prefix = buf;
    out->prefix_size = size - SRH_TOKEN_SIZE;
    out->token = buf + (size - SRH_TOKEN_SIZE);
    out->token_size = SRH_TOKEN_SIZE;
    return 1;
}

/* Write one harvested Stateless Reset prefix record to the binary output file.
 * Record format: [uint32_t prefix_size][prefix bytes]
 */
static int srh_record_sr(FILE *fp, const srh_sr_view_t *sr_view) {
    if (!fp || !sr_view) return 0;
    uint32_t prefix_size;

    prefix_size = (uint32_t)sr_view->prefix_size;
    if (fwrite(&prefix_size, sizeof(prefix_size), 1, fp) != 1) return -1;
    if (prefix_size > 0 && fwrite(sr_view->prefix, 1, prefix_size, fp) != prefix_size) return -1;

    return 0;
}

/* Print current statistics */
static void srh_print_stats(srh_ctx_t *ctx, uint64_t now_us_value, int force) {
    if (ctx == NULL || ctx->start_time_us == 0) return;
    if (!force && ctx->cfg.stats_period_us == 0) return;
    if (!force && now_us_value < ctx->last_stats_time_us + ctx->cfg.stats_period_us) return;

    double elapsed_s;
    double window_s;
    double random_avg_kib_s = 0.0;
    double random_int_kib_s = 0.0;
    double avg_unpredictable_bits = 0.0;

    elapsed_s = (double)(now_us_value - ctx->start_time_us) / 1000000.0;
    window_s = (double)(now_us_value - ctx->last_stats_time_us) / 1000000.0;

    if (elapsed_s > 0.0) {
        random_avg_kib_s = ((double)ctx->stats.unpredictable_bits / 8.0) / (1024.0 * elapsed_s);
    }
    if (window_s > 0.0) {
        random_int_kib_s = ((double)(ctx->stats.unpredictable_bits - ctx->last_stats_unpr_bits) / 8.0)
           / (1024.0 * window_s);
    }
    if (ctx->stats.sr_count > 0) {
        avg_unpredictable_bits = (double)ctx->stats.unpredictable_bits
           / (double)ctx->stats.sr_count;
    }

    fprintf(stdout,
        "[Elapsed=%.3f s]"
        " random_int=%.1f KiB/s"
        " ; random_avg=%.1f KiB/s"
        " ; probes_sent=%" PRIu64
        " ; sr_recv=%" PRIu64 "/%u"
        " ; udp_rx=%" PRIu64 " datagrams / %" PRIu64 " bytes"
        " ; calls=%" PRIu64 " sendmmsg / %" PRIu64 " recvmmsg"
        " ; avg_unpredictable_bits=%.1f\n",
        elapsed_s,
        random_int_kib_s,
        random_avg_kib_s,
        ctx->stats.probe_count,
        ctx->stats.sr_count,
        (unsigned int)ctx->cfg.target_sr,
        ctx->stats.udp_rx_count,
        ctx->stats.udp_rx_bytes,
        ctx->stats.send_calls,
        ctx->stats.recv_calls,
        avg_unpredictable_bits);

    ctx->last_stats_time_us = now_us_value;
    ctx->last_stats_unpr_bits = ctx->stats.unpredictable_bits;
}

/* Prepare unique incremented DCIDs, seen as big-endian integer, for the next TX batch */
static void srh_prepare_tx_dcids(srh_ctx_t *ctx, unsigned int count) {
    const srh_config_t *cfg = &ctx->cfg;
    const srh_probe_t *probe = &ctx->probe;
    const uint8_t *base_dcid = probe->data + probe->dcid_off;
    uint64_t seq = ctx->stats.probe_count;
    unsigned int i;

    for (i = 0; i < count; i++) {
        uint8_t *dst = ctx->tx->buf[i] + probe->dcid_off;
        uint64_t carry = seq + (uint64_t)i;
        size_t pos = cfg->dcid_size;

        memcpy(dst, base_dcid, cfg->dcid_size);

        while (pos > 0 && carry != 0) {
            uint64_t v;

            pos--;
            v = (uint64_t)dst[pos] + (carry & 0xffu);
            dst[pos] = (uint8_t)v;
            carry = (carry >> 8) + (v >> 8);
        }
    }
}

/* Sends a batch of probes using sendmmsg(). Returns the number of probes successfully sent */
static int srh_send_burst(int fd, srh_udp_batch_t *tx, unsigned int count, srh_stats_t *stats) {
    int sent_count;

    /* Try to send 'count' UDP datagrams, starting at offset 'off'
     * of the buffer in the batch 'tx'
     */
    sent_count = sendmmsg(fd, &tx->msg[0], count, MSG_DONTWAIT);
    if (sent_count < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) return 0;
        return -1;
    }
    stats->send_calls++;

    return sent_count;
}

/* Drains available UDP responses in batches using recvmmsg(), and extracts Stateless Reset,
 * updates statistics, and stops when the target is reached.
 */
static int srh_drain_rx_batch(int fd, srh_udp_batch_t *rx, unsigned int max, srh_ctx_t *ctx) {
    srh_stats_t *stats = &ctx->stats;
    FILE *output = ctx->output;
    int total = 0;

    while (!g_stop_flag) {
        int recv_count;
        unsigned int i;

        recv_count = recvmmsg(fd, rx->msg, max, MSG_DONTWAIT, NULL);
        if (recv_count < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            if (errno == EINTR) {
                if (g_stop_flag) break;
                continue;
            }
            return -1;
        }
        if (recv_count == 0) break;

        stats->recv_calls++;
        total += recv_count;

        for (i = 0; i < (unsigned int)recv_count; i++) {
            srh_sr_view_t sr_view = {0};
            size_t len = rx->msg[i].msg_len;

            stats->udp_rx_count++;
            stats->udp_rx_bytes += (uint64_t)len;

            if (srh_extract_sr_view(rx->buf[i], len, &sr_view) > 0) {
                stats->unpredictable_bits += ((uint64_t)sr_view.prefix_size * 8ull) - 2ull;
                uint64_t parsed_after = ++stats->sr_count;

                if (output && srh_record_sr(output, &sr_view) != 0) return -1;
                if (ctx->cfg.target_sr > 0 && parsed_after >= ctx->cfg.target_sr) {
                    fprintf(stdout, "[SRH] Stateless Reset target reached: %" PRIu64 "\n", parsed_after);
                    g_stop_flag = true;
                    return total;
                }
            }
        }
    }
    return total;
}

 /* Runs the harvesting loop by:
  *   1. draining available UDP responses
  *   2. sending one TX batch of probes, applying optional rate limit
  *   3. printing periodic statistics.
  */
static int srh_loop(srh_ctx_t *ctx) {
    const srh_config_t *cfg = &ctx->cfg;
    srh_stats_t *stats = &ctx->stats;
    uint64_t tx_start_ns = now_ns();

    while (!g_stop_flag) {
        int drained;
        unsigned int want = cfg->udp_batch;
        bool tx_allowed = true;

        /* First drain any responses already queued in the kernel */
        drained = srh_drain_rx_batch(ctx->fd, ctx->rx, cfg->udp_batch, ctx);
        if (drained < 0) {
            perror("recvmmsg/capture");
            return -1;
        }

        /* Rate limiting compute how many probes are allowed and send only that amount */
        if (cfg->target_tx_pps > 0) {
            uint64_t now = now_ns();
            uint64_t elapsed_ns = now - tx_start_ns;
            uint64_t allowed_sent = (elapsed_ns * cfg->target_tx_pps) / 1000000000ull;

            if (allowed_sent <= stats->probe_count) {
                tx_allowed = false;
                want = 0;
            } else {
                uint64_t send_budget = allowed_sent - stats->probe_count;
                if (send_budget < (uint64_t)want) want = (unsigned int)send_budget;
            }
        }

        /* Send at most one full TX batch per loop iteration. */
        if (tx_allowed) {
            if (!cfg->fixed_dcid) srh_prepare_tx_dcids(ctx, want);
            int sent_count = srh_send_burst(ctx->fd, ctx->tx, want, stats);
            if (sent_count < 0) {
                perror("sendmmsg");
                return -1;
            }
            if (sent_count == 0) break;  // Socket temporarily unable to TX

            stats->probe_count += (uint64_t)sent_count;
        }

        srh_print_stats(ctx, now_us(), 0);  // Print stats if a period has elapsed
    }

    return 0;
}

/* Release all resources allocated */
static void srh_cleanup(srh_ctx_t* ctx) {
    if (ctx == NULL) return;

    if (ctx->output) fclose(ctx->output);
    free(ctx->coutput_buf);
    free(ctx->rx);
    free(ctx->tx);
    close(ctx->fd);
}

/*********************************
 * MAIN FUNCTION
 *********************************/

/* Initializes the harvester context and config with parsed options.
 * Opens the UDP socket and output file.
 * Runs the main harvesting loop and print statistics.
 */
int main(int argc, char **argv) {
    srh_ctx_t ctx;
    struct sockaddr_storage dst;
    socklen_t dstlen;
    int ret;

    signal(SIGINT, on_sigint);  // Ctrl+C handler: sets g_stop_flag
    g_stop_flag = false;

    memset(&ctx, 0, sizeof(ctx));
    memset(&ctx.stats, 0, sizeof(ctx.stats));
    srh_init_default_cfg(&ctx.cfg);
    srh_parse_args(argc, argv, &ctx.cfg);

    if (make_peer_addr(&ctx.cfg, &dst, &dstlen) != 0) die_msg("Invalid server address");
    ctx.fd = make_udp_socket_connected(&ctx.cfg, (const struct sockaddr *)&dst, dstlen);
    if (ctx.fd < 0) die_perror("make_udp_socket_connected");

    ctx.tx = calloc(1, sizeof(*ctx.tx));
    ctx.rx = calloc(1, sizeof(*ctx.rx));
    if (!ctx.tx || !ctx.rx) die_perror("calloc");

    if (ctx.cfg.out) {
        ctx.output = fopen(ctx.cfg.out, "wb");
        if (!ctx.output) die_perror("fopen capture file");

        ctx.coutput_buf = malloc(SRH_OUTPUT_BUFFER);
        if (!ctx.coutput_buf) die_perror("malloc capture stdio buffer");
        if (setvbuf(ctx.output, ctx.coutput_buf, _IOFBF, SRH_OUTPUT_BUFFER) != 0) {
            die_perror("setvbuf capture");
        }
    }

    srh_init_tx_template(&ctx.probe, &ctx.cfg);
    srh_init_tx_batch(ctx.tx, ctx.cfg.udp_batch, &ctx.probe, &ctx.cfg);
    srh_init_rx_batch(ctx.rx, ctx.cfg.udp_batch);

    fprintf(stderr,
            "[SRH] Start: server=%s port=%u local_port=%u dcid_size=%zu tx_probe_size=%zu "
            "target_sr=%" PRIu64 " udp_batch=%u stats_period_us=%" PRIu64
            " probe_rate=%" PRIu64 " output=%s\n",
            ctx.cfg.server_ip,
            ctx.cfg.server_port,
            ctx.cfg.local_port,
            ctx.cfg.dcid_size,
            ctx.cfg.tx_probe_size,
            ctx.cfg.target_sr,
            ctx.cfg.udp_batch,
            ctx.cfg.stats_period_us,
            ctx.cfg.target_tx_pps,
            ctx.cfg.out ? ctx.cfg.out : "off");

    ctx.start_time_us = now_us();
    ctx.last_stats_time_us = ctx.start_time_us;
    ctx.last_stats_unpr_bits = 0;

    ret = srh_loop(&ctx);

    if (ctx.output && fflush(ctx.output) != 0) die_perror("fflush capture");
    fprintf(stdout, "[SRH] Finished:\n");
    srh_print_stats(&ctx, now_us(), 1);
    srh_cleanup(&ctx);

    return (ret == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}