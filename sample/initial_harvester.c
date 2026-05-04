/*
 * initial_harvester.c
 *
 * Minimal QUIC client derived from the structure of picoquic's sample_client.c.
 *
 * This program is not intended to behave as a complete QUIC application client.
 * In particular, it does not create application streams, does not exchange
 * application data, and does not try to complete or use an HTTP/3 session.
 *
 * It is an experimental tool designed to test the oracle's access to the
 * peer's secure random source trough TLS Handshake.
 *
 * Goal:
 *   Its only purpose is to run a controlled laboratory measurement: create many
 *   short-lived QUIC client connections in order to trigger the server Initial
 *   flight, extract the TLS ServerHello.random value and the server Source
 *   Connection ID (SCID), then discard the connection as quickly as possible.
 *
 * Principle:
 *   - Keep only pool of picoquic connections awaiting the Server Initial answer
 *   - Each connection is used only to send a Client Initial
 *   - A custom TLS hook extract ServerHello.random from the TSL ServerHello,
 *     and the SCID (first DCID provided), and save in the output file:
 *           "server_scid_hex;serverhello_random_hex"
 *   - Stop further processing of that packet and return to the packet loop callback
 *   - Delete the corresponding connection
 *   - Create a new connection to fill the pool
 *
 *   In practice, additional mechanisms are implemented to make it reliable and
 *   effective (timeout, buffer, ...)
 *
 * Main constraint:
 *   The picoquic connections cannot be deleted immediately after sending the
 *   Client Initial. Picoquic still needs the connection state to decrypt and
 *   process the server Initial packet containing the ServerHello.
 *
 * Assumptions about the modified picoquic tree:
 *   - picoquic_set_on_server_hello_cb(cnx, cb, ctx) is available;
 *   - picoquic_set_on_udp_datagram_received_cb(quic, cb, ctx) is available;
 *   - The ServerHello hook returns IH_STOP_AFTER_SERVER_HELLO after extraction;
 *   - sockloop.c handles IH_STOP_AFTER_SERVER_HELLO as a non-fatal local stop,
 *     calls the packet-loop after-receive callback immediately, and skips the
 *     send phase for that iteration;
 *   - sockloop.c calls the UDP datagram hook after receiving a UDP datagram and
 *     before calling picoquic_incoming_packet_ex(...).
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
 *   - IH: Initial_Harvester
 *   - cnx: connection
 *   - ctx: context
 *   - st_: structure_
 *   - _t: _type
 *   - us: microseconds
 *   - sh: server_hello
 *   - cb: callback
 *   - fn: function
 *   - bw: bandwidth
 */

/*********************************
 * INCLUDE
 *********************************/

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <signal.h>

#ifdef _WINDOWS
#include <WinSock2.h>
#include <Windows.h>
#else
#include <unistd.h>
#endif

#include "picoquic.h"
#include "picoquic_packet_loop.h"
#include "picoquic_utils.h"
#include "quicctx.c"

/*********************************
 * DEFINE CONSTANT VALUE
 *********************************/

#define IH_ALPN               "h3"                    // HTTP/3 as Application Protocol
#define IH_SNI                "localhost"             // DNS Server name used for TLS SNI
#define IH_OUTPUT_FILE        "randoms.txt"           // Output file to save harvested random values
#define IH_MAX_INFLIGHT       ((size_t)32)            // Default max number of active cnx
#define IH_TARGET_SH          ((size_t)0)             // Default number of ServerHello to harvest, 0=infinite
#define IH_OUTPUT_BUFFER      ((size_t)16*1024*1024)  // Size of the buffer used to save random numbers
#define IH_REFILL_BURST       ((size_t)32)            // Max number of new cnx at each loop
#define IH_TIMEOUT_US         UINT64_C(100000)       // Default max lifetime of a cnx in us
#define IH_STATS_PERIOD_US    UINT64_C(1000000)       // Period between stats report in us
#define IH_TIMEOUT_PERIOD_US  UINT64_C(10000)         // Default verification period of cnx timeout in us
#define IH_SCID_HARVEST       1                       // SCIDs are also extracted (0=True, 1=False)

/*********************************
 * TYPES
 *********************************/

/* Type prototype: custom connection context structure */
typedef struct st_ih_ctx_t ih_ctx_t;

/* Type: custom connexion structure that can be chained */
typedef struct st_ih_cnx_t {
    picoquic_cnx_t* cnx;       // Picoquic cnx
    ih_ctx_t* ctx;             // Custom context of this cnx
    uint64_t created_at;       // Creation time to check the timeout
    int delete_requested;      // Indicates if this cnx have to be cnx_deleted
    struct st_ih_cnx_t* next;  // Next link of the chain
} ih_cnx_t;

/* Type: test statistic */
typedef struct st_ih_stats_t {
    uint64_t cnx_started;    // Number of cnx started
    uint64_t cnx_timeouts;   // Number of cnx timeouts
    uint64_t cnx_deleted;    // Number of cnx deleted
    uint64_t sh_received;    // Number of server hello received
    uint64_t udp_datagrams;  // Number of UDP datagrams received
    uint64_t udp_bytes;      // Total size received as UDP payload, in bytes
} ih_stats_t;

/* Custom context structure (declared in the type prototype) */
struct st_ih_ctx_t {
    picoquic_quic_t* quic;                // Picoquic global ctx in which this cnx ctx belongs
    struct sockaddr_storage server_addr;  // Network address
    const char* sni;                      // Server name requested
    const char* alpn;                     // Application protocol requested
    FILE* out;                            // Output file to save harvested random numbers
    char* outbuf;                         // Buffr for harvested random numbers before saving
    ih_cnx_t* first;                      // First element of the cnx chain
    ih_cnx_t* last;                       // Last element of the cnx chain
    size_t active;                        // Current number of active cnx
    size_t max_inflight;                  // Max number of active cnx
    uint64_t timeout_us;                  // Max lifetime of a cnx in us
    uint64_t target_sh;                   // Target number of sh harvested (0 = infinite)
    uint64_t start_time;                  // Start time of the test
    uint64_t last_stats_time;             // Last time stats were displayed
    uint64_t last_stats_sh_received;      // Number of sh received in the last stats displayed
    uint64_t pending_delete;              // Number of cnx deletion requested
    uint64_t next_check_timeout_time;     // Next time to check timeouts
    ih_stats_t stats;                     // Global stats of the test
};

/*********************************
 * STATIC VARIABLES
 *********************************/

/* Global flag to indicate that the test termination is request */
static volatile sig_atomic_t stop_flag = 0;

/*********************************
 * STATIC FUNCTIONS
 *********************************/

/* SIGINT signal handler (Ctrl+C): clean program termination */
static void ih_sigint_handler(int sig) {
    (void)sig;  // Unused: sig always equals SIGINT in this handler
    stop_flag = 1;
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
 * if IH_STATS_PERIOD_US elapsed since the last print, or force != 0.
 */
static void ih_print_stats(ih_ctx_t* ctx, uint64_t now, int force) {
    if (ctx == NULL || ctx->start_time == 0) return;
    if (!force && now < ctx->last_stats_time + IH_STATS_PERIOD_US) return;

    double elapsed_s;
    double window_s;
    double avg_kib_s = 0.0;
    double inst_kib_s = 0.0;
    uint64_t delta_sh;

    elapsed_s = (double)(now - ctx->start_time) / 1000000.0;
    window_s = (double)(now - ctx->last_stats_time) / 1000000.0;
    delta_sh = ctx->stats.sh_received - ctx->last_stats_sh_received;
    if (elapsed_s > 0.0) avg_kib_s = ((double)ctx->stats.sh_received * 32.0) / (1024.0 * elapsed_s);
    if (window_s > 0.0) inst_kib_s = ((double)delta_sh * 32.0) / (1024.0 * window_s);

    fprintf(stdout,
        "[Elapsed=%.3f s]"
        " random_int=%.1f KiB/s"
        " ; random_avg=%.1f KiB/s"
        " ; cnx_started=%" PRIu64
        " ; cnx_active=%zu"
        " ; cnx_deleted=%" PRIu64
        " ; cnx_timeouts=%" PRIu64
        " ; udp=%" PRIu64 " datagrams / %" PRIu64 " bytes"
        " ; sh_received=%" PRIu64 "\n",
        elapsed_s,
        inst_kib_s,
        avg_kib_s,
        ctx->stats.cnx_started,
        ctx->active,
        ctx->stats.cnx_deleted,
        ctx->stats.cnx_timeouts,
        ctx->stats.udp_datagrams,
        ctx->stats.udp_bytes,
        ctx->stats.sh_received);

        ctx->last_stats_time = now;
        ctx->last_stats_sh_received = ctx->stats.sh_received;
}

/* Callback function triggered on each UDP datagram reception.
 * It updates the received UDP datagram and byte counters.
 */
static void ih_on_udp_datagram_received(size_t udp_payload_length, void* callback_ctx) {
    ih_ctx_t* ctx = (ih_ctx_t*)callback_ctx;
    if (ctx != NULL) {
        ctx->stats.udp_datagrams++;
        ctx->stats.udp_bytes += (uint64_t)udp_payload_length;
    }
}

/* Mark a cnx for deletion and increment the counter for cnx awaiting deletion */
static void ih_mark_delete(ih_cnx_t* ih_cnx) {
    if (ih_cnx == NULL || ih_cnx->delete_requested) return;

    ih_ctx_t* ctx;
    ctx = ih_cnx->ctx;
    ih_cnx->delete_requested = 1;
    if (ctx != NULL) ctx->pending_delete++;
}

/* Callback function triggered on each potential sh reception */
static int ih_on_server_hello(picoquic_cnx_t* cnx, const uint8_t server_random[32], void* cb_ctx) {
    ih_cnx_t* ih_cnx = (ih_cnx_t*)cb_ctx;
    if (ih_cnx == NULL || ih_cnx->ctx == NULL) return 0;

    ih_ctx_t* ctx;
    picoquic_connection_id_t server_scid;
    char scid_hex[2 * 20 + 1];
    char random_hex[2 * 32 + 1];

    ctx = ih_cnx->ctx;
    ctx->stats.sh_received++;
    server_scid = picoquic_get_server_cnxid(cnx);
    bytes_to_hex(server_scid.id, server_scid.id_len, scid_hex, sizeof(scid_hex));
    bytes_to_hex(server_random, 32, random_hex, sizeof(random_hex));

    /* Randomness extracted saved */
    if (ctx->out != NULL) {
        if(IH_SCID_HARVEST) fprintf(ctx->out, "%s;%s\n", scid_hex, random_hex);
        else fprintf(ctx->out, "%s\n", random_hex);
    }

    /* ih_cnx is mark to delete */
    ih_mark_delete(ih_cnx);

    /* sh processing complete, code sent to stop processing this cnx */
    return IH_STOP_AFTER_SERVER_HELLO;
}

/* Add a ih_cnx at the end of chain in the ih_ctx */
static void ih_add_cnx(ih_ctx_t* ctx, ih_cnx_t* ih_cnx) {
    if (ctx == NULL || ih_cnx == NULL) return;

    /* New cnx add at the end of the chain to keep a chronologically decreasing order */
    ih_cnx->next = NULL;
    if (ctx->last != NULL) ctx->last->next = ih_cnx;
    else ctx->first = ih_cnx;
    ctx->last = ih_cnx;
    ctx->active++;
}

/* Delete all the pending cnx deletion, and timed out cnx if check_timeouts */
static void ih_prune_connections(ih_ctx_t* ctx, uint64_t now, int check_timeouts) {
    if (ctx == NULL) return;
    if (ctx->pending_delete == 0 && !check_timeouts) return;

    ih_cnx_t** pp;
    ih_cnx_t* prev = NULL;

    /* If check_timeouts, since the cnx are chained from the oldest to newest,
     * at first cnx haven't reached the limit time the check for timeouts stop.
     */
    int timeout_boundary_seen = 0;

    pp = &ctx->first;
    while (*pp != NULL) {
        ih_cnx_t* ih_cnx = *pp;
        int remove = 0;
        int remove_is_pending_delete = 0;

        if (ih_cnx->delete_requested) {
            remove = 1;
            if (ctx->pending_delete > 0) remove_is_pending_delete = 1;
        } else if (check_timeouts &&
                   now >= ih_cnx->created_at &&
                   now - ih_cnx->created_at > ctx->timeout_us) {
            remove = 1;
            ctx->stats.cnx_timeouts++;
        }

        if (!remove) {
            if (check_timeouts) timeout_boundary_seen = 1;
            if (ctx->pending_delete == 0) break;

            prev = ih_cnx;
            pp = &ih_cnx->next;
            continue;
        }

        /* ih_cnx deletion */
        *pp = ih_cnx->next;
        if (ctx->last == ih_cnx) ctx->last = prev;
        if (remove_is_pending_delete && ctx->pending_delete > 0) ctx->pending_delete--;
        if (ih_cnx->cnx != NULL) {
            picoquic_delete_cnx(ih_cnx->cnx);
            ih_cnx->cnx = NULL;
        }
        free(ih_cnx);
        if (ctx->active > 0) ctx->active--;
        ctx->stats.cnx_deleted++;

        /* If the chain is empty */
        if (ctx->first == NULL) ctx->last = NULL;

        if (ctx->pending_delete == 0) {
            if (!check_timeouts || timeout_boundary_seen) break;
        }
    }
}

/* Create a new ih_cnx and add it to the ih_ctx */
static int ih_start_one_connection(ih_ctx_t* ctx) {
    int ret;
    picoquic_cnx_t* cnx;
    ih_cnx_t* ih_cnx;
    uint64_t now;

    now = picoquic_current_time();
    cnx = picoquic_create_cnx(
        ctx->quic,
        picoquic_null_connection_id,
        picoquic_null_connection_id,
        (struct sockaddr*)&ctx->server_addr,
        now,
        0,
        ctx->sni,
        ctx->alpn,
        1);
    if (cnx == NULL) return -1;

    ih_cnx = (ih_cnx_t*)calloc(1, sizeof(*ih_cnx));
    if (ih_cnx == NULL) {
        picoquic_delete_cnx(cnx);
        return -1;
    }

    ih_cnx->cnx = cnx;
    ih_cnx->ctx = ctx;
    ih_cnx->created_at = now;
    ih_cnx->delete_requested = 0;
    ih_cnx->next = NULL;

    /* Set the callback on serveur hello reception */
    picoquic_set_on_server_hello_cb(cnx, ih_on_server_hello, ih_cnx);

    /* Start the cnx, prepare client handshake */
    ret = picoquic_start_client_cnx(cnx);
    if (ret != 0) {
        picoquic_delete_cnx(cnx);
        free(ih_cnx);
        return ret;
    }
    ih_add_cnx(ctx, ih_cnx);
    ctx->stats.cnx_started++;

    return 0;
}

/* Create n new cnx to try to reach max_inflight active cnx,
 * n = Max[ max_inflight-ctx.active ; IH_REFILL_BURST ].
 */
static int ih_fill_window_burst(ih_ctx_t* ctx) {
    size_t n = 0;

    while (ctx->active < ctx->max_inflight && n < IH_REFILL_BURST) {
        if (ih_start_one_connection(ctx) != 0) {
            return -1;
        }
        n++;
    }

    return 0;
}

/* Custom packet loop callback */
static int ih_loop_cb(
    picoquic_quic_t* quic,
    picoquic_packet_loop_cb_enum cb_mode,
    void* callback_ctx,
    void* callback_arg)
{
    (void)quic; // Not used, already in callback_ctx
    uint64_t now;
    ih_ctx_t* ctx = (ih_ctx_t*)callback_ctx;
    if (ctx == NULL) return PICOQUIC_ERROR_UNEXPECTED_ERROR;

    /* cb_mode: event that have triggered this callback */
    switch (cb_mode) {
        case picoquic_packet_loop_ready:
            fprintf(stdout, "[READY] packet loop ready\n");
            now = picoquic_current_time();
            ctx->next_check_timeout_time = now + IH_TIMEOUT_PERIOD_US;
            break;

        /* An UDP datagram has been received and processed */
        case picoquic_packet_loop_after_receive:
            now = picoquic_current_time();

            /* Deletion of cnx marked to delete, and timeouts if next check time is reached */
            if (now >= ctx->next_check_timeout_time) {
                ih_prune_connections(ctx, now, 1);
                ctx->next_check_timeout_time = now + IH_TIMEOUT_PERIOD_US;
            }
            else ih_prune_connections(ctx, now, 0);

            /* Creation of new cnx to fill the active cnx window */
            ih_fill_window_burst(ctx);

            /* Print stats if next stats time is reached */
            ih_print_stats(ctx, now, 0);
            break;

        case picoquic_packet_loop_after_send:
        case picoquic_packet_loop_port_update:
        default:
            break;
    }

    if (stop_flag || (ctx->target_sh != 0 && ctx->stats.sh_received >= ctx->target_sh)) {
        return PICOQUIC_NO_ERROR_TERMINATE_PACKET_LOOP;
    }

    return 0;
}

/* Open the output file to write the random numbers harvested,
 * and create its buffer for performance.
 */
static int ih_open_output(ih_ctx_t* ctx) {
    /* Open the file for persistent save */
    ctx->out = fopen(IH_OUTPUT_FILE, "a");
    if (ctx->out == NULL) {
        fprintf(stderr, "Cannot open %s\n", IH_OUTPUT_FILE);
        return -1;
    }

    /* Buffer to stack random numbers before saving in the file by block */
    ctx->outbuf = (char*)malloc(IH_OUTPUT_BUFFER);
    if (ctx->outbuf != NULL) setvbuf(ctx->out, ctx->outbuf, _IOFBF, IH_OUTPUT_BUFFER);

    return 0;
}

/* Resolve the server address and select the SNI used in the TLS ClientHello. */
static int ih_resolve_server(
    const char* server_name,
    int server_port,
    struct sockaddr_storage* server_addr,
    const char** sni)
{
    int ret;
    int is_name = 0;

    ret = picoquic_get_server_address(server_name, server_port, server_addr, &is_name);
    if (ret != 0) {
        fprintf(stderr, "Cannot resolve server address for %s:%d\n", server_name, server_port);
        return ret;
    }

    /* TLS need a server name, not an IP */
    *sni = is_name ? server_name : IH_SNI;

    return 0;
}

/* Create and configure the custom quic ctx used. */
static int ih_create_quic(ih_ctx_t* ctx) {
    uint64_t now = picoquic_current_time();

    /* Minimal quic ctx */
    ctx->quic = picoquic_create(
        (int)(ctx->max_inflight + 16),
        NULL,      // cert_file_name
        NULL,      // key_file_name
        NULL,      // cert_root_file_name
        ctx->alpn, // default_alpn
        NULL,      // default_callback_fn
        NULL,      // default_callback_ctx
        NULL,      // cnx_id_callback
        NULL,      // cnx_id_callback_data
        NULL,      // reset_seed
        now,       // current_time
        NULL,      // p_simulated_time
        NULL,      // ticket_file_name
        NULL,      // ticket_encryption_key
        0);        // ticket_encryption_key_length
    if (ctx->quic == NULL) {
        fprintf(stderr, "Could not create picoquic context\n");
        return -1;
    }

    /* Deactivate certificate verification procedure to accept auto-signed certificates */
    picoquic_set_null_verifier(ctx->quic);

    /* Force X25519 as exchange group for TLS keys: The server targeted must accept it !
     * ngtcp2 server used for the tests accept this group.
     * Another server may need to change it !
     */
    if (picoquic_set_key_exchange(ctx->quic, PICOQUIC_GROUP_X25519) != 0) {
        fprintf(stderr, "Could not force X25519 key exchange\n");
        return -1;
    }

    /* Set the callback on UDP datagram reception with the global ctx */
    picoquic_set_on_udp_datagram_received_cb(ctx->quic, ih_on_udp_datagram_received, ctx);

    /* May be used by wireshark to decipher the QUIC packets */
    picoquic_set_key_log_file_from_env(ctx->quic);

    return 0;
}

/* Release all resources allocated */
static void ih_cleanup(ih_ctx_t* ctx)
{
    if (ctx == NULL) return;

    /* Delete all the active cnx */
    while (ctx->first != NULL) {
        ih_cnx_t* ih_cnx = ctx->first;
        ctx->first = ih_cnx->next;
        if (ih_cnx->cnx != NULL) picoquic_delete_cnx(ih_cnx->cnx);
        free(ih_cnx);
    }

    /* Freed the quic ctx */
    if (ctx->quic != NULL) {
        picoquic_free(ctx->quic);
        ctx->quic = NULL;
    }

    /* Save the randomness still in the buffer in the output file, then close the file */
    if (ctx->out != NULL) {
        fflush(ctx->out);
        fclose(ctx->out);
        ctx->out = NULL;
    }

    /* Freed the buffer  */
    if (ctx->outbuf != NULL) {
        free(ctx->outbuf);
        ctx->outbuf = NULL;
    }
}

/* Print command-line usage information. */
static void ih_usage(const char* prog)
{
    fprintf(stderr,
        "Usage: %s <server_name> <server_port> [max_inflight] [target_sh] [timeout_us]\n"
        "\n"
        "Default values:\n"
        "   max_inflight=%zu\n"
        "   target_sh=%zu (0=infinite)\n"
        "   timeout_us=%" PRIu64 "\n"
        "Examples:\n"
        "   %s 127.0.0.1 4443\n"
        "   %s 127.0.0.1 4443 32 30000\n"
        "   %s ::1 4443 256 100000 500000\n",
        prog,
        IH_MAX_INFLIGHT,
        IH_TARGET_SH,
        IH_TIMEOUT_PERIOD_US,
        prog, prog, prog);
}

/*********************************
 * MAIN FUNCTION
 *********************************/

/* Main steps:
 *   - initialize the harvester
 *   - start the picoquic packet loop
 *   - print final statistics
 *   - release all resources
 */
int main(int argc, char** argv)
{
    ih_ctx_t ctx;
    picoquic_packet_loop_param_t param;
    const char* server_name;
    int server_port;
    int ret;
    uint64_t now;

    memset(&ctx, 0, sizeof(ctx));
    memset(&param, 0, sizeof(param));

    /* Minimum 2 arguments are required: server_name and server_port */
    if (argc < 3 || argc > 6) {
        ih_usage(argv[0]);
        return -1;
    }

    server_name = argv[1];
    server_port = atoi(argv[2]);

    /* Set default values ctx */
    ctx.alpn = IH_ALPN;
    ctx.sni = IH_SNI;
    ctx.max_inflight = (size_t)IH_MAX_INFLIGHT;
    ctx.timeout_us = IH_TIMEOUT_US;
    ctx.target_sh = IH_TARGET_SH;

    /* Set users requested values */
    if (argc >= 4) ctx.max_inflight = (size_t)strtoull(argv[3], NULL, 10);
    if (argc >= 5) ctx.target_sh = strtoull(argv[4], NULL, 10);
    if (argc == 6) ctx.timeout_us = strtoull(argv[5], NULL, 10);

    /* Set an handler for SIGINT signal (Ctrl+C) */
    signal(SIGINT, ih_sigint_handler);

    ret = ih_open_output(&ctx);
    if (ret != 0) {
        ih_cleanup(&ctx);
        return ret;
    }

    ret = ih_resolve_server(server_name, server_port, &ctx.server_addr, &ctx.sni);
    if (ret != 0) {
        ih_cleanup(&ctx);
        return ret;
    }

    ret = ih_create_quic(&ctx);
    if (ret != 0) {
        ih_cleanup(&ctx);
        return ret;
    }

    /* Initialize timings */
    ctx.start_time = picoquic_current_time();
    ctx.last_stats_time = ctx.start_time;
    ctx.last_stats_sh_received = 0;

    ret = ih_fill_window_burst(&ctx);
    if (ret != 0) {
        fprintf(stderr, "Could not create initial connection window\n");
        ih_cleanup(&ctx);
        return ret;
    }

    /* Set parameters of the picoquic packet loop */
    param.local_af = ctx.server_addr.ss_family;   // IPv4 or IPv6
    param.socket_buffer_size = 16 * 1024 * 1024;  // Socket UDP buffer size
    param.do_not_use_gso = 0;
    param.extra_socket_required = 0;
    param.local_port = 0;                         // Client port chosen by the system

    fprintf(stdout,
        "[START] server=%s:%d max_inflight=%zu target_sh=%" PRIu64
        " timeout_us=%" PRIu64 " output=%s\n",
        server_name,
        server_port,
        ctx.max_inflight,
        ctx.target_sh,
        ctx.timeout_us,
        IH_OUTPUT_FILE);

    /* Start the picoquic packet loop, so the harvester */
    ret = picoquic_packet_loop_v2(ctx.quic, &param, ih_loop_cb, &ctx);

    /* The harvest is finished, print global stats */
    now = picoquic_current_time();
    fprintf(stdout, "[DONE] results: \n");
    ih_print_stats(&ctx, now, 1);

    ih_cleanup(&ctx);

    return ret;
}
