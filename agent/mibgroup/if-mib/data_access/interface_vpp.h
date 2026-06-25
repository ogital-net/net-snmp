/*
 * interface_vpp.h -- Shared VPP data access helpers.
 *
 * Declares the VAPI connection context, stats-segment helpers, and
 * counter-summation utilities used by all VPP arch backends.
 */

#ifndef IF_MIB_DATA_ACCESS_INTERFACE_VPP_H
#define IF_MIB_DATA_ACCESS_INTERFACE_VPP_H

#include <stdint.h>
#include <stdbool.h>
#include <vapi/vapi.h>
#include <vlib/counter_types.h>
#include <vpp-api/client/stat_client.h>

/*
 * VPP stats-segment paths used by this module.
 */
#define VPP_STATS_SOCKET     "/run/vpp/stats.sock"
#define VPP_STATS_PATH_RX    "/if/rx"
#define VPP_STATS_PATH_TX    "/if/tx"
#define VPP_STATS_PATH_DROPS "/if/drops"
/*
 * ifInErrors maps to /if/rx-error (genuine receive errors).
 * /if/rx-miss is a no-buffer drop (a discard, not an error) and is
 * intentionally NOT used here -- ifInDiscards is sourced from /if/drops.
 *
 * dot3Stats_vpp.c and etherstats_vpp.c follow the same classification:
 * they source error columns from /if/rx-error and /if/tx-error, and do
 * NOT use /if/rx-miss for dot3StatsInternalMacReceiveErrors (that column
 * is left at 0 because VPP does not expose a separate per-interface MAC
 * sublayer receive error counter).
 */
#define VPP_STATS_PATH_RXERR "/if/rx-error"
#define VPP_STATS_PATH_TXERR "/if/tx-error"

/*
 * VPP VAPI shared memory socket.
 */
#define VPP_VAPI_APP_NAME    "snmpd-ifmib"

/*
 * Maximum length of a VPP interface name including the NUL terminator.
 * VPP uses 64 bytes (VNET_INTF_NAME_MAX) but the VAPI struct allocates 64.
 */
#define VPP_IF_NAME_MAX 64

/*
 * VAPI request timeout.
 *
 * The VAPI context is opened in VAPI_MODE_NONBLOCKING so that a wedged or
 * crashed VPP cannot hang the snmpd agent thread forever (blocking mode uses
 * an unbounded SVM_Q_WAIT / pthread_cond_wait).  In non-blocking mode we drive
 * the dispatch loop ourselves and bound the total time spent waiting for a
 * request's replies with VPP_VAPI_REQUEST_TIMEOUT_S.
 *
 * Units are SECONDS (the value is passed to vapi_dispatch_one_timedwait(),
 * which forwards it to svm_queue_timedwait as unix_time_now() + timeout).
 * VPP_VAPI_DISPATCH_SLICE_S is the per-iteration wait so the loop re-checks
 * the overall deadline periodically.
 */
#define VPP_VAPI_REQUEST_TIMEOUT_S  3   /* overall per-request deadline (s) */
#define VPP_VAPI_DISPATCH_SLICE_S   1   /* per-dispatch_one wait slice (s)  */

/*
 * Shared VAPI context (owned by interface_vpp.c).
 */
extern vapi_ctx_t g_vapi_ctx;
extern bool       g_stats_connected;

/*
 * Lazy-connect to VPP VAPI.  Returns 0 on success, -1 on failure.
 */
int vapi_connect_once(void);

/*
 * Drive the VAPI dispatch loop (non-blocking mode) until the caller's dump
 * completion flag is set or the overall timeout elapses.
 *
 * @param done  Pointer to a volatile flag the dump's reply callback sets to
 *              true once the end-of-dump sentinel (is_last && !details) or a
 *              single-reply response has been received.
 *
 * @return  0 if *done became true within the deadline,
 *         -1 on dispatch error or timeout (caller should treat the VAPI
 *            connection as broken and reconnect).
 */
int vapi_dump_dispatch(volatile bool *done);

/*
 * Disconnect and free the shared VAPI context (g_vapi_ctx -> NULL).
 * Call after any VAPI request failure or timeout; the next
 * vapi_connect_once() will establish a fresh session.
 */
void vapi_reset_connection(void);

/*
 * Pump pending VAPI messages without blocking.  Drains the input queue, which
 * answers VPP's memclnt_keepalive pings so an otherwise-idle VAPI session is
 * not reaped.  Called from the agent main loop each select() cycle.
 */
void vapi_pump(void);

/*
 * Ensure the stats-segment connection is established.
 * Calls clib_mem_init() on first invocation (once per process).
 * Returns 0 on success, -1 on failure.
 */
int vpp_stats_connect_once(void);

/*
 * Return the number of sw_if_index slots VPP currently reports, i.e. the
 * length of the per-interface stats counter vectors (equivalently the
 * highest sw_if_index + 1).  This is the authoritative interface count as
 * reported by VPP itself -- callers must NOT assume a fixed upper bound.
 *
 * Ensures the stats segment is connected first.
 *
 * @return  interface count (>= 0) on success, -1 if VPP/stats unavailable.
 */
int vpp_stats_iface_count(void);

/*
 * Per-interface combined counter snapshot (sums all worker threads).
 */
typedef struct {
    uint64_t rx_packets;
    uint64_t rx_bytes;
    uint64_t tx_packets;
    uint64_t tx_bytes;
    uint64_t rx_drops;
    uint64_t tx_drops;
    uint64_t rx_errors;
    uint64_t tx_errors;
} vpp_if_counters_t;

/*
 * Read counters for sw_if_index from the stats segment.
 * max_sw_if_index is the highest sw_if_index seen in the sw_interface_dump;
 * the caller allocates an array of that size + 1.
 *
 * @return  0 on success, negative on error.
 */
int vpp_stats_read_counters(uint32_t max_sw_if_index,
                            vpp_if_counters_t *counters);

/*
 * Free a patterns vector built by stat_segment_string_vector().
 *
 * stat_segment_string_vector() builds a vector-of-vecs: an outer pointer
 * array plus one independently-allocated clib vec per path string.  This
 * helper frees the inner vecs first, then the outer array.
 */
void vpp_stats_free_patterns(uint8_t **patterns);

/*
 * Callback invoked once per dumped stat entry.  `name` is the stats-segment
 * path (e.g. "/if/rx"); `entry` is the dumped data (do not free or retain).
 */
typedef void (*vpp_stats_foreach_cb)(const char *name,
                                     const stat_segment_data_t *entry,
                                     void *ctx);

/*
 * Dump every stat under `prefix` in a single stat_segment_dump() and call
 * `cb` once per entry.  Preferred over per-path stat_segment_dump() loops.
 * Returns 0 on success, negative if the stats segment is unavailable.
 */
int vpp_stats_dump_foreach(const char *prefix, vpp_stats_foreach_cb cb,
                           void *ctx);

/*
 * Sum a combined_counter_vec across all workers for one sw_if_index.
 */
vlib_counter_t vpp_sum_combined(stat_segment_data_t *entry,
                                uint32_t sw_if_index);

/*
 * Sum a simple_counter_vec across all workers for one sw_if_index.
 */
uint64_t vpp_sum_simple(stat_segment_data_t *entry, uint32_t sw_if_index);

#endif /* IF_MIB_DATA_ACCESS_INTERFACE_VPP_H */
