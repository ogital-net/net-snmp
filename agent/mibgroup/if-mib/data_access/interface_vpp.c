/*
 * interface_vpp.c -- VPP-backed IF-MIB data access layer.
 *
 * Replaces interface_linux.c for builds targeting the latigo-gw appliance,
 * where all data-plane interfaces are owned by VPP.  Interface enumeration,
 * counter reads, and admin-status writes all go through the VPP API instead
 * of the Linux kernel netlink / ioctl paths.
 *
 * Data sources:
 *   - Interface inventory (name, MAC, flags, MTU, speed, type):
 *       VAPI sw_interface_dump over the SHM transport
 *   - Counters (bytes, packets, drops, errors):
 *       VPP stats segment via libvppapiclient (stat_client.h)
 *   - Admin-status write:
 *       VAPI sw_interface_set_flags
 *
 * VPP sw_if_index is used directly as the SNMP ifIndex.  This matches the
 * latigo-gw design where all interfaces are VPP-owned and sw_if_index >= 1.
 *
 * VAPI message-ID storage:
 *   The DEFINE_VAPI_MSG_IDS_* macros must appear in exactly one translation
 *   unit per linked binary.  They live here.
 */

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-features.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <net-snmp/agent/snmp_vars.h>
#include <net-snmp/data_access/interface.h>

#include "mibII/mibII_common.h"
#include "if-mib/ifTable/ifTable_constants.h"
#include "if-mib/data_access/interface.h"
#include "if-mib/data_access/interface_private.h"

/* Force netsnmp feature declarations needed by the generic interface layer. */
netsnmp_feature_child_of(interface_arch_set_admin_status, interface_all);

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>
#include <arpa/inet.h>

/* -- VPP VAPI high-level bindings ----------------------------------------- */
#include <vapi/vapi.h>
#include <vapi/vpe.api.vapi.h>
#include <vapi/interface.api.vapi.h>
#include <vapi/interface_types.api.vapi.h>
#include <vlibapi/api_types.h>   /* vl_api_c_string_to_api_string() */

/*
 * Allocate storage for the VAPI message-ID globals.
 * These macros expand to definitions of vapi_msg_id_<name> variables.
 * They must appear exactly once in the linked binary.
 */
DEFINE_VAPI_MSG_IDS_VPE_API_JSON;
DEFINE_VAPI_MSG_IDS_INTERFACE_API_JSON;
DEFINE_VAPI_MSG_IDS_INTERFACE_TYPES_API_JSON;

/* -- VPP stats segment client --------------------------------------------- */
#include <vpp-api/client/stat_client.h>
#include <vppinfra/mem.h>

/* -- Our own header (shared constants / types) ----------------------------- */
#include "interface_vpp.h"

/* --------------------------------------------------------------------------
 * Module-level VAPI context.
 * Initialized once in netsnmp_arch_interface_init() and reused across calls.
 * -------------------------------------------------------------------------- */
vapi_ctx_t g_vapi_ctx = NULL;
bool       g_stats_connected = false;

/*
 * VAPI connection helper
 * -----------------------------------------------------------*/

int
vapi_connect_once(void)
{
    vapi_error_e rv;

    if (g_vapi_ctx != NULL)
        return 0; /* already connected */

    rv = vapi_ctx_alloc(&g_vapi_ctx);
    if (rv != VAPI_OK) {
        snmp_log(LOG_ERR, "interface_vpp: vapi_ctx_alloc failed (%d)\n", rv);
        g_vapi_ctx = NULL;
        return -1;
    }

    /*
     * Connect in NON-BLOCKING mode.  In blocking mode every vapi_*_dump()
     * call ends in vapi_dispatch() -> svm_queue_sub(SVM_Q_WAIT), an unbounded
     * pthread_cond_wait: if VPP wedges or dies mid-request the snmpd agent
     * thread hangs forever.  In non-blocking mode the generated dump returns
     * immediately after sending and we drive the dispatch loop ourselves with
     * a bounded deadline (see vapi_dump_dispatch()).
     */
    rv = vapi_connect(g_vapi_ctx, VPP_VAPI_APP_NAME,
                      NULL,  /* no chroot prefix */
                      32,    /* max outstanding requests */
                      64,    /* response queue depth */
                      VAPI_MODE_NONBLOCKING,
                      true   /* handle keepalives */);
    if (rv != VAPI_OK) {
        snmp_log(LOG_ERR,
                 "interface_vpp: vapi_connect failed (%d) -- "
                 "is VPP running?\n", rv);
        vapi_ctx_free(g_vapi_ctx);
        g_vapi_ctx = NULL;
        return -1;
    }

    return 0;
}

/*
 * Bounded VAPI dispatch loop (non-blocking mode)
 *
 * In VAPI_MODE_NONBLOCKING the generated vapi_*_dump()/request helpers send
 * the message and return immediately; the caller is responsible for pumping
 * vapi_dispatch_one_timedwait() until all replies have been delivered to the
 * registered callbacks.  We loop until the caller's *done flag is set (the
 * reply callback sets it on the end-of-dump sentinel) or an overall deadline
 * elapses, whichever comes first.  This is what makes timeouts actually work.
 * -----------------------------------------------------------*/

int
vapi_dump_dispatch(volatile bool *done)
{
    time_t deadline = time(NULL) + VPP_VAPI_REQUEST_TIMEOUT_S;

    while (!*done) {
        vapi_error_e rv =
            vapi_dispatch_one_timedwait(g_vapi_ctx, VPP_VAPI_DISPATCH_SLICE_S);

        if (rv == VAPI_OK)
            continue; /* processed a message; check *done again */

        if (rv == VAPI_EAGAIN) {
            /* No message within the slice -- check the overall deadline. */
            if (time(NULL) >= deadline) {
                snmp_log(LOG_ERR,
                         "interface_vpp: VAPI dispatch timed out after %ds "
                         "(VPP unresponsive)\n", VPP_VAPI_REQUEST_TIMEOUT_S);
                return -1;
            }
            continue;
        }

        /* Any other return is a hard transport error. */
        snmp_log(LOG_ERR,
                 "interface_vpp: VAPI dispatch error (%d)\n", rv);
        return -1;
    }

    return 0;
}

/*
 * Pump pending VAPI messages without blocking.
 *
 * Drains the VAPI input queue, which is what answers VPP's memclnt_keepalive
 * pings (vapi_dispatch responds to them automatically when keepalives are
 * enabled).  The SNMP interface tables are read from the stats segment, not
 * VAPI, so without an occasional pump an otherwise-idle VAPI session answers
 * no keepalives and VPP's dead-client reaper eventually tears it down.  The
 * agent's main loop calls this each select() cycle; each call is a non-
 * blocking SVM_Q_NOWAIT drain that returns as soon as the queue is empty.
 */
void
vapi_pump(void)
{
    int i;

    if (!g_vapi_ctx)
        return;

    for (i = 0; i < 32; i++) {
        if (vapi_dispatch_one_timedwait(g_vapi_ctx, 0) != VAPI_OK)
            break;
    }
}

/*
 * Tear down the shared VAPI context.
 *
 * Called whenever a request fails or times out: the context may have
 * outstanding (never-answered) requests and a possibly-dead VPP peer, so we
 * disconnect and free it.  The next vapi_connect_once() re-establishes a clean
 * session.  Centralised here so every module resets identically.
 * -----------------------------------------------------------*/

void
vapi_reset_connection(void)
{
    if (g_vapi_ctx == NULL)
        return;
    vapi_disconnect(g_vapi_ctx);
    vapi_ctx_free(g_vapi_ctx);
    g_vapi_ctx = NULL;
}

/*
 * Stats-segment connection helper (shared by all VPP modules)
 * -----------------------------------------------------------*/

int
vpp_stats_connect_once(void)
{
    static bool clib_initialized = false;

    if (g_stats_connected)
        return 0;

    if (!clib_initialized) {
        /*
         * stat_segment_string_vector() uses VPP vec operations internally,
         * which require the clib heap allocator.  Per the VAPI test suite
         * (vapi_c_test.c), 1 MB is sufficient for a client that only needs
         * vec for stat path construction.  The vec-of-vecs built by
         * stat_segment_string_vector() are freed element-by-element (see
         * vpp_stats_free_patterns) so the heap stays bounded per poll.
         */
        clib_mem_init(0, 1 << 20);
        clib_initialized = true;
    }

    if (stat_segment_connect(VPP_STATS_SOCKET) != 0) {
        DEBUGMSGTL(("access:interface:vpp",
                    "stats segment not available at %s\n",
                    VPP_STATS_SOCKET));
        return -1;
    }

    g_stats_connected = true;
    return 0;
}

/*
 * Authoritative interface-count query
 *
 * The length of a per-interface stats counter vector is exactly the number
 * of sw_if_index slots VPP maintains (highest sw_if_index + 1).  We read it
 * from /if/rx (always present once at least one interface exists).  This is
 * the single source of truth for "how many interfaces" -- no module hard-codes
 * an upper bound.
 * -----------------------------------------------------------*/

int
vpp_stats_iface_count(void)
{
    uint8_t **patterns = NULL;
    uint32_t *stat_ids = NULL;
    stat_segment_data_t *data = NULL;
    uint32_t n_stats, i;
    int count = 0;

    if (vpp_stats_connect_once() != 0)
        return -1;

    patterns = stat_segment_string_vector(patterns, VPP_STATS_PATH_RX);
    stat_ids = stat_segment_ls(patterns);
    vpp_stats_free_patterns(patterns);
    if (!stat_ids) {
        /* VPP may have restarted; drop the stale mapping. */
        g_stats_connected = false;
        return -1;
    }

    n_stats = stat_segment_vec_len(stat_ids);
    data = stat_segment_dump(stat_ids);
    stat_segment_vec_free(stat_ids);
    if (!data) {
        g_stats_connected = false;
        return -1;
    }

    for (i = 0; i < n_stats; i++) {
        if (!data[i].name || strcmp(data[i].name, VPP_STATS_PATH_RX) != 0)
            continue;
        if (data[i].type == STAT_DIR_TYPE_COUNTER_VECTOR_COMBINED &&
            data[i].combined_counter_vec) {
            int nthreads =
                stat_segment_vec_len(data[i].combined_counter_vec);
            int t;
            /*
             * Per-thread vectors are all the same length (the interface
             * count); take the maximum to be safe against partial setup.
             */
            for (t = 0; t < nthreads; t++) {
                int vlen =
                    stat_segment_vec_len(data[i].combined_counter_vec[t]);
                if (vlen > count)
                    count = vlen;
            }
        }
    }

    stat_segment_data_free(data);
    return count;
}

/*
 * Free a stat_segment_string_vector() patterns vector.
 *
 * The patterns vector is a vector-of-vecs: each element is its own clib vec
 * (allocated by vec_validate_init_c_string inside stat_segment_string_vector).
 * Free each inner vec, then the outer array, so nothing is left in the clib
 * heap.
 * -----------------------------------------------------------*/

void
vpp_stats_free_patterns(uint8_t **patterns)
{
    int i, n;

    if (!patterns)
        return;

    n = stat_segment_vec_len(patterns);
    for (i = 0; i < n; i++)
        stat_segment_vec_free(patterns[i]);
    stat_segment_vec_free(patterns);
}

/*
 * Dump every stat under `prefix` in ONE stat_segment_ls()+stat_segment_dump()
 * and invoke `cb` once per entry.  This is the canonical way to read a group
 * of related stats: a single dump keeps clib-heap churn and per-request VPP
 * work flat regardless of how many OIDs are being walked.  Returns 0 on
 * success, negative if the stats segment is unavailable.
 * -----------------------------------------------------------*/

int
vpp_stats_dump_foreach(const char *prefix, vpp_stats_foreach_cb cb, void *ctx)
{
    uint8_t **patterns = NULL;
    uint32_t *dir;
    stat_segment_data_t *res;
    uint32_t n, i;

    if (!cb)
        return -1;

    if (vpp_stats_connect_once() != 0)
        return -1;

    patterns = stat_segment_string_vector(patterns, prefix);
    dir = stat_segment_ls(patterns);
    vpp_stats_free_patterns(patterns);

    if (!dir)
        return -1;
    if (stat_segment_vec_len(dir) == 0) {
        stat_segment_vec_free(dir);
        return -1;
    }

    res = stat_segment_dump(dir);
    stat_segment_vec_free(dir);
    if (!res)
        return -1;

    n = stat_segment_vec_len(res);
    for (i = 0; i < n; i++) {
        if (res[i].name)
            cb(res[i].name, &res[i], ctx);
    }

    stat_segment_data_free(res);
    return 0;
}

/*
 * Stats-segment counter reader
 * -----------------------------------------------------------*/

/*
 * Sum a combined_counter_vec across all worker threads for one sw_if_index.
 * Returns packets+bytes, zeroed if the index is out of range.
 */
vlib_counter_t
vpp_sum_combined(stat_segment_data_t *entry, uint32_t sw_if_index)
{
    vlib_counter_t result = {0, 0};
    int nthreads, i;

    if (!entry || entry->type != STAT_DIR_TYPE_COUNTER_VECTOR_COMBINED)
        return result;

    nthreads = stat_segment_vec_len(entry->combined_counter_vec);
    for (i = 0; i < nthreads; i++) {
        vlib_counter_t *vec = entry->combined_counter_vec[i];
        int vlen;

        if (!vec)
            continue;
        vlen = stat_segment_vec_len(vec);
        if ((int)sw_if_index >= vlen)
            continue;
        result.packets += vec[sw_if_index].packets;
        result.bytes   += vec[sw_if_index].bytes;
    }
    return result;
}

/*
 * Sum a simple_counter_vec across all threads for one sw_if_index.
 */
uint64_t
vpp_sum_simple(stat_segment_data_t *entry, uint32_t sw_if_index)
{
    uint64_t result = 0;
    int nthreads, i;

    if (!entry || entry->type != STAT_DIR_TYPE_COUNTER_VECTOR_SIMPLE)
        return 0;

    nthreads = stat_segment_vec_len(entry->simple_counter_vec);
    for (i = 0; i < nthreads; i++) {
        counter_t *vec = entry->simple_counter_vec[i];
        int vlen;

        if (!vec)
            continue;
        vlen = stat_segment_vec_len(vec);
        if ((int)sw_if_index >= vlen)
            continue;
        result += vec[sw_if_index];
    }
    return result;
}

int
vpp_stats_read_counters(uint32_t max_sw_if_index, vpp_if_counters_t *counters)
{
    uint8_t **patterns = NULL;
    uint32_t *stat_ids = NULL;
    stat_segment_data_t *data = NULL;
    uint32_t n_stats;
    unsigned i;
    int rc = 0;

    memset(counters, 0, sizeof(*counters) * (max_sw_if_index + 1));

    if (vpp_stats_connect_once() != 0)
        return -1;

    patterns = stat_segment_string_vector(patterns, VPP_STATS_PATH_RX);
    patterns = stat_segment_string_vector(patterns, VPP_STATS_PATH_TX);
    patterns = stat_segment_string_vector(patterns, VPP_STATS_PATH_DROPS);
    patterns = stat_segment_string_vector(patterns, VPP_STATS_PATH_RXERR);
    patterns = stat_segment_string_vector(patterns, VPP_STATS_PATH_TXERR);

    stat_ids = stat_segment_ls(patterns);
    vpp_stats_free_patterns(patterns);
    if (!stat_ids) {
        DEBUGMSGTL(("access:interface:vpp",
                    "stat_segment_ls returned no results\n"));
        /*
         * If VPP restarted, the stats segment mapping is stale.
         * Reset so the next poll will reconnect.
         */
        g_stats_connected = false;
        return 0; /* non-fatal: just report zero counters */
    }

    n_stats = stat_segment_vec_len(stat_ids);
    data = stat_segment_dump(stat_ids);
    stat_segment_vec_free(stat_ids);
    if (!data) {
        DEBUGMSGTL(("access:interface:vpp", "stat_segment_dump failed\n"));
        g_stats_connected = false;
        return 0;
    }

    for (i = 0; i < n_stats; i++) {
        uint32_t sw_if;

        if (!data[i].name)
            continue;

        for (sw_if = 0; sw_if <= max_sw_if_index; sw_if++) {
            if (strcmp(data[i].name, VPP_STATS_PATH_RX) == 0) {
                vlib_counter_t c = vpp_sum_combined(&data[i], sw_if);
                counters[sw_if].rx_packets += c.packets;
                counters[sw_if].rx_bytes   += c.bytes;
            } else if (strcmp(data[i].name, VPP_STATS_PATH_TX) == 0) {
                vlib_counter_t c = vpp_sum_combined(&data[i], sw_if);
                counters[sw_if].tx_packets += c.packets;
                counters[sw_if].tx_bytes   += c.bytes;
            } else if (strcmp(data[i].name, VPP_STATS_PATH_DROPS) == 0) {
                counters[sw_if].rx_drops +=
                    vpp_sum_simple(&data[i], sw_if);
            } else if (strcmp(data[i].name, VPP_STATS_PATH_RXERR) == 0) {
                counters[sw_if].rx_errors +=
                    vpp_sum_simple(&data[i], sw_if);
            } else if (strcmp(data[i].name, VPP_STATS_PATH_TXERR) == 0) {
                counters[sw_if].tx_errors +=
                    vpp_sum_simple(&data[i], sw_if);
            }
        }
    }

    stat_segment_data_free(data);
    return rc;
}

/*
 * sw_interface_dump callback state
 * -----------------------------------------------------------*/

typedef struct {
    netsnmp_container *container;
    uint32_t           max_sw_if_index;
    int                error;
    volatile bool      done;   /* set when end-of-dump sentinel received */
} dump_cb_ctx_t;

/*
 * Map VPP interface details to an IANA ifType.
 *
 * VPP's if_type enum is coarse (HARDWARE/SUB/P2P/PIPE).  The finer
 * interface kind is carried in interface_dev_type, which is the
 * VNET_DEVICE_CLASS name string (e.g. "Loopback", "tap", "virtio").
 */
static int
_vpp_if_type_to_iana(vapi_enum_if_type vpp_type, const char *dev_type,
                     const char *name)
{
    /*
     * local0 (sw_if_index 0) is VPP's null/discard interface.
     * It has no HW backing and no dev_type; classify by name.
     */
    if (name && strcmp(name, "local0") == 0)
        return IANAIFTYPE_OTHER;

    if (vpp_type == IF_API_TYPE_SUB)
        return IANAIFTYPE_ETHERNETCSMACD; /* subinterface */
    if (vpp_type == IF_API_TYPE_PIPE)
        return IANAIFTYPE_OTHER;

    /*
     * P2P in the VAPI enum is VNET_SW_INTERFACE_TYPE_P2P, which is only
     * used for p2p-ethernet subinterfaces - they are Ethernet.
     */
    if (vpp_type == IF_API_TYPE_P2P)
        return IANAIFTYPE_ETHERNETCSMACD;

    if (dev_type && dev_type[0] != '\0') {
        /* VNET_DEVICE_CLASS "Loopback" */
        if (strcmp(dev_type, "Loopback") == 0)
            return IANAIFTYPE_SOFTWARELOOPBACK;

        /*
         * Tunnel types - all have VNET_DEVICE_CLASS names like:
         * "GRE", "GRE tunnel device", "mGRE", "IPIP", "IPIP tunnel device",
         * "mIPIP", "ip6ip-6rd", "GTPU", "Wireguard", "Wireguard Tunnel".
         * Match on unique prefixes to avoid an exhaustive strcmp table.
         */
        if (strncmp(dev_type, "GRE", 3) == 0 ||
            strncmp(dev_type, "IPIP", 4) == 0 ||
            strncmp(dev_type, "ip6ip", 5) == 0 ||
            strncmp(dev_type, "mGRE", 4) == 0 ||
            strncmp(dev_type, "mIPIP", 5) == 0 ||
            strncmp(dev_type, "GTPU", 4) == 0 ||
            strncmp(dev_type, "Wireguard", 9) == 0)
            return IANAIFTYPE_TUNNEL;
    }

    /*
     * Fallback for everything else (dpdk, virtio, tap, af_packet, rdma,
     * memif, tuntap, etc.) - all are Ethernet.
     */
    return IANAIFTYPE_ETHERNETCSMACD;
}

/* --------------------------------------------------------------------------
 * VAPI callback: called once per sw_interface_details reply.
 * -------------------------------------------------------------------------- */
static vapi_error_e
_sw_interface_details_cb(vapi_ctx_t ctx __attribute__((unused)),
                         void *caller_ctx,
                         vapi_error_e rv,
                         bool is_last,
                         vapi_payload_sw_interface_details *details)
{
    dump_cb_ctx_t *dctx = (dump_cb_ctx_t *)caller_ctx;
    netsnmp_interface_entry *entry;
    char name[VPP_IF_NAME_MAX + 1];
    uint32_t sw_if;
    int iana_type;

    if (rv != VAPI_OK) {
        snmp_log(LOG_ERR, "interface_vpp: VAPI transport error in dump: %d\n",
                 rv);
        dctx->error = 1;
        dctx->done = true;
        return rv;
    }

    /* is_last=true with details=NULL is the end-of-dump sentinel. */
    if (is_last && !details) {
        dctx->done = true;
        return VAPI_OK;
    }

    if (!details)
        return VAPI_OK;

    sw_if = details->sw_if_index;

    /* Copy null-terminated interface name */
    memset(name, 0, sizeof(name));
    memcpy(name, details->interface_name,
           sizeof(details->interface_name) < VPP_IF_NAME_MAX
               ? sizeof(details->interface_name) : VPP_IF_NAME_MAX);

    DEBUGMSGTL(("access:interface:vpp",
                "sw_if_index=%-4u  name=%s  dev_type=%s\n",
                sw_if, name, details->interface_dev_type));

    iana_type = _vpp_if_type_to_iana(details->type,
                                     (const char *)details->interface_dev_type,
                                     name);

    /*
     * netsnmp_access_interface_entry_create() allocates the entry and
     * copies the name string.  The second argument is the ifIndex; we
     * use sw_if_index + 1 (SNMP ifIndex is 1-based, VPP sw_if_index is
     * 0-based).  This also avoids passing 0 which the framework treats
     * as "unknown -- please look up".
     */
    entry = netsnmp_access_interface_entry_create(name, sw_if + 1);
    if (!entry) {
        snmp_log(LOG_ERR, "interface_vpp: could not allocate entry for %s\n",
                 name);
        dctx->error = 1;
        return VAPI_OK; /* continue dump even on malloc failure */
    }

    /* --- Static / mostly-static interface properties ------------------- */

    entry->type = iana_type;
    entry->mtu  = details->link_mtu;

    /*
     * link_speed is in kbps in VPP 26.x VAPI (NOT Mbps -- the field was
     * changed from Mbps to kbps in VPP 23.02).  Convert to bps for SNMP.
     */
    {
        uint64_t speed_bps = (uint64_t)details->link_speed * 1000ULL;

        entry->speed      = speed_bps > 0xFFFFFFFFULL
                                ? 0xFFFFFFFFU
                                : (u_int)speed_bps;
        entry->speed_high = (u_int)(speed_bps / 1000000ULL);
    }

    /* MAC address (6 bytes from vapi_type_mac_address). */
    entry->paddr = (char *)malloc(6);
    if (entry->paddr) {
        memcpy(entry->paddr, details->l2_address, 6);
        entry->paddr_len = 6;
    }

    /* Admin and oper status */
    entry->admin_status =
        (details->flags & IF_STATUS_API_FLAG_ADMIN_UP)
            ? IFADMINSTATUS_UP : IFADMINSTATUS_DOWN;
    entry->oper_status =
        (details->flags & IF_STATUS_API_FLAG_LINK_UP)
            ? IFOPERSTATUS_UP : IFOPERSTATUS_DOWN;

    /* VPP tag -> ifAlias (interface description) */
    if (details->tag[0] != '\0') {
        size_t tag_len = strlen((const char *)details->tag);

        if (tag_len >= sizeof(entry->ifAlias))
            tag_len = sizeof(entry->ifAlias) - 1;
        memcpy(entry->ifAlias, details->tag, tag_len);
        entry->ifAlias[tag_len] = '\0';
        entry->ifAlias_len = tag_len;
    }

    /*
     * os_flags: we re-use the IFF_* values here because the generic layer
     * does not mandate a particular encoding, and it simplifies compat with
     * any helpers that check NETSNMP_INTERFACE_FLAGS_HAS_IF_FLAGS.
     */
    entry->os_flags = 0;
    if (details->flags & IF_STATUS_API_FLAG_ADMIN_UP)
        entry->os_flags |= IFF_UP;
    if (details->flags & IF_STATUS_API_FLAG_LINK_UP)
        entry->os_flags |= IFF_RUNNING;
    entry->ns_flags |= NETSNMP_INTERFACE_FLAGS_HAS_IF_FLAGS;

    /*
     * Hardcoded reassembly max (VPP does not report this via sw_interface_dump;
     * 65535 is the standard IPv4/IPv6 maximum).
     */
    entry->reasm_max_v4 = 65535;
    entry->reasm_max_v6 = 65535;
    entry->ns_flags |=
        NETSNMP_INTERFACE_FLAGS_HAS_V4_REASMMAX |
        NETSNMP_INTERFACE_FLAGS_HAS_V6_REASMMAX;

    /*
     * Mark capability flags -- counters filled below after the dump.
     * CALCULATE_UCAST tells the table code: iucast = iall - imcast.
     * We do not have multicast packet counts from the stats segment, so
     * we leave imcast at 0 and set CALCULATE_UCAST to derive iucast.
     */
    entry->ns_flags |=
        NETSNMP_INTERFACE_FLAGS_ACTIVE           |
        NETSNMP_INTERFACE_FLAGS_HAS_BYTES        |
        NETSNMP_INTERFACE_FLAGS_HAS_DROPS        |
        NETSNMP_INTERFACE_FLAGS_HAS_HIGH_BYTES   |
        NETSNMP_INTERFACE_FLAGS_HAS_HIGH_PACKETS |
        NETSNMP_INTERFACE_FLAGS_HAS_HIGH_SPEED   |
        NETSNMP_INTERFACE_FLAGS_CALCULATE_UCAST;

    netsnmp_access_interface_entry_overrides(entry);

    if (CONTAINER_INSERT(dctx->container, entry) != 0) {
        snmp_log(LOG_ERR,
                 "interface_vpp: container insert failed for %s\n", name);
        netsnmp_access_interface_entry_free(entry);
        dctx->error = 1;
    }

    if (sw_if > dctx->max_sw_if_index)
        dctx->max_sw_if_index = sw_if;

    return VAPI_OK;
}

/*
 * Public arch functions required by interface_private.h
 * -----------------------------------------------------------*/

/**
 * netsnmp_arch_interface_init -- called once at agent startup.
 *
 * We defer the VAPI connection to the first container_load() call.
 * Connecting here would establish a VPP SHM session that times out during
 * the lengthy MIB-loading phase (VPP keepalives go unprocessed).
 */
void
netsnmp_arch_interface_init(void)
{
    DEBUGMSGTL(("access:interface:vpp", "init (connection deferred)\n"));
}

/**
 * netsnmp_arch_interface_container_load -- populate *container* with one
 * netsnmp_interface_entry per VPP interface.
 *
 * Called periodically by the generic interface cache handler.
 *
 * @param container   Pre-allocated container; caller owns it.
 * @param load_flags  Bitmask of NETSNMP_ACCESS_INTERFACE_LOAD_* flags.
 *
 * @return  0 on success, -1 on fatal error, -2 on VPP not available.
 */
int
netsnmp_arch_interface_container_load(netsnmp_container *container,
                                      u_int load_flags)
{
    dump_cb_ctx_t dctx = {container, 0, 0, false};
    vapi_msg_sw_interface_dump *msg;
    vapi_error_e rv;
    vpp_if_counters_t *counters = NULL;
    netsnmp_iterator *it;
    netsnmp_interface_entry *entry;

    DEBUGMSGTL(("access:interface:vpp:container", "load (flags %x)\n",
                load_flags));


    if (container == NULL) {
        snmp_log(LOG_ERR, "interface_vpp: no container specified\n");
        return -1;
    }

    /* Reconnect if a previous failure disconnected us. */
    if (vapi_connect_once() != 0) {
        snmp_log(LOG_ERR,
                 "interface_vpp: VPP not available -- "
                 "returning empty interface table\n");
        return -2;
    }

    /* --- Phase 1: enumerate interfaces via sw_interface_dump ----------- */


    msg = vapi_alloc_sw_interface_dump(g_vapi_ctx, 0);
    if (!msg) {
        snmp_log(LOG_ERR, "interface_vpp: vapi_alloc_sw_interface_dump failed\n");
        return -2;
    }

    msg->payload.sw_if_index     = ~0u; /* dump all interfaces */
    msg->payload.name_filter_valid = false;


    rv = vapi_sw_interface_dump(g_vapi_ctx, msg, _sw_interface_details_cb,
                                &dctx);

    /*
     * In non-blocking mode the dump only sends the request; drive the
     * dispatch loop (bounded by VPP_VAPI_REQUEST_TIMEOUT_S) to collect the
     * replies.  A send error or a dispatch timeout means the VAPI connection
     * is unusable -- drop it so the next poll reconnects.
     *
     * A send failure leaves msg caller-owned (the generated wrapper returns
     * the error before vapi_send consumes it), so free it before resetting.
     * After a successful send the message is owned by VPP; a dispatch timeout
     * therefore resets without touching msg.
     */
    if (rv != VAPI_OK) {
        snmp_log(LOG_ERR, "interface_vpp: vapi_sw_interface_dump failed (%d)\n",
                 rv);
        vapi_msg_free(g_vapi_ctx, msg);
        vapi_reset_connection();
        return -2;
    }
    if (vapi_dump_dispatch(&dctx.done) != 0) {
        snmp_log(LOG_ERR, "interface_vpp: vapi_sw_interface_dump dispatch timeout\n");
        vapi_reset_connection();
        return -2;
    }

    if (dctx.error) {
        snmp_log(LOG_ERR,
                 "interface_vpp: errors during sw_interface_dump\n");
        /* Container may be partially populated; that is still useful. */
    }


    if (dctx.max_sw_if_index == 0)
        return 0; /* no interfaces -- that is valid */

    /* --- Phase 2: read counters from the stats segment ----------------- */

    counters = calloc(dctx.max_sw_if_index + 1, sizeof(*counters));
    if (!counters) {
        snmp_log(LOG_ERR, "interface_vpp: out of memory for counters\n");
        return 0; /* non-fatal: report interface table without counters */
    }

    if (vpp_stats_read_counters(dctx.max_sw_if_index, counters) < 0) {
        DEBUGMSGTL(("access:interface:vpp",
                    "stats segment not available; counters will be zero\n"));
    }

    /* --- Phase 3: attach counters to each entry in the container ------- */

    it = CONTAINER_ITERATOR(container);
    if (!it) {
        free(counters);
        return 0;
    }

    for (entry = ITERATOR_FIRST(it); entry; entry = ITERATOR_NEXT(it)) {
        uint32_t sw_if = (uint32_t)(entry->index - 1);
        const vpp_if_counters_t *c;

        if (sw_if > dctx.max_sw_if_index)
            continue;

        c = &counters[sw_if];

        /* ibytes / obytes (64-bit split into high:low halves) */
        entry->stats.ibytes.low  = c->rx_bytes   & 0xffffffff;
        entry->stats.ibytes.high = c->rx_bytes   >> 32;
        entry->stats.obytes.low  = c->tx_bytes   & 0xffffffff;
        entry->stats.obytes.high = c->tx_bytes   >> 32;

        /*
         * iall holds all inbound packets.  The table code derives iucast by
         * subtracting imcast (which we leave at 0) because CALCULATE_UCAST
         * is set.
         */
        entry->stats.iall.low  = c->rx_packets & 0xffffffff;
        entry->stats.iall.high = c->rx_packets >> 32;
        entry->stats.oucast.low  = c->tx_packets & 0xffffffff;
        entry->stats.oucast.high = c->tx_packets >> 32;

        /*
         * Error and discard counters (32-bit in the struct).
         *
         * VPP exposes /if/rx-error, /if/tx-error and /if/drops (an inbound
         * drop counter), but has no per-interface outbound-discard counter.
         * tx_drops therefore remains 0 and odiscards is reported as 0 rather
         * than fabricated.
         */
        entry->stats.ierrors   = (unsigned int)(c->rx_errors > 0xffffffff
                                                    ? 0xffffffff : c->rx_errors);
        entry->stats.oerrors   = (unsigned int)(c->tx_errors > 0xffffffff
                                                    ? 0xffffffff : c->tx_errors);
        entry->stats.idiscards = (unsigned int)(c->rx_drops  > 0xffffffff
                                                    ? 0xffffffff : c->rx_drops);
        entry->stats.odiscards = (unsigned int)(c->tx_drops  > 0xffffffff
                                                    ? 0xffffffff : c->tx_drops);
    }

    ITERATOR_RELEASE(it);
    free(counters);
    return 0;
}

/**
 * netsnmp_arch_interface_index_find -- look up ifIndex by name.
 *
 * On this appliance the ifIndex IS the VPP sw_if_index.  We obtain it via
 * a targeted sw_interface_dump with a name filter.
 *
 * @return  ifIndex (> 0) on success, 0 if not found.
 */

/* State for the single-interface name lookup callback. */
typedef struct {
    const char   *target_name;
    oid           found_index;
    volatile bool done;   /* set when end-of-dump sentinel received */
} index_find_ctx_t;

static vapi_error_e
_index_find_cb(vapi_ctx_t ctx __attribute__((unused)),
               void *caller_ctx,
               vapi_error_e rv,
               bool is_last,
               vapi_payload_sw_interface_details *details)
{
    index_find_ctx_t *fctx = (index_find_ctx_t *)caller_ctx;

    if (rv != VAPI_OK || (is_last && !details)) {
        fctx->done = true;
        return VAPI_OK;
    }
    if (!details)
        return VAPI_OK;

    {
        char name[VPP_IF_NAME_MAX + 1];
        memset(name, 0, sizeof(name));
        memcpy(name, details->interface_name,
               sizeof(details->interface_name) < VPP_IF_NAME_MAX
                   ? sizeof(details->interface_name) : VPP_IF_NAME_MAX);

        if (strcmp(name, fctx->target_name) == 0)
            fctx->found_index = (oid)(details->sw_if_index + 1);
    }
    return VAPI_OK;
}

oid
netsnmp_arch_interface_index_find(const char *name)
{
    index_find_ctx_t fctx = {name, 0, false};
    vapi_msg_sw_interface_dump *msg;
    size_t name_len;
    vapi_error_e rv;

    if (!name || *name == '\0')
        return 0;

    if (vapi_connect_once() != 0)
        return 0;

    name_len = strlen(name);

    msg = vapi_alloc_sw_interface_dump(g_vapi_ctx, name_len);
    if (!msg)
        return 0;

    msg->payload.sw_if_index       = ~0u;
    msg->payload.name_filter_valid  = true;
    vl_api_c_string_to_api_string(name, &msg->payload.name_filter);

    rv = vapi_sw_interface_dump(g_vapi_ctx, msg, _index_find_cb, &fctx);
    if (rv != VAPI_OK) {
        snmp_log(LOG_ERR,
                 "interface_vpp: index_find vapi_sw_interface_dump failed (%d)\n",
                 rv);
        vapi_msg_free(g_vapi_ctx, msg);
        vapi_reset_connection();
        return 0;
    }
    if (vapi_dump_dispatch(&fctx.done) != 0) {
        snmp_log(LOG_ERR,
                 "interface_vpp: index_find dispatch timeout\n");
        vapi_reset_connection();
        return 0;
    }

    return fctx.found_index;
}

/**
 * netsnmp_arch_set_admin_status -- set ifAdminStatus via VPP VAPI.
 *
 * Sends sw_interface_set_flags to raise or lower admin-up.
 */

typedef struct {
    int           retval;
    volatile bool done;   /* set when the single reply is received */
} set_flags_cb_ctx_t;

static vapi_error_e
_set_flags_reply_cb(vapi_ctx_t ctx __attribute__((unused)),
                    void *caller_ctx,
                    vapi_error_e rv,
                    bool is_last __attribute__((unused)),
                    vapi_payload_sw_interface_set_flags_reply *reply)
{
    set_flags_cb_ctx_t *sctx = (set_flags_cb_ctx_t *)caller_ctx;

    sctx->done = true;
    if (rv != VAPI_OK) {
        sctx->retval = -1;
        return rv;
    }
    sctx->retval = reply->retval;
    return VAPI_OK;
}

#ifndef NETSNMP_FEATURE_REMOVE_INTERFACE_ARCH_SET_ADMIN_STATUS
int
netsnmp_arch_set_admin_status(netsnmp_interface_entry *entry,
                              int ifAdminStatus_val)
{
    set_flags_cb_ctx_t sctx = {0, false};
    vapi_msg_sw_interface_set_flags *msg;
    vapi_error_e rv;
    bool admin_up;

    DEBUGMSGTL(("access:interface:vpp",
                "set_admin_status sw_if=%u status=%d\n",
                (unsigned)entry->index, ifAdminStatus_val));

    if (vapi_connect_once() != 0)
        return -1;

    admin_up = (ifAdminStatus_val == IFADMINSTATUS_UP);

    msg = vapi_alloc_sw_interface_set_flags(g_vapi_ctx);
    if (!msg) {
        snmp_log(LOG_ERR,
                 "interface_vpp: vapi_alloc_sw_interface_set_flags failed\n");
        return -1;
    }

    msg->payload.sw_if_index = (uint32_t)(entry->index - 1);
    msg->payload.flags = admin_up
                             ? IF_STATUS_API_FLAG_ADMIN_UP
                             : (vapi_enum_if_status_flags)0;

    rv = vapi_sw_interface_set_flags(g_vapi_ctx, msg, _set_flags_reply_cb,
                                     &sctx);
    if (rv != VAPI_OK) {
        snmp_log(LOG_ERR,
                 "interface_vpp: sw_interface_set_flags VAPI error (%d)\n", rv);
        vapi_msg_free(g_vapi_ctx, msg);
        vapi_reset_connection();
        return -1;
    }
    if (vapi_dump_dispatch(&sctx.done) != 0) {
        snmp_log(LOG_ERR,
                 "interface_vpp: sw_interface_set_flags dispatch timeout\n");
        vapi_reset_connection();
        return -1;
    }

    if (sctx.retval != 0) {
        snmp_log(LOG_ERR,
                 "interface_vpp: sw_interface_set_flags VPP error (%d)\n",
                 sctx.retval);
        return -1;
    }

    return 0;
}
#endif /* NETSNMP_FEATURE_REMOVE_INTERFACE_ARCH_SET_ADMIN_STATUS */

/**
 * netsnmp_arch_set_ifalias -- set interface alias string.
 *
 * Pushes the alias to VPP via sw_interface_tag_add_del.
 * The VPP tag field is the canonical source for interface descriptions;
 * reads are served from sw_interface_details.tag (see _sw_interface_details_cb).
 */

typedef struct {
    int           retval;
    volatile bool done;
} tag_add_del_cb_ctx_t;

static vapi_error_e
_tag_add_del_reply_cb(vapi_ctx_t ctx __attribute__((unused)),
                      void *caller_ctx,
                      vapi_error_e rv,
                      bool is_last __attribute__((unused)),
                      vapi_payload_sw_interface_tag_add_del_reply *reply)
{
    tag_add_del_cb_ctx_t *tc = (tag_add_del_cb_ctx_t *)caller_ctx;

    tc->done = true;
    if (rv != VAPI_OK) {
        tc->retval = -1;
        return rv;
    }
    tc->retval = reply->retval;
    return VAPI_OK;
}

int
netsnmp_arch_set_ifalias(netsnmp_interface_entry *entry,
                         const char *alias, size_t alias_len)
{
    tag_add_del_cb_ctx_t tctx = {0, false};
    vapi_msg_sw_interface_tag_add_del *msg;
    vapi_error_e rv;

    if (!entry || !entry->name)
        return -1;

    if (vapi_connect_once() != 0)
        return -1;

    msg = vapi_alloc_sw_interface_tag_add_del(g_vapi_ctx);
    if (!msg) {
        DEBUGMSGTL(("access:interface:vpp",
                    "set_ifalias: vapi_alloc_sw_interface_tag_add_del "
                    "failed\n"));
        return -1;
    }

    msg->payload.is_add       = (alias_len > 0);
    msg->payload.sw_if_index  = (uint32_t)(entry->index - 1);
    if (alias_len > 0)
        memcpy(msg->payload.tag, alias,
               alias_len < sizeof(msg->payload.tag)
                   ? alias_len
                   : sizeof(msg->payload.tag) - 1);

    rv = vapi_sw_interface_tag_add_del(g_vapi_ctx, msg,
                                       _tag_add_del_reply_cb, &tctx);
    if (rv != VAPI_OK) {
        DEBUGMSGTL(("access:interface:vpp",
                    "set_ifalias: sw_interface_tag_add_del send error "
                    "(rv=%d)\n", rv));
        vapi_msg_free(g_vapi_ctx, msg);
        vapi_reset_connection();
        return -1;
    }
    if (vapi_dump_dispatch(&tctx.done) != 0 || tctx.retval != 0) {
        DEBUGMSGTL(("access:interface:vpp",
                    "set_ifalias: sw_interface_tag_add_del error "
                    "(retval=%d)\n", tctx.retval));
        vapi_reset_connection();
        return -1;
    }

    return 0;
}
