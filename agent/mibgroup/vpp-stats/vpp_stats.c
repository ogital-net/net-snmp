/*
 * vpp_stats.c -- VPP dataplane health statistics via SNMP.
 *
 * Exposes ARP/ND counters and VPP memory/buffer stats as scalars under
 * netSnmpExperimental.9696 (1.3.6.1.4.1.8072.9999.9696):
 *
 *   .1  vppArpStats
 *       .1.0  vppArpRxRequests     Counter64
 *       .2.0  vppArpRxReplies      Counter64
 *       .3.0  vppArpRxGratuitous   Counter64
 *       .4.0  vppArpTxRequests     Counter64
 *       .5.0  vppArpTxReplies      Counter64
 *       .6.0  vppArpTxGratuitous   Counter64
 *       .7.0  vppNdRxRequests      Counter64
 *       .8.0  vppNdRxReplies       Counter64
 *       .9.0  vppNdRxGratuitous    Counter64
 *       .10.0 vppNdTxRequests      Counter64
 *       .11.0 vppNdTxReplies       Counter64
 *       .12.0 vppNdTxGratuitous    Counter64
 *
 *   .2  vppMemory
 *       .1.0  vppMainHeapTotal     Gauge32 (KB)
 *       .2.0  vppMainHeapUsed      Gauge32 (KB)
 *       .3.0  vppMainHeapFree      Gauge32 (KB)
 *       .4.0  vppBufferPoolAvail   Gauge32 (buffers)
 *       .5.0  vppBufferPoolUsed    Gauge32 (buffers)
 *       .6.0  vppBufferPoolCached  Gauge32 (buffers)
 *
 * These do NOT replace or hide any existing host-resources data.
 */

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>

/* Shared VPP helpers */
#include "if-mib/data_access/interface_vpp.h"

#include "vpp_stats.h"

/*
 * Base OID: netSnmpExperimental.9696
 * netSnmpExperimental = 1.3.6.1.4.1.8072.9999
 */
static const oid vppArpStats_oid[]  = {1,3,6,1,4,1,8072,9999,9696,1};
static const oid vppMemory_oid[]    = {1,3,6,1,4,1,8072,9999,9696,2};

#define OID_LEN_ARP  (sizeof(vppArpStats_oid) / sizeof(oid))
#define OID_LEN_MEM  (sizeof(vppMemory_oid)   / sizeof(oid))

/*
 * Stats segment reader helpers
 *
 * All VPP-DATAPLANE-MIB scalars are read from the stats segment in a single
 * dump per collection (one for the /net ARP/ND subtree, one for the
 * /mem + /buffer-pools subtrees), matched by entry name.  A short TTL cache
 * serves a GETNEXT walk from one dump per collection per window.
 */

/* Aggregate one dumped stat entry across all workers (and indices). */
static uint64_t
_entry_value(const stat_segment_data_t *e)
{
    uint64_t val = 0;
    int nw, w, nc, c;

    if (!e)
        return 0;

    switch (e->type) {
    case STAT_DIR_TYPE_SCALAR_INDEX:
    case STAT_DIR_TYPE_GAUGE:
        val = (uint64_t)e->scalar_value;
        break;
    case STAT_DIR_TYPE_COUNTER_VECTOR_SIMPLE:
        if (e->simple_counter_vec) {
            nw = stat_segment_vec_len(e->simple_counter_vec);
            for (w = 0; w < nw; w++) {
                nc = stat_segment_vec_len(e->simple_counter_vec[w]);
                for (c = 0; c < nc; c++)
                    val += e->simple_counter_vec[w][c];
            }
        }
        break;
    default:
        break;
    }
    return val;
}

/* Aggregate one dumped per-worker memory entry (index 0 of each worker). */
static uint64_t
_entry_mem_value(const stat_segment_data_t *e)
{
    uint64_t total = 0;
    int nw, w;

    if (!e || e->type != STAT_DIR_TYPE_COUNTER_VECTOR_SIMPLE ||
        !e->simple_counter_vec)
        return 0;

    nw = stat_segment_vec_len(e->simple_counter_vec);
    for (w = 0; w < nw; w++) {
        if (stat_segment_vec_len(e->simple_counter_vec[w]) > 0)
            total += e->simple_counter_vec[w][0];
    }
    return total;
}

/*
 * ARP/ND statistics
 */

/* Stats paths for ARP/ND (leaf index -> path) */
static const char *arp_paths[] = {
    NULL,                          /* 0 unused */
    "/net/arp/rx/requests",        /* 1 */
    "/net/arp/rx/replies",         /* 2 */
    "/net/arp/rx/gratuitous",      /* 3 */
    "/net/arp/tx/requests",        /* 4 */
    "/net/arp/tx/replies",         /* 5 */
    "/net/arp/tx/gratuitous",      /* 6 */
    "/net/ip6-nd/rx/requests",     /* 7 */
    "/net/ip6-nd/rx/replies",      /* 8 */
    "/net/ip6-nd/rx/gratuitous",   /* 9 */
    "/net/ip6-nd/tx/requests",     /* 10 */
    "/net/ip6-nd/tx/replies",      /* 11 */
    "/net/ip6-nd/tx/gratuitous",   /* 12 */
};
#define ARP_NUM_LEAVES 12

/*
 * Snapshot of all ARP/ND counters, filled by one dump of the /net subtree.
 */
typedef struct {
    uint64_t leaf[ARP_NUM_LEAVES + 1]; /* 1..12 */
} vpp_arp_snapshot_t;

static void
_arp_collect_cb(const char *name, const stat_segment_data_t *entry, void *ctx)
{
    vpp_arp_snapshot_t *snap = ctx;
    int leaf;

    for (leaf = 1; leaf <= ARP_NUM_LEAVES; leaf++) {
        if (arp_paths[leaf] && strcmp(name, arp_paths[leaf]) == 0) {
            snap->leaf[leaf] = _entry_value(entry);
            return;
        }
    }
}

/*
 * Memory/buffer snapshot, filled by one dump of /mem and one of
 * /buffer-pools.
 */
typedef struct {
    uint64_t heap_total, heap_used, heap_free;      /* bytes */
    uint64_t buf_available, buf_used, buf_cached;   /* buffers */
} vpp_mem_snapshot_t;

static void
_mem_collect_cb(const char *name, const stat_segment_data_t *entry, void *ctx)
{
    vpp_mem_snapshot_t *snap = ctx;

    if (strcmp(name, "/mem/main heap/total") == 0)
        snap->heap_total = _entry_mem_value(entry);
    else if (strcmp(name, "/mem/main heap/used") == 0)
        snap->heap_used = _entry_mem_value(entry);
    else if (strcmp(name, "/mem/main heap/free") == 0)
        snap->heap_free = _entry_mem_value(entry);
}

static void
_bufpool_collect_cb(const char *name, const stat_segment_data_t *entry,
                    void *ctx)
{
    vpp_mem_snapshot_t *snap = ctx;

    if (strcmp(name, "/buffer-pools/default-numa-0/available") == 0)
        snap->buf_available = _entry_value(entry);
    else if (strcmp(name, "/buffer-pools/default-numa-0/used") == 0)
        snap->buf_used = _entry_value(entry);
    else if (strcmp(name, "/buffer-pools/default-numa-0/cached") == 0)
        snap->buf_cached = _entry_value(entry);
}

/*
 * TTL cache (5 s, matching net-snmp's scalar stats cache cadence), so a
 * GETNEXT walk is served from one snapshot per collection per window.
 */
#define VPP_STATS_CACHE_TTL_S 5

static vpp_arp_snapshot_t  g_arp_snap;
static time_t              g_arp_snap_at = 0;
static vpp_mem_snapshot_t  g_mem_snap;
static time_t              g_mem_snap_at = 0;

static const vpp_arp_snapshot_t *
_get_arp_snapshot(void)
{
    time_t now = time(NULL);

    if (now - g_arp_snap_at >= VPP_STATS_CACHE_TTL_S) {
        vpp_arp_snapshot_t fresh;
        memset(&fresh, 0, sizeof(fresh));
        if (vpp_stats_dump_foreach("/net/", _arp_collect_cb, &fresh) == 0) {
            g_arp_snap = fresh;
            g_arp_snap_at = now;
        }
    }
    return &g_arp_snap;
}

static const vpp_mem_snapshot_t *
_get_mem_snapshot(void)
{
    time_t now = time(NULL);

    if (now - g_mem_snap_at >= VPP_STATS_CACHE_TTL_S) {
        vpp_mem_snapshot_t fresh;
        memset(&fresh, 0, sizeof(fresh));
        if (vpp_stats_dump_foreach("/mem/", _mem_collect_cb, &fresh) == 0 &&
            vpp_stats_dump_foreach("/buffer-pools/", _bufpool_collect_cb,
                                   &fresh) == 0) {
            g_mem_snap = fresh;
            g_mem_snap_at = now;
        }
    }
    return &g_mem_snap;
}

static int
handle_vppArpStats(netsnmp_mib_handler *handler,
                   netsnmp_handler_registration *reginfo,
                   netsnmp_agent_request_info *reqinfo,
                   netsnmp_request_info *requests)
{
    netsnmp_request_info *req;
    const vpp_arp_snapshot_t *snap;
    (void)handler;
    (void)reginfo;

    if (reqinfo->mode != MODE_GET)
        return SNMP_ERR_NOERROR;

    snap = _get_arp_snapshot();

    for (req = requests; req; req = req->next) {
        oid *name;
        size_t name_len;
        int leaf;
        struct counter64 c64;
        uint64_t val;

        if (req->processed)
            continue;

        name = req->requestvb->name;
        name_len = req->requestvb->name_length;

        /* OID: ...9696.1.<leaf>.0  — leaf is at name[OID_LEN_ARP] */
        if (name_len < OID_LEN_ARP + 2)
            continue;
        leaf = (int)name[OID_LEN_ARP];

        if (leaf < 1 || leaf > ARP_NUM_LEAVES) {
            netsnmp_set_request_error(reqinfo, req, SNMP_NOSUCHOBJECT);
            continue;
        }
        val = snap->leaf[leaf];
        c64.high = (uint32_t)(val >> 32);
        c64.low  = (uint32_t)(val & 0xFFFFFFFF);
        snmp_set_var_typed_value(req->requestvb, ASN_COUNTER64,
                                (const u_char *)&c64, sizeof(c64));
    }
    return SNMP_ERR_NOERROR;
}

/*
 * VPP Memory / Buffer Pool
 */

static int
handle_vppMemory(netsnmp_mib_handler *handler,
                 netsnmp_handler_registration *reginfo,
                 netsnmp_agent_request_info *reqinfo,
                 netsnmp_request_info *requests)
{
    netsnmp_request_info *req;
    const vpp_mem_snapshot_t *snap;
    (void)handler;
    (void)reginfo;

    if (reqinfo->mode != MODE_GET)
        return SNMP_ERR_NOERROR;

    snap = _get_mem_snapshot();

    for (req = requests; req; req = req->next) {
        oid *name;
        size_t name_len;
        int leaf;
        uint32_t val32;

        if (req->processed)
            continue;

        name = req->requestvb->name;
        name_len = req->requestvb->name_length;

        /* OID: ...9696.2.<leaf>.0  — leaf is at name[OID_LEN_MEM] */
        if (name_len < OID_LEN_MEM + 2)
            continue;
        leaf = (int)name[OID_LEN_MEM];

        switch (leaf) {
        case 1: /* vppMainHeapTotal (KB) */
            val32 = (uint32_t)(snap->heap_total / 1024);
            break;
        case 2: /* vppMainHeapUsed (KB) */
            val32 = (uint32_t)(snap->heap_used / 1024);
            break;
        case 3: /* vppMainHeapFree (KB) */
            val32 = (uint32_t)(snap->heap_free / 1024);
            break;
        case 4: /* vppBufferPoolAvailable */
            val32 = (uint32_t)snap->buf_available;
            break;
        case 5: /* vppBufferPoolUsed */
            val32 = (uint32_t)snap->buf_used;
            break;
        case 6: /* vppBufferPoolCached */
            val32 = (uint32_t)snap->buf_cached;
            break;
        default:
            netsnmp_set_request_error(reqinfo, req, SNMP_NOSUCHOBJECT);
            continue;
        }
        snmp_set_var_typed_value(req->requestvb, ASN_GAUGE,
                                (const u_char *)&val32, sizeof(val32));
    }
    return SNMP_ERR_NOERROR;
}

/*
 * Registration
 */

void
init_vpp_stats(void)
{
    netsnmp_handler_registration *reg;
    oid arp_oid[MAX_OID_LEN];
    oid mem_oid[MAX_OID_LEN];
    size_t arp_len, mem_len;
    int leaf;

    DEBUGMSGTL(("vpp_stats", "Initializing VPP dataplane stats\n"));

    /* Register each ARP/ND scalar individually so GETNEXT works */
    for (leaf = 1; leaf <= ARP_NUM_LEAVES; leaf++) {
        arp_len = OID_LEN_ARP;
        memcpy(arp_oid, vppArpStats_oid, OID_LEN_ARP * sizeof(oid));
        arp_oid[arp_len++] = leaf;

        reg = netsnmp_create_handler_registration(
            "vppArpStats", handle_vppArpStats,
            arp_oid, arp_len, HANDLER_CAN_RONLY);
        if (reg)
            netsnmp_register_scalar(reg);
    }

    /* Register each memory scalar individually */
    for (leaf = 1; leaf <= 6; leaf++) {
        mem_len = OID_LEN_MEM;
        memcpy(mem_oid, vppMemory_oid, OID_LEN_MEM * sizeof(oid));
        mem_oid[mem_len++] = leaf;

        reg = netsnmp_create_handler_registration(
            "vppMemory", handle_vppMemory,
            mem_oid, mem_len, HANDLER_CAN_RONLY);
        if (reg)
            netsnmp_register_scalar(reg);
    }

    DEBUGMSGTL(("vpp_stats", "Registered %d ARP/ND + 6 memory scalars\n",
                ARP_NUM_LEAVES));
}
