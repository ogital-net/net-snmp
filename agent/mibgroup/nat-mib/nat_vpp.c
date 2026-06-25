/*
 * nat_vpp.c -- VPP-backed NAT session/protocol statistics.
 *
 * Implements a subset of NATV2-MIB (RFC 7659) using VPP stats segment:
 *   - natv2GlobalStats scalars (sessions, translations, drops)
 *   - natv2ProtocolStatsTable (per-protocol counters)
 *
 * OID tree (mib-2.234 = natv2MIB):
 *   .1.3.6.1.2.1.234.1.6   natv2ProtocolStatsTable
 *   .1.3.6.1.2.1.234.1.10  natv2GlobalStats
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

#include "nat_vpp.h"

/*
 * VPP stats segment helpers
 */

/*
 * NAT counter aggregation
 */

/* Protocol indices matching IANA protocol numbers */
#define NAT_PROTO_ICMP   1
#define NAT_PROTO_TCP    6
#define NAT_PROTO_UDP   17
#define NAT_PROTO_OTHER 255

typedef struct {
    uint64_t in_translates;
    uint64_t out_translates;
    uint64_t drops;
} nat_proto_stats_t;

typedef struct {
    uint64_t active_sessions;
    uint64_t max_sessions;
    uint64_t total_in;
    uint64_t total_out;
    uint64_t total_drops;
    nat_proto_stats_t tcp;
    nat_proto_stats_t udp;
    nat_proto_stats_t icmp;
    nat_proto_stats_t other;
} nat_global_stats_t;

/*
 * Extract the aggregate value of one dumped stat entry (sum across workers
 * and indices).  Mirrors the switch in _read_stat_value() but operates on an
 * already-dumped entry, so a whole group can be read from a single dump.
 */
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

/*
 * Collect all NAT44-ED stats in a single stats-segment dump of the
 * /nat44-ed subtree, matched by entry name.
 */
static void
_collect_nat_stats(nat_global_stats_t *s)
{
    uint8_t **patterns = NULL;
    uint32_t *dir;
    stat_segment_data_t *res;
    uint32_t n, i;

    memset(s, 0, sizeof(*s));

    if (vpp_stats_connect_once() != 0)
        return;

    patterns = stat_segment_string_vector(patterns, "/nat44-ed/");
    dir = stat_segment_ls(patterns);
    vpp_stats_free_patterns(patterns);

    if (!dir)
        return;
    if (stat_segment_vec_len(dir) == 0) {
        stat_segment_vec_free(dir);
        return;
    }

    res = stat_segment_dump(dir);
    stat_segment_vec_free(dir);
    if (!res)
        return;

    n = stat_segment_vec_len(res);
    for (i = 0; i < n; i++) {
        const char *nm = res[i].name;
        uint64_t v;

        if (!nm)
            continue;
        v = _entry_value(&res[i]);

        if (strcmp(nm, "/nat44-ed/total-sessions") == 0)
            s->active_sessions = v;
        else if (strcmp(nm, "/nat44-ed/max-cfg-sessions") == 0)
            s->max_sessions = v;
        /* in2out */
        else if (strcmp(nm, "/nat44-ed/in2out/fastpath/tcp") == 0)
            s->tcp.in_translates += v;
        else if (strcmp(nm, "/nat44-ed/in2out/slowpath/tcp") == 0)
            s->tcp.in_translates += v;
        else if (strcmp(nm, "/nat44-ed/in2out/fastpath/udp") == 0)
            s->udp.in_translates += v;
        else if (strcmp(nm, "/nat44-ed/in2out/slowpath/udp") == 0)
            s->udp.in_translates += v;
        else if (strcmp(nm, "/nat44-ed/in2out/fastpath/icmp") == 0)
            s->icmp.in_translates += v;
        else if (strcmp(nm, "/nat44-ed/in2out/slowpath/icmp") == 0)
            s->icmp.in_translates += v;
        else if (strcmp(nm, "/nat44-ed/in2out/fastpath/other") == 0)
            s->other.in_translates += v;
        else if (strcmp(nm, "/nat44-ed/in2out/slowpath/other") == 0)
            s->other.in_translates += v;
        /* out2in */
        else if (strcmp(nm, "/nat44-ed/out2in/fastpath/tcp") == 0)
            s->tcp.out_translates += v;
        else if (strcmp(nm, "/nat44-ed/out2in/slowpath/tcp") == 0)
            s->tcp.out_translates += v;
        else if (strcmp(nm, "/nat44-ed/out2in/fastpath/udp") == 0)
            s->udp.out_translates += v;
        else if (strcmp(nm, "/nat44-ed/out2in/slowpath/udp") == 0)
            s->udp.out_translates += v;
        else if (strcmp(nm, "/nat44-ed/out2in/fastpath/icmp") == 0)
            s->icmp.out_translates += v;
        else if (strcmp(nm, "/nat44-ed/out2in/slowpath/icmp") == 0)
            s->icmp.out_translates += v;
        else if (strcmp(nm, "/nat44-ed/out2in/fastpath/other") == 0)
            s->other.out_translates += v;
        else if (strcmp(nm, "/nat44-ed/out2in/slowpath/other") == 0)
            s->other.out_translates += v;
        /* drops (VPP does not split drops by protocol) */
        else if (strcmp(nm, "/nat44-ed/in2out/fastpath/drops") == 0)
            s->total_drops += v;
        else if (strcmp(nm, "/nat44-ed/in2out/slowpath/drops") == 0)
            s->total_drops += v;
        else if (strcmp(nm, "/nat44-ed/out2in/fastpath/drops") == 0)
            s->total_drops += v;
        else if (strcmp(nm, "/nat44-ed/out2in/slowpath/drops") == 0)
            s->total_drops += v;
    }

    stat_segment_data_free(res);

    /* Totals */
    s->total_in  = s->tcp.in_translates + s->udp.in_translates
                 + s->icmp.in_translates + s->other.in_translates;
    s->total_out = s->tcp.out_translates + s->udp.out_translates
                 + s->icmp.out_translates + s->other.out_translates;
}

/*
 * TTL cache around the collection (5 s, matching net-snmp's scalar stats
 * cache cadence), so a GETNEXT walk is served from one dump per window.
 */
#define NAT_STATS_CACHE_TTL_S 5

static nat_global_stats_t g_nat_snap;
static time_t             g_nat_snap_at = 0;

static const nat_global_stats_t *
_get_nat_stats(void)
{
    time_t now = time(NULL);

    if (now - g_nat_snap_at >= NAT_STATS_CACHE_TTL_S) {
        nat_global_stats_t fresh;
        _collect_nat_stats(&fresh);
        g_nat_snap = fresh;
        g_nat_snap_at = now;
    }
    return &g_nat_snap;
}

/*
 * SNMP OID definitions
 *
 * natv2MIB          = 1.3.6.1.2.1.234
 * natv2MIBObjects   = natv2MIB.1
 * natv2ProtocolStatsTable = natv2MIBObjects.6
 * natv2GlobalStats  = natv2MIBObjects.10
 */

/* natv2GlobalStats scalars: .1.3.6.1.2.1.234.1.10.x */
#define NATV2_GLOBAL_ACTIVE_SESSIONS  1
#define NATV2_GLOBAL_MAX_SESSIONS     2
#define NATV2_GLOBAL_IN_TRANSLATES    3
#define NATV2_GLOBAL_OUT_TRANSLATES   4
#define NATV2_GLOBAL_DROPS            5

static oid natv2GlobalActiveSessions_oid[] = {1,3,6,1,2,1,234,1,10,1};
static oid natv2GlobalMaxSessions_oid[]    = {1,3,6,1,2,1,234,1,10,2};
static oid natv2GlobalInTranslates_oid[]   = {1,3,6,1,2,1,234,1,10,3};
static oid natv2GlobalOutTranslates_oid[]  = {1,3,6,1,2,1,234,1,10,4};
static oid natv2GlobalDrops_oid[]          = {1,3,6,1,2,1,234,1,10,5};

/* natv2ProtocolStatsTable: .1.3.6.1.2.1.234.1.6 */
static oid natv2ProtocolStatsTable_oid[] = {1,3,6,1,2,1,234,1,6};

/* Column OIDs for the protocol stats table */
#define COL_NATV2_PROTO_IN_TRANSLATES  2
#define COL_NATV2_PROTO_OUT_TRANSLATES 3
#define COL_NATV2_PROTO_DISCARDS       4

/*
 * Scalar handlers
 */

static int
handle_natv2Scalar(netsnmp_mib_handler *handler,
                   netsnmp_handler_registration *reginfo,
                   netsnmp_agent_request_info *reqinfo,
                   netsnmp_request_info *requests)
{
    const nat_global_stats_t *snap;
    oid *req_oid;
    size_t req_oid_len;
    int leaf;
    uint32_t gauge_val;
    struct counter64 c64;

    if (reqinfo->mode != MODE_GET)
        return SNMP_ERR_NOERROR;

    snap = _get_nat_stats();

    /*
     * Determine which scalar was requested from the registered OID.
     *
     * netsnmp_register_scalar() registers at the object OID
     * (...234.1.10.<leaf>) and the scalar helper appends the ".0" instance
     * sub-id, so reginfo->rootoid is "...234.1.10.<leaf>.0".  The column
     * leaf is therefore the second-to-last sub-identifier.
     */
    req_oid = reginfo->rootoid;
    req_oid_len = reginfo->rootoid_len;
    if (req_oid_len < 2)
        return SNMP_ERR_GENERR;
    leaf = req_oid[req_oid_len - 2];

    switch (leaf) {
    case NATV2_GLOBAL_ACTIVE_SESSIONS:
        gauge_val = (uint32_t)snap->active_sessions;
        snmp_set_var_typed_value(requests->requestvb, ASN_GAUGE,
                                &gauge_val, sizeof(gauge_val));
        break;
    case NATV2_GLOBAL_MAX_SESSIONS:
        gauge_val = (uint32_t)snap->max_sessions;
        snmp_set_var_typed_value(requests->requestvb, ASN_GAUGE,
                                &gauge_val, sizeof(gauge_val));
        break;
    case NATV2_GLOBAL_IN_TRANSLATES:
        c64.low  = snap->total_in & 0xffffffff;
        c64.high = snap->total_in >> 32;
        snmp_set_var_typed_value(requests->requestvb, ASN_COUNTER64,
                                &c64, sizeof(c64));
        break;
    case NATV2_GLOBAL_OUT_TRANSLATES:
        c64.low  = snap->total_out & 0xffffffff;
        c64.high = snap->total_out >> 32;
        snmp_set_var_typed_value(requests->requestvb, ASN_COUNTER64,
                                &c64, sizeof(c64));
        break;
    case NATV2_GLOBAL_DROPS:
        c64.low  = snap->total_drops & 0xffffffff;
        c64.high = snap->total_drops >> 32;
        snmp_set_var_typed_value(requests->requestvb, ASN_COUNTER64,
                                &c64, sizeof(c64));
        break;
    default:
        return SNMP_ERR_NOSUCHNAME;
    }

    return SNMP_ERR_NOERROR;
}

/*
 * Protocol Stats Table handler
 *
 * Table structure:
 *   natv2ProtocolStatsEntry = natv2ProtocolStatsTable.1
 *   INDEX { natv2ProtocolStatsProtocol }  -- INTEGER (IANA protocol number)
 *   natv2ProtocolStatsInTranslates  (Counter64) = ...Entry.2
 *   natv2ProtocolStatsOutTranslates (Counter64) = ...Entry.3
 *   natv2ProtocolStatsDiscards      (Counter64) = ...Entry.4
 */

/* Known protocol entries */
static const int proto_indices[] = { NAT_PROTO_ICMP, NAT_PROTO_TCP,
                                     NAT_PROTO_UDP, NAT_PROTO_OTHER };
#define NUM_PROTOS 4

static netsnmp_variable_list *
_proto_get_first(void **loop_ctx, void **data_ctx,
                 netsnmp_variable_list *idx, netsnmp_iterator_info *info)
{
    long proto = proto_indices[0];
    *loop_ctx = (void *)0;
    snmp_set_var_value(idx, &proto, sizeof(proto));
    *data_ctx = (void *)(uintptr_t)proto;
    return idx;
}

static netsnmp_variable_list *
_proto_get_next(void **loop_ctx, void **data_ctx,
                netsnmp_variable_list *idx, netsnmp_iterator_info *info)
{
    long proto;
    int pos = (int)(uintptr_t)*loop_ctx + 1;
    if (pos >= NUM_PROTOS)
        return NULL;
    *loop_ctx = (void *)(uintptr_t)pos;
    proto = proto_indices[pos];
    snmp_set_var_value(idx, &proto, sizeof(proto));
    *data_ctx = (void *)(uintptr_t)proto;
    return idx;
}

static int
_proto_handler(netsnmp_mib_handler *handler,
               netsnmp_handler_registration *reginfo,
               netsnmp_agent_request_info *reqinfo,
               netsnmp_request_info *requests)
{
    const nat_global_stats_t *snap;
    netsnmp_request_info *req;
    netsnmp_table_request_info *tinfo;
    int proto;
    const nat_proto_stats_t *ps;
    struct counter64 c64;

    if (reqinfo->mode != MODE_GET)
        return SNMP_ERR_NOERROR;

    snap = _get_nat_stats();

    for (req = requests; req; req = req->next) {
        if (req->processed)
            continue;

        tinfo = netsnmp_extract_table_info(req);
        if (!tinfo)
            continue;

        proto = (int)(uintptr_t)netsnmp_extract_iterator_context(req);

        switch (proto) {
        case NAT_PROTO_TCP:  ps = &snap->tcp;  break;
        case NAT_PROTO_UDP:  ps = &snap->udp;  break;
        case NAT_PROTO_ICMP: ps = &snap->icmp; break;
        default:             ps = &snap->other; break;
        }

        switch (tinfo->colnum) {
        case COL_NATV2_PROTO_IN_TRANSLATES:
            c64.low  = ps->in_translates & 0xffffffff;
            c64.high = ps->in_translates >> 32;
            snmp_set_var_typed_value(req->requestvb, ASN_COUNTER64,
                                    &c64, sizeof(c64));
            break;
        case COL_NATV2_PROTO_OUT_TRANSLATES:
            c64.low  = ps->out_translates & 0xffffffff;
            c64.high = ps->out_translates >> 32;
            snmp_set_var_typed_value(req->requestvb, ASN_COUNTER64,
                                    &c64, sizeof(c64));
            break;
        case COL_NATV2_PROTO_DISCARDS:
            c64.low  = ps->drops & 0xffffffff;
            c64.high = ps->drops >> 32;
            snmp_set_var_typed_value(req->requestvb, ASN_COUNTER64,
                                    &c64, sizeof(c64));
            break;
        default:
            netsnmp_set_request_error(reqinfo, req, SNMP_NOSUCHOBJECT);
            break;
        }
    }
    return SNMP_ERR_NOERROR;
}

/*
 * Module initialization
 */

void
init_nat_vpp(void)
{
    netsnmp_handler_registration *reg;
    netsnmp_iterator_info *iinfo;
    netsnmp_table_registration_info *tinfo;

    DEBUGMSGTL(("nat_vpp", "Initializing NATV2-MIB VPP module\n"));

    /* Register global scalars */
    netsnmp_register_scalar(
        netsnmp_create_handler_registration(
            "natv2GlobalActiveSessions", handle_natv2Scalar,
            natv2GlobalActiveSessions_oid,
            OID_LENGTH(natv2GlobalActiveSessions_oid),
            HANDLER_CAN_RONLY));

    netsnmp_register_scalar(
        netsnmp_create_handler_registration(
            "natv2GlobalMaxSessions", handle_natv2Scalar,
            natv2GlobalMaxSessions_oid,
            OID_LENGTH(natv2GlobalMaxSessions_oid),
            HANDLER_CAN_RONLY));

    netsnmp_register_scalar(
        netsnmp_create_handler_registration(
            "natv2GlobalInTranslates", handle_natv2Scalar,
            natv2GlobalInTranslates_oid,
            OID_LENGTH(natv2GlobalInTranslates_oid),
            HANDLER_CAN_RONLY));

    netsnmp_register_scalar(
        netsnmp_create_handler_registration(
            "natv2GlobalOutTranslates", handle_natv2Scalar,
            natv2GlobalOutTranslates_oid,
            OID_LENGTH(natv2GlobalOutTranslates_oid),
            HANDLER_CAN_RONLY));

    netsnmp_register_scalar(
        netsnmp_create_handler_registration(
            "natv2GlobalDrops", handle_natv2Scalar,
            natv2GlobalDrops_oid,
            OID_LENGTH(natv2GlobalDrops_oid),
            HANDLER_CAN_RONLY));

    /* Register protocol stats table */
    reg = netsnmp_create_handler_registration(
        "natv2ProtocolStatsTable", _proto_handler,
        natv2ProtocolStatsTable_oid,
        OID_LENGTH(natv2ProtocolStatsTable_oid),
        HANDLER_CAN_RONLY);

    tinfo = SNMP_MALLOC_TYPEDEF(netsnmp_table_registration_info);
    netsnmp_table_helper_add_indexes(tinfo, ASN_INTEGER, 0);
    tinfo->min_column = COL_NATV2_PROTO_IN_TRANSLATES;
    tinfo->max_column = COL_NATV2_PROTO_DISCARDS;

    iinfo = SNMP_MALLOC_TYPEDEF(netsnmp_iterator_info);
    iinfo->get_first_data_point = _proto_get_first;
    iinfo->get_next_data_point  = _proto_get_next;
    iinfo->table_reginfo        = tinfo;

    netsnmp_register_table_iterator(reg, iinfo);

    DEBUGMSGTL(("nat_vpp", "NATV2-MIB VPP module initialized\n"));
}
