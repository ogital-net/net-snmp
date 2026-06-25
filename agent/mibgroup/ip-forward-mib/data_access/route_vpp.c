/*
 * route_vpp.c -- VPP-backed IP route data access layer.
 *
 * Replaces route_linux.c for --with-vpp builds.  Enumerates IPv4 and IPv6
 * routes from VPP FIB table 0 via ip_route_dump VAPI call.
 */

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-features.h>
#include <net-snmp/net-snmp-includes.h>

#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <net-snmp/data_access/route.h>
#include <net-snmp/data_access/interface.h>

#include "ip-forward-mib/inetCidrRouteTable/inetCidrRouteTable_constants.h"
#include "ip-forward-mib/data_access/route_private.h"

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <arpa/inet.h>

/* VPP VAPI headers */
#include <vapi/vapi.h>
#include <vapi/ip.api.vapi.h>
#include <vapi/ip_types.api.vapi.h>

/* Shared VPP helpers */
#include "if-mib/data_access/interface_vpp.h"

/* --------------------------------------------------------------------------
 * Route protocol mapping -- VPP FIB source to SNMP ipRouteProto
 * -------------------------------------------------------------------------- */
#define IPROUTEPROTOCOL_OTHER   1
#define IPROUTEPROTOCOL_LOCAL   2
#define IPROUTEPROTOCOL_STATIC  3
#define IPROUTEPROTOCOL_ICMP    4

/* VPP fib_path_type values we care about */
#define FIB_API_PATH_TYPE_NORMAL     0
#define FIB_API_PATH_TYPE_LOCAL      1
#define FIB_API_PATH_TYPE_DROP       2
#define FIB_API_PATH_TYPE_ATTACHED   6

/* --------------------------------------------------------------------------
 * Callback context for ip_route_dump
 * -------------------------------------------------------------------------- */
typedef struct {
    netsnmp_container *container;
    u_long             count;
    int                error;
    volatile bool      done;   /* set on end-of-dump sentinel */
} route_dump_ctx_t;

/*
 * Callback invoked for each ip_route_details reply.
 */
static vapi_error_e
_ip_route_details_cb(vapi_ctx_t ctx __attribute__((unused)),
                     void *caller_ctx,
                     vapi_error_e rv,
                     bool is_last,
                     vapi_payload_ip_route_details *details)
{
    route_dump_ctx_t *dctx = (route_dump_ctx_t *)caller_ctx;
    netsnmp_route_entry *entry;
    const vapi_type_ip_route *route;
    const vapi_type_fib_path *path;
    int addr_len;

    if (rv != VAPI_OK) {
        dctx->error = 1;
        dctx->done = true;
        return rv;
    }

    if (is_last && !details) {
        dctx->done = true;
        return VAPI_OK;
    }
    if (!details)
        return VAPI_OK;

    route = &details->route;

    /* Determine address family from prefix. */
    if (route->prefix.address.af == ADDRESS_IP4)
        addr_len = 4;
    else
        addr_len = 16;

    /* Use first path for next-hop info. */
    if (route->n_paths == 0)
        return VAPI_OK; /* no paths: drop/unreachable, skip */

    path = &route->paths[0];

    /* Skip internal VPP drop/punt routes */
    if (path->type == FIB_API_PATH_TYPE_DROP)
        return VAPI_OK;

    entry = netsnmp_access_route_entry_create();
    if (!entry) {
        dctx->error = 1;
        return VAPI_OK;
    }

    dctx->count++;
    entry->ns_rt_index = (oid)dctx->count;

    /* Destination prefix */
    entry->rt_dest_len  = addr_len;
    entry->rt_dest_type = (addr_len == 4) ? INETADDRESSTYPE_IPV4
                                          : INETADDRESSTYPE_IPV6;
    if (addr_len == 4)
        memcpy(entry->rt_dest, route->prefix.address.un.ip4, 4);
    else
        memcpy(entry->rt_dest, route->prefix.address.un.ip6, 16);

    entry->rt_pfx_len = route->prefix.len;

    /* Next-hop */
    entry->rt_nexthop_len  = addr_len;
    entry->rt_nexthop_type = entry->rt_dest_type;
    if (addr_len == 4)
        memcpy(entry->rt_nexthop, path->nh.address.ip4, 4);
    else
        memcpy(entry->rt_nexthop, path->nh.address.ip6, 16);

    /* Interface index of next-hop (SNMP ifIndex is sw_if_index + 1) */
    entry->if_index = (oid)(path->sw_if_index + 1);

    /* Route type */
    if (path->type == FIB_API_PATH_TYPE_LOCAL)
        entry->rt_type = 3; /* local(3) */
    else if (path->type == FIB_API_PATH_TYPE_ATTACHED)
        entry->rt_type = 3; /* direct(3) */
    else
        entry->rt_type = 4; /* indirect(4) -- remote */

    /* Protocol -- VPP does not expose per-route source easily via this API */
    if (path->type == FIB_API_PATH_TYPE_LOCAL)
        entry->rt_proto = IPROUTEPROTOCOL_LOCAL;
    else
        entry->rt_proto = IPROUTEPROTOCOL_STATIC;

    /* Metrics */
    entry->rt_metric1 = path->weight;

    /* Age: not available from VPP route dump; set 0 */
    entry->rt_age = 0;

#ifdef USING_IP_FORWARD_MIB_IPCIDRROUTETABLE_IPCIDRROUTETABLE_MODULE
    /* Mask for IPv4 (network byte order) */
    if (addr_len == 4) {
        if (route->prefix.len == 0)
            entry->rt_mask = 0;
        else
            entry->rt_mask = htonl(~0u << (32 - route->prefix.len));
    }
#endif

    if (CONTAINER_INSERT(dctx->container, entry) != 0) {
        snmp_log(LOG_ERR, "route_vpp: container insert failed\n");
        netsnmp_access_route_entry_free(entry);
        dctx->error = 1;
    }

    return VAPI_OK;
}

/*
 * Issue ip_route_dump for one address family on table 0.
 */
static int
_load_routes(netsnmp_container *container, u_long *count, bool is_ip6)
{
    route_dump_ctx_t dctx;
    vapi_msg_ip_route_dump *msg;
    vapi_error_e rv;

    dctx.container = container;
    dctx.count     = *count;
    dctx.error     = 0;
    dctx.done      = false;

    msg = vapi_alloc_ip_route_dump(g_vapi_ctx);
    if (!msg)
        return -2;

    memset(&msg->payload.table, 0, sizeof(msg->payload.table));
    msg->payload.table.table_id = 0;
    msg->payload.table.is_ip6   = is_ip6;

    rv = vapi_ip_route_dump(g_vapi_ctx, msg, _ip_route_details_cb, &dctx);
    if (rv != VAPI_OK) {
        snmp_log(LOG_ERR, "route_vpp: vapi_ip_route_dump failed (%d)\n", rv);
        vapi_msg_free(g_vapi_ctx, msg);
        vapi_reset_connection();
        return -2;
    }
    if (vapi_dump_dispatch(&dctx.done) != 0) {
        snmp_log(LOG_ERR, "route_vpp: vapi_ip_route_dump dispatch timeout\n");
        vapi_reset_connection();
        return -2;
    }

    *count = dctx.count;
    return dctx.error ? -3 : 0;
}

/*
 * Public arch functions (route_private.h)
 * -----------------------------------------------------------*/

int
netsnmp_access_route_container_arch_load(netsnmp_container *container,
                                         u_int load_flags)
{
    u_long count = 0;
    int rc;

    DEBUGMSGTL(("access:route:vpp:container",
                "load (flags %x)\n", load_flags));

    if (!container) {
        snmp_log(LOG_ERR, "route_vpp: no container\n");
        return -1;
    }

    if (vapi_connect_once() != 0) {
        snmp_log(LOG_ERR, "route_vpp: VPP not available\n");
        return -2;
    }

    /* Load IPv4 routes */
    rc = _load_routes(container, &count, false);

#ifdef NETSNMP_ENABLE_IPV6
    if (rc == 0 && !(load_flags & NETSNMP_ACCESS_ROUTE_LOAD_IPV4_ONLY)) {
        rc = _load_routes(container, &count, true);
        if (rc == -2)
            rc = 0; /* IPv6 not available is non-fatal */
    }
#endif

    return rc;
}

int
netsnmp_arch_route_create(netsnmp_route_entry *entry)
{
    /*
     * Route creation via SNMP is not supported on the VPP data plane.
     */
    (void)entry;
    return -1;
}

int
netsnmp_arch_route_delete(netsnmp_route_entry *entry)
{
    (void)entry;
    return -1;
}
