/*
 * defaultrouter_vpp.c -- VPP-backed ipDefaultRouterTable data access.
 *
 * Enumerates IPv4/IPv6 default routes (prefix length 0) from VPP FIB table 0
 * via ip_route_dump and exposes them through net-snmp defaultrouter access API.
 */

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <net-snmp/data_access/defaultrouter.h>

#include "ip-mib/ipDefaultRouterTable/ipDefaultRouterTable.h"
#include "ip-mib/ipDefaultRouterTable/ipDefaultRouterTable_enums.h"
#include "defaultrouter_private.h"

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <vapi/vapi.h>
#include <vapi/ip.api.vapi.h>
#include <vapi/ip_types.api.vapi.h>

/* Shared VPP helpers */
#include "if-mib/data_access/interface_vpp.h"

#define FIB_API_PATH_TYPE_DROP 2

typedef struct {
    netsnmp_container *container;
    oid                idx_offset;
    int                rc;
    volatile bool      done;   /* set on end-of-dump sentinel */
} dr_dump_ctx_t;

static vapi_error_e
_dr_details_cb(vapi_ctx_t ctx __attribute__((unused)),
               void *caller_ctx,
               vapi_error_e rv,
               bool is_last,
               vapi_payload_ip_route_details *details)
{
    dr_dump_ctx_t *dctx;
    const vapi_type_ip_route *route;
    const vapi_type_fib_path *path;
    netsnmp_defaultrouter_entry *entry;
    u_char addresstype;

    dctx = (dr_dump_ctx_t *)caller_ctx;
    if (rv != VAPI_OK) {
        dctx->rc = -2;
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

    /* ipDefaultRouterTable only wants default routes. */
    if (route->prefix.len != 0)
        return VAPI_OK;

    if (route->n_paths == 0)
        return VAPI_OK;

    path = &route->paths[0];
    if (path->type == FIB_API_PATH_TYPE_DROP)
        return VAPI_OK;

    entry = netsnmp_access_defaultrouter_entry_create();
    if (!entry) {
        dctx->rc = -3;
        return VAPI_OK;
    }

    entry->ns_dr_index = ++dctx->idx_offset;

    if (route->prefix.address.af == ADDRESS_IP4) {
        addresstype = INETADDRESSTYPE_IPV4;
        entry->dr_address_len = 4;
        memcpy(entry->dr_address, path->nh.address.ip4, 4);
    } else {
#ifdef NETSNMP_ENABLE_IPV6
        addresstype = INETADDRESSTYPE_IPV6;
        entry->dr_address_len = 16;
        memcpy(entry->dr_address, path->nh.address.ip6, 16);
#else
        netsnmp_access_defaultrouter_entry_free(entry);
        return VAPI_OK;
#endif
    }

    entry->dr_addresstype = addresstype;
    entry->dr_if_index = (oid)(path->sw_if_index + 1);

    /* Not exposed by route dump in a portable way; keep sensible defaults. */
    entry->dr_lifetime = IPDEFAULTROUTERLIFETIME_MAX;
    entry->dr_preference = IPDEFAULTROUTERPREFERENCE_MEDIUM;

    if (CONTAINER_INSERT(dctx->container, entry) < 0) {
        netsnmp_access_defaultrouter_entry_free(entry);
        dctx->rc = -3;
    }

    return VAPI_OK;
}

static int
_load_default_routes(netsnmp_container *container, oid *idx_offset, bool is_ip6)
{
    dr_dump_ctx_t dctx;
    vapi_msg_ip_route_dump *msg;
    vapi_error_e rv;

    dctx.container = container;
    dctx.idx_offset = *idx_offset;
    dctx.rc = 0;
    dctx.done = false;

    msg = vapi_alloc_ip_route_dump(g_vapi_ctx);
    if (!msg)
        return -2;

    memset(&msg->payload.table, 0, sizeof(msg->payload.table));
    msg->payload.table.table_id = 0;
    msg->payload.table.is_ip6 = is_ip6;

    rv = vapi_ip_route_dump(g_vapi_ctx, msg, _dr_details_cb, &dctx);
    if (rv != VAPI_OK) {
        vapi_msg_free(g_vapi_ctx, msg);
        vapi_reset_connection();
        return -2;
    }
    if (vapi_dump_dispatch(&dctx.done) != 0) {
        snmp_log(LOG_ERR, "defaultrouter_vpp: vapi_ip_route_dump dispatch timeout\n");
        vapi_reset_connection();
        return -2;
    }

    *idx_offset = dctx.idx_offset;
    return dctx.rc;
}

int
netsnmp_arch_defaultrouter_entry_init(netsnmp_defaultrouter_entry *entry)
{
    (void)entry;
    return 0;
}

int
netsnmp_arch_defaultrouter_container_load(netsnmp_container *container,
                                          u_int load_flags)
{
    oid idx_offset;
    int rc;

    DEBUGMSGTL(("access:defaultrouter:entry:arch", "load (vpp)\n"));

    if (!container)
        return -1;

    if (vapi_connect_once() != 0)
        return -2;

    idx_offset = 0;

    if (!(load_flags & NETSNMP_ACCESS_DEFAULTROUTER_LOAD_IPV6_ONLY)) {
        rc = _load_default_routes(container, &idx_offset, false);
        if (rc < 0)
            return rc;
    }

#ifdef NETSNMP_ENABLE_IPV6
    if (!(load_flags & NETSNMP_ACCESS_DEFAULTROUTER_LOAD_IPV4_ONLY)) {
        rc = _load_default_routes(container, &idx_offset, true);
        if (rc < 0 && rc != -2)
            return rc;
    }
#endif

    return 0;
}
