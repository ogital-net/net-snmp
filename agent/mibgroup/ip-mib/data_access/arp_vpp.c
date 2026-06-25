/*
 * arp_vpp.c -- VPP-backed ARP/neighbor data access layer.
 *
 * Replaces arp_netlink.c for --with-vpp builds.  Enumerates IPv4 and IPv6
 * neighbors via the ip_neighbor_dump VAPI call.
 */

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <net-snmp/data_access/arp.h>
#include <net-snmp/data_access/interface.h>

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

/* VPP VAPI headers */
#include <vapi/vapi.h>
#include <vapi/ip_neighbor.api.vapi.h>
#include <vapi/ip_types.api.vapi.h>

DEFINE_VAPI_MSG_IDS_IP_NEIGHBOR_API_JSON;

/* Shared VPP helpers */
#include "if-mib/data_access/interface_vpp.h"

/* --------------------------------------------------------------------------
 * Callback context for ip_neighbor_dump
 * -------------------------------------------------------------------------- */
typedef struct {
    netsnmp_arp_access *access;
    int                 error;
    volatile bool       done;   /* set on end-of-dump sentinel */
} neighbor_dump_ctx_t;

/*
 * Map VPP neighbor flags to inetNetToMediaState.
 */
static u_char
_neighbor_state(vapi_enum_ip_neighbor_flags flags)
{
    if (flags & IP_API_NEIGHBOR_FLAG_STATIC)
        return INETNETTOMEDIASTATE_REACHABLE;
    /* Dynamic neighbors from VPP are assumed reachable (VPP resolved them) */
    return INETNETTOMEDIASTATE_REACHABLE;
}

static u_char
_neighbor_type(vapi_enum_ip_neighbor_flags flags)
{
    if (flags & IP_API_NEIGHBOR_FLAG_STATIC)
        return INETNETTOMEDIATYPE_STATIC;
    return INETNETTOMEDIATYPE_DYNAMIC;
}

/*
 * Callback invoked for each ip_neighbor_details reply.
 */
static vapi_error_e
_ip_neighbor_details_cb(vapi_ctx_t ctx __attribute__((unused)),
                        void *caller_ctx,
                        vapi_error_e rv,
                        bool is_last,
                        vapi_payload_ip_neighbor_details *details)
{
    neighbor_dump_ctx_t *dctx = (neighbor_dump_ctx_t *)caller_ctx;
    netsnmp_arp_entry *entry;
    const vapi_type_ip_neighbor *nb;
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

    nb = &details->neighbor;

    if (nb->ip_address.af == ADDRESS_IP4)
        addr_len = 4;
    else
        addr_len = 16;

    entry = netsnmp_access_arp_entry_create();
    if (!entry) {
        dctx->error = 1;
        return VAPI_OK;
    }

    entry->generation = dctx->access->generation;

    /* ifIndex = VPP sw_if_index + 1 (SNMP ifIndex is 1-based) */
    entry->if_index = (oid)(nb->sw_if_index + 1);

    /* IP address */
    entry->arp_ipaddress_len = addr_len;
    if (addr_len == 4)
        memcpy(entry->arp_ipaddress, nb->ip_address.un.ip4, 4);
    else
        memcpy(entry->arp_ipaddress, nb->ip_address.un.ip6, 16);

    /* MAC address (6 bytes) */
    memcpy(entry->arp_physaddress, nb->mac_address, 6);
    entry->arp_physaddress_len = 6;

    /* Type and state */
    entry->arp_type  = _neighbor_type(nb->flags);
    entry->arp_state = _neighbor_state(nb->flags);

    /* Deliver entry via the update hook */
    dctx->access->update_hook(dctx->access, entry);

    return VAPI_OK;
}

/*
 * Issue ip_neighbor_dump for one address family on all interfaces.
 */
static int
_dump_neighbors(netsnmp_arp_access *access, vapi_enum_address_family af)
{
    neighbor_dump_ctx_t dctx;
    vapi_msg_ip_neighbor_dump *msg;
    vapi_error_e rv;

    dctx.access = access;
    dctx.error  = 0;
    dctx.done   = false;

    msg = vapi_alloc_ip_neighbor_dump(g_vapi_ctx);
    if (!msg)
        return -1;

    msg->payload.sw_if_index = ~0u; /* all interfaces */
    msg->payload.af          = af;

    rv = vapi_ip_neighbor_dump(g_vapi_ctx, msg, _ip_neighbor_details_cb, &dctx);
    if (rv != VAPI_OK) {
        snmp_log(LOG_ERR, "arp_vpp: vapi_ip_neighbor_dump failed (%d)\n", rv);
        vapi_msg_free(g_vapi_ctx, msg);
        vapi_reset_connection();
        return -1;
    }
    if (vapi_dump_dispatch(&dctx.done) != 0) {
        snmp_log(LOG_ERR, "arp_vpp: vapi_ip_neighbor_dump dispatch timeout\n");
        vapi_reset_connection();
        return -1;
    }

    return dctx.error ? -1 : 0;
}

/*
 * Public arch functions (same signatures as arp_netlink.c)
 * -----------------------------------------------------------*/

netsnmp_arp_access *
netsnmp_access_arp_create(u_int init_flags,
                          NetsnmpAccessArpUpdate *update_hook,
                          NetsnmpAccessArpGC *gc_hook,
                          int *cache_timeout, int *cache_flags,
                          char *cache_expired)
{
    netsnmp_arp_access *access;

    (void)init_flags;

    access = SNMP_MALLOC_TYPEDEF(netsnmp_arp_access);
    if (!access) {
        snmp_log(LOG_ERR, "arp_vpp: malloc failed\n");
        return NULL;
    }

    access->arch_magic    = NULL;
    access->magic         = NULL;
    access->update_hook   = update_hook;
    access->gc_hook       = gc_hook;
    access->synchronized  = 0;
    access->cache_expired = cache_expired;

    if (cache_timeout)
        *cache_timeout = 15; /* poll VPP every 15s */
    if (cache_flags)
        *cache_flags |= NETSNMP_CACHE_RESET_TIMER_ON_USE;

    DEBUGMSGTL(("access:arp:vpp", "create arp cache\n"));
    return access;
}

int
netsnmp_access_arp_delete(netsnmp_arp_access *access)
{
    if (!access)
        return 0;
    free(access);
    return 0;
}

int
netsnmp_access_arp_load(netsnmp_arp_access *access)
{
    int rc;

    if (!access)
        return -1;

    if (access->synchronized)
        return 0;

    DEBUGMSGTL(("access:arp:vpp", "loading neighbor table from VPP\n"));

    if (vapi_connect_once() != 0) {
        snmp_log(LOG_ERR, "arp_vpp: VPP not available\n");
        return -1;
    }

    access->generation++;

    /* Dump IPv4 neighbors */
    rc = _dump_neighbors(access, ADDRESS_IP4);

#if defined(NETSNMP_ENABLE_IPV6)
    /* Dump IPv6 neighbors */
    if (rc == 0)
        rc = _dump_neighbors(access, ADDRESS_IP6);
#endif

    if (rc == 0) {
        access->synchronized = 1;
        access->gc_hook(access);
    }

    return rc;
}

int
netsnmp_access_arp_unload(netsnmp_arp_access *access)
{
    if (!access)
        return 0;

    DEBUGMSGTL(("access:arp:vpp", "unload arp cache\n"));
    access->synchronized = 0;
    return 0;
}
