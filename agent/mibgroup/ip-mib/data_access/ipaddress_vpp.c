/*
 * ipaddress_vpp.c -- VPP-backed IP address data access layer.
 *
 * Replaces ipaddress_linux.c for --with-vpp builds.  Enumerates IPv4 and
 * IPv6 addresses on VPP interfaces via the ip_address_dump VAPI call.
 *
 * VPP sw_if_index is used directly as the SNMP ifIndex.
 */

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-features.h>
#include <net-snmp/net-snmp-includes.h>

#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <net-snmp/data_access/ipaddress.h>
#include <net-snmp/data_access/interface.h>

#include "ip-mib/ipAddressTable/ipAddressTable_constants.h"

netsnmp_feature_child_of(ipaddress_arch_entry_copy, ipaddress_common);

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <arpa/inet.h>

/* VPP VAPI headers */
#include <vapi/vapi.h>
#include <vapi/ip.api.vapi.h>
#include <vapi/ip_types.api.vapi.h>
#include <vapi/interface.api.vapi.h>

/*
 * VAPI message-ID storage for IP API.
 * interface_vpp.c already defines INTERFACE_API and VPE_API IDs.
 */
DEFINE_VAPI_MSG_IDS_IP_API_JSON;

/* Shared VPP helpers */
#include "if-mib/data_access/interface_vpp.h"

/* --------------------------------------------------------------------------
 * Callback context for ip_address_dump
 * -------------------------------------------------------------------------- */
typedef struct {
    netsnmp_container *container;
    int                idx_offset;  /* running entry index */
    u_int              load_flags;
    int                error;
    volatile bool      done;        /* set on end-of-dump sentinel */
} ipaddr_dump_ctx_t;

/*
 * Callback invoked for each ip_address_details reply.
 */
static vapi_error_e
_ip_address_details_cb(vapi_ctx_t ctx __attribute__((unused)),
                       void *caller_ctx,
                       vapi_error_e rv,
                       bool is_last,
                       vapi_payload_ip_address_details *details)
{
    ipaddr_dump_ctx_t *dctx = (ipaddr_dump_ctx_t *)caller_ctx;
    netsnmp_ipaddress_entry *entry;
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

    /* Determine address family from the prefix. */
    if (details->prefix.address.af == ADDRESS_IP4)
        addr_len = 4;
    else
        addr_len = 16;

    /* Allocate entry with a running index. */
    entry = netsnmp_access_ipaddress_entry_create();
    if (!entry) {
        dctx->error = 1;
        return VAPI_OK;
    }

    dctx->idx_offset++;
    entry->ns_ia_index = dctx->idx_offset;

    /* ifIndex = VPP sw_if_index + 1 (SNMP ifIndex is 1-based) */
    entry->if_index = (oid)(details->sw_if_index + 1);

    /* Address bytes (network byte order in VPP). */
    entry->ia_address_len = addr_len;
    if (addr_len == 4)
        memcpy(entry->ia_address, details->prefix.address.un.ip4, 4);
    else
        memcpy(entry->ia_address, details->prefix.address.un.ip6, 16);

    /* Prefix length */
    entry->ia_prefix_len = details->prefix.len;

    /* Type: unicast(1) for now; VPP does not distinguish in ip_address_dump */
    entry->ia_type = IPADDRESSTYPE_UNICAST;

    /* Status: preferred(1) -- VPP addresses are always preferred */
    entry->ia_status = IPADDRESSSTATUSTC_PREFERRED;

    /* Origin: manual(2) -- VPP addresses are typically manually configured */
    entry->ia_origin = IPADDRESSORIGINTC_MANUAL;

    /* Storage: volatile(2) -- VPP config is not persistent by default */
    entry->ia_storagetype = STORAGETYPE_VOLATILE;

    if (CONTAINER_INSERT(dctx->container, entry) != 0) {
        snmp_log(LOG_ERR, "ipaddress_vpp: container insert failed\n");
        netsnmp_access_ipaddress_entry_free(entry);
        dctx->error = 1;
    }

    return VAPI_OK;
}

/*
 * Issue ip_address_dump for each interface.
 *
 * VPP 26.06's ip_address_dump does not support sw_if_index=~0 to dump all
 * interfaces at once.  We must iterate per sw_if_index.  To find the valid
 * range, we first do a sw_interface_dump to enumerate active interfaces,
 * then query each one individually.
 */

/* Callback to collect sw_if_index values */
typedef struct {
    uint32_t     *indices;
    int           count;
    int           capacity;
    volatile bool done;   /* set on end-of-dump sentinel */
} sw_if_enum_ctx_t;

static vapi_error_e
_enum_if_cb(vapi_ctx_t ctx __attribute__((unused)),
            void *caller_ctx,
            vapi_error_e rv,
            bool is_last,
            vapi_payload_sw_interface_details *details)
{
    sw_if_enum_ctx_t *ectx = (sw_if_enum_ctx_t *)caller_ctx;

    if (rv != VAPI_OK || (is_last && !details)) {
        ectx->done = true;
        return VAPI_OK;
    }
    if (!details)
        return VAPI_OK;

    /* Grow the array if needed */
    if (ectx->count >= ectx->capacity) {
        int new_cap = ectx->capacity * 2;
        uint32_t *tmp = realloc(ectx->indices, new_cap * sizeof(*tmp));
        if (!tmp)
            return VAPI_OK; /* drop this entry on OOM */
        ectx->indices  = tmp;
        ectx->capacity = new_cap;
    }

    ectx->indices[ectx->count++] = details->sw_if_index;
    return VAPI_OK;
}

static int
_load_addresses(netsnmp_container *container, int *idx_offset, bool is_ipv6)
{
    ipaddr_dump_ctx_t dctx;
    sw_if_enum_ctx_t ectx;
    int i;

    /* Phase 1: enumerate interfaces to find valid sw_if_index values */
    ectx.indices  = malloc(64 * sizeof(*ectx.indices));
    ectx.count    = 0;
    ectx.capacity = 64;
    ectx.done     = false;

    if (!ectx.indices)
        return -3;

    {
        vapi_msg_sw_interface_dump *emsg;
        vapi_error_e erv;

        emsg = vapi_alloc_sw_interface_dump(g_vapi_ctx, 0);
        if (!emsg) {
            free(ectx.indices);
            return -2;
        }
        emsg->payload.sw_if_index = ~0u;
        emsg->payload.name_filter_valid = false;

        erv = vapi_sw_interface_dump(g_vapi_ctx, emsg, _enum_if_cb, &ectx);
        if (erv != VAPI_OK) {
            snmp_log(LOG_ERR,
                     "ipaddress_vpp: sw_interface_dump failed (%d)\n", erv);
            vapi_msg_free(g_vapi_ctx, emsg);
            free(ectx.indices);
            vapi_reset_connection();
            return -2;
        }
        if (vapi_dump_dispatch(&ectx.done) != 0) {
            snmp_log(LOG_ERR,
                     "ipaddress_vpp: sw_interface_dump dispatch timeout\n");
            free(ectx.indices);
            vapi_reset_connection();
            return -2;
        }
    }

    /* Phase 2: dump addresses for each discovered interface */
    dctx.container  = container;
    dctx.idx_offset = *idx_offset;
    dctx.load_flags = 0;
    dctx.error      = 0;

    for (i = 0; i < ectx.count; i++) {
        vapi_msg_ip_address_dump *msg;
        vapi_error_e rv;

        msg = vapi_alloc_ip_address_dump(g_vapi_ctx);
        if (!msg)
            continue;

        msg->payload.sw_if_index = ectx.indices[i];
        msg->payload.is_ipv6     = is_ipv6;

        dctx.done = false;
        rv = vapi_ip_address_dump(g_vapi_ctx, msg,
                                  _ip_address_details_cb, &dctx);
        if (rv != VAPI_OK) {
            snmp_log(LOG_ERR,
                     "ipaddress_vpp: ip_address_dump sw_if=%u failed (%d)\n",
                     ectx.indices[i], rv);
            /*
             * A send error leaves msg caller-owned; free it before reset.
             */
            vapi_msg_free(g_vapi_ctx, msg);
            vapi_reset_connection();
            free(ectx.indices);
            *idx_offset = dctx.idx_offset;
            return -2;
        }
        if (vapi_dump_dispatch(&dctx.done) != 0) {
            /*
             * Dispatch timeout after a successful send: VPP owns msg now,
             * so do NOT free it -- just drop the broken connection.
             */
            snmp_log(LOG_ERR,
                     "ipaddress_vpp: ip_address_dump sw_if=%u dispatch timeout\n",
                     ectx.indices[i]);
            vapi_reset_connection();
            free(ectx.indices);
            *idx_offset = dctx.idx_offset;
            return -2;
        }
    }

    free(ectx.indices);
    *idx_offset = dctx.idx_offset;
    return dctx.error ? -3 : 0;
}

/*
 * Public arch functions (ipaddress_private.h)
 * -----------------------------------------------------------*/

int
netsnmp_arch_ipaddress_entry_init(netsnmp_ipaddress_entry *entry)
{
    (void)entry;
    return 0;
}

void
netsnmp_arch_ipaddress_entry_cleanup(netsnmp_ipaddress_entry *entry)
{
    (void)entry;
}

#ifndef NETSNMP_FEATURE_REMOVE_IPADDRESS_ARCH_ENTRY_COPY
int
netsnmp_arch_ipaddress_entry_copy(netsnmp_ipaddress_entry *lhs,
                                  netsnmp_ipaddress_entry *rhs)
{
    (void)lhs;
    (void)rhs;
    return 0;
}
#endif /* NETSNMP_FEATURE_REMOVE_IPADDRESS_ARCH_ENTRY_COPY */

int
netsnmp_arch_ipaddress_create(netsnmp_ipaddress_entry *entry)
{
    /*
     * Creating IP addresses on VPP interfaces is not supported via SNMP
     * in this implementation.
     */
    (void)entry;
    return -1;
}

int
netsnmp_arch_ipaddress_delete(netsnmp_ipaddress_entry *entry)
{
    (void)entry;
    return -1;
}

/**
 * netsnmp_arch_ipaddress_container_load -- populate the container with
 * VPP interface addresses via ip_address_dump.
 */
int
netsnmp_arch_ipaddress_container_load(netsnmp_container *container,
                                      u_int load_flags)
{
    int rc = 0, idx_offset = 0;

    DEBUGMSGTL(("access:ipaddress:vpp:container",
                "load (flags %x)\n", load_flags));


    if (!container) {
        snmp_log(LOG_ERR, "ipaddress_vpp: no container\n");
        return -1;
    }

    if (vapi_connect_once() != 0) {
        snmp_log(LOG_ERR,
                 "ipaddress_vpp: VPP not available\n");
        return -2;
    }

    /* Load IPv4 addresses */
    if (!(load_flags & NETSNMP_ACCESS_IPADDRESS_LOAD_IPV6_ONLY)) {
        rc = _load_addresses(container, &idx_offset, false);
        if (rc < 0) {
            u_int flags = NETSNMP_ACCESS_IPADDRESS_FREE_KEEP_CONTAINER;
            netsnmp_access_ipaddress_container_free(container, flags);
            return rc;
        }
    }

#if defined(NETSNMP_ENABLE_IPV6)
    /* Load IPv6 addresses */
    if (!(load_flags & NETSNMP_ACCESS_IPADDRESS_LOAD_IPV4_ONLY)) {
        rc = _load_addresses(container, &idx_offset, true);
        if (rc < 0 && rc != -2) {
            u_int flags = NETSNMP_ACCESS_IPADDRESS_FREE_KEEP_CONTAINER;
            netsnmp_access_ipaddress_container_free(container, flags);
            return rc;
        }
        if (rc == -2)
            rc = 0; /* non-fatal if IPv6 not available */
    }
#endif

    return rc < 0 ? rc : 0;
}
