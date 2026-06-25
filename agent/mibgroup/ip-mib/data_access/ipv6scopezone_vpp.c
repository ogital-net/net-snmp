/*
 * ipv6scopezone_vpp.c -- VPP-backed ipv6ScopeZoneIndexTable data access.
 *
 * Builds scope-zone entries from VPP IPv6 interface addresses. For each
 * interface that has at least one link-local IPv6 address (fe80::/10), insert
 * one scope zone entry mapping link-local zone to the interface index.
 */

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <net-snmp/data_access/scopezone.h>
#include <net-snmp/data_access/ipaddress.h>

#include "ipv6scopezone_private.h"

#include <string.h>

static int
_is_link_local_v6(const u_char *addr, size_t len)
{
    if (len < 16)
        return 0;

    /* fe80::/10 */
    if (addr[0] != 0xfe)
        return 0;
    if ((addr[1] & 0xc0) != 0x80)
        return 0;

    return 1;
}

int
netsnmp_access_scopezone_container_arch_load(netsnmp_container *container,
                                             u_int load_flags)
{
#ifdef NETSNMP_ENABLE_IPV6
    netsnmp_container *ipaddr;
    netsnmp_ipaddress_entry *ia;
    oid *seen_if = NULL;
    int seen_count;
    int seen_capacity;
    int idx_offset;
    int i;

    (void)load_flags;

    if (!container) {
        snmp_log(LOG_ERR, "no container specified/found for access_scopezone_\n");
        return -1;
    }

    ipaddr = netsnmp_access_ipaddress_container_load(NULL,
                NETSNMP_ACCESS_IPADDRESS_LOAD_IPV6_ONLY);
    if (!ipaddr)
        return -2;

    seen_capacity = 64;
    seen_if = malloc(seen_capacity * sizeof(*seen_if));
    seen_count = 0;
    idx_offset = 0;

    if (!seen_if) {
        netsnmp_access_ipaddress_container_free(
            ipaddr, NETSNMP_ACCESS_IPADDRESS_FREE_NOFLAGS);
        return -3;
    }

    ia = (netsnmp_ipaddress_entry *)CONTAINER_FIRST(ipaddr);
    while (ia) {
        int duplicate;
        netsnmp_v6scopezone_entry *entry;

        if (!_is_link_local_v6((const u_char *)ia->ia_address,
                               ia->ia_address_len)) {
            ia = (netsnmp_ipaddress_entry *)CONTAINER_NEXT(ipaddr, ia);
            continue;
        }

        duplicate = 0;
        for (i = 0; i < seen_count; i++) {
            if (seen_if[i] == ia->if_index) {
                duplicate = 1;
                break;
            }
        }
        if (duplicate) {
            ia = (netsnmp_ipaddress_entry *)CONTAINER_NEXT(ipaddr, ia);
            continue;
        }

        if (seen_count >= seen_capacity) {
            int new_cap = seen_capacity * 2;
            oid *tmp = realloc(seen_if, new_cap * sizeof(*tmp));
            if (tmp) {
                seen_if = tmp;
                seen_capacity = new_cap;
            }
        }
        if (seen_count < seen_capacity)
            seen_if[seen_count++] = ia->if_index;

        entry = netsnmp_access_scopezone_entry_create();
        if (!entry) {
            free(seen_if);
            netsnmp_access_ipaddress_container_free(
                ipaddr, NETSNMP_ACCESS_IPADDRESS_FREE_NOFLAGS);
            return -3;
        }

        entry->ns_scopezone_index = ++idx_offset;
        entry->index = ia->if_index;
        entry->scopezone_linklocal = (int)ia->if_index;

        if (CONTAINER_INSERT(container, entry) < 0)
            netsnmp_access_scopezone_entry_free(entry);

        ia = (netsnmp_ipaddress_entry *)CONTAINER_NEXT(ipaddr, ia);
    }

    free(seen_if);
    netsnmp_access_ipaddress_container_free(
        ipaddr, NETSNMP_ACCESS_IPADDRESS_FREE_NOFLAGS);

    return 0;
#else
    (void)container;
    (void)load_flags;
    return 0;
#endif
}
