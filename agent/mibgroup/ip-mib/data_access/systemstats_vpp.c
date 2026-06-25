/*
 * systemstats_vpp.c -- VPP-backed IP system/per-interface stats.
 *
 * Replaces systemstats_linux.c for --with-vpp builds.
 *
 * VPP exposes per-interface RX/TX packet/byte counters via the stats segment.
 * This module aggregates them into the ipSystemStatsTable (global) and
 * ipIfStatsTable (per-interface) entries.
 *
 * Note: VPP does not expose fine-grained IP-layer statistics (header errors,
 * address errors, reassembly counts, etc.) that Linux provides through
 * /proc/net/snmp.  Those columns will be reported as 0/unavailable.
 */

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-features.h>
#include <net-snmp/net-snmp-includes.h>

#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <net-snmp/data_access/ipstats.h>
#include <net-snmp/data_access/systemstats.h>

#include "ip-mib/data_access/systemstats_private.h"

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

/* Shared VPP helpers */
#include "if-mib/data_access/interface_vpp.h"

/* Forward declaration */
static int _read_simple_counter(const char *path, uint64_t *out,
                                uint32_t max_sw_if);

/*
 * Internal helpers
 * -----------------------------------------------------------*/

/*
 * Load ipSystemStatsTable -- one entry per IP version with global counters.
 */
static int
_systemstats_load_global(netsnmp_container *container, int ip_version)
{
    netsnmp_systemstats_entry *entry;
    vpp_if_counters_t *counters = NULL;
    int iface_count;
    uint32_t max_sw_if;
    uint32_t i;
    uint64_t total_rx_pkts = 0, total_rx_bytes = 0;
    uint64_t total_tx_pkts = 0, total_tx_bytes = 0;
    uint64_t total_ip_rx = 0;
    uint64_t *ip_rx = NULL;
    const char *rx_path;

    /* Authoritative interface count from VPP (no hard-coded bound). */
    iface_count = vpp_stats_iface_count();
    if (iface_count < 0)
        return -2;
    if (iface_count == 0)
        return 0; /* no interfaces yet -- valid, nothing to report */
    max_sw_if = (uint32_t)(iface_count - 1); /* highest sw_if_index */

    counters = calloc(max_sw_if + 1, sizeof(*counters));
    if (!counters)
        return -3;

    if (vpp_stats_read_counters(max_sw_if, counters) < 0) {
        free(counters);
        return -2;
    }

    /* Read IP-version-specific rx counter for InReceives */
    ip_rx = calloc(max_sw_if + 1, sizeof(*ip_rx));
    rx_path = (ip_version == 1) ? "/if/ip4" : "/if/ip6";
    if (ip_rx)
        _read_simple_counter(rx_path, ip_rx, max_sw_if);

    /* Aggregate across all interfaces */
    for (i = 0; i <= max_sw_if; i++) {
        total_rx_pkts  += counters[i].rx_packets;
        total_rx_bytes += counters[i].rx_bytes;
        total_tx_pkts  += counters[i].tx_packets;
        total_tx_bytes += counters[i].tx_bytes;
        if (ip_rx)
            total_ip_rx += ip_rx[i];
    }
    free(counters);
    free(ip_rx);

    /* Use IP-version-specific rx if available, else fall back to total */
    total_rx_pkts = total_ip_rx ? total_ip_rx : total_rx_pkts;

    entry = netsnmp_access_systemstats_entry_create(ip_version, 0,
                                                    "ipSystemStatsTable");
    if (!entry)
        return -3;

    /* Populate available counters */
    entry->stats.HCInReceives.low  = total_rx_pkts  & 0xffffffff;
    entry->stats.HCInReceives.high = total_rx_pkts  >> 32;
    entry->stats.columnAvail[IPSYSTEMSTATSTABLE_HCINRECEIVES] = 1;

    entry->stats.HCInOctets.low  = total_rx_bytes & 0xffffffff;
    entry->stats.HCInOctets.high = total_rx_bytes >> 32;
    entry->stats.columnAvail[IPSYSTEMSTATSTABLE_HCINOCTETS] = 1;

    entry->stats.HCOutTransmits.low  = total_tx_pkts  & 0xffffffff;
    entry->stats.HCOutTransmits.high = total_tx_pkts  >> 32;
    entry->stats.columnAvail[IPSYSTEMSTATSTABLE_HCOUTTRANSMITS] = 1;

    entry->stats.HCOutOctets.low  = total_tx_bytes & 0xffffffff;
    entry->stats.HCOutOctets.high = total_tx_bytes >> 32;
    entry->stats.columnAvail[IPSYSTEMSTATSTABLE_HCOUTOCTETS] = 1;

    entry->stats.HCOutRequests.low  = total_tx_pkts  & 0xffffffff;
    entry->stats.HCOutRequests.high = total_tx_pkts  >> 32;
    entry->stats.columnAvail[IPSYSTEMSTATSTABLE_HCOUTREQUESTS] = 1;

    entry->stats.HCInDelivers.low  = total_rx_pkts  & 0xffffffff;
    entry->stats.HCInDelivers.high = total_rx_pkts  >> 32;
    entry->stats.columnAvail[IPSYSTEMSTATSTABLE_HCINDELIVERS] = 1;

    if (CONTAINER_INSERT(container, entry) != 0) {
        netsnmp_access_systemstats_entry_free(entry);
        return -3;
    }

    return 0;
}

/*
 * Read a simple counter vector (per sw_if_index) from the stats segment.
 * Returns 0 on success, -1 on error.
 */
static int
_read_simple_counter(const char *path, uint64_t *out, uint32_t max_sw_if)
{
    uint8_t **patterns = NULL;
    uint32_t *stat_ids = NULL;
    stat_segment_data_t *data = NULL;
    uint32_t n_stats, sw_if;
    int nthreads, t, vlen;

    memset(out, 0, sizeof(*out) * (max_sw_if + 1));

    patterns = stat_segment_string_vector(patterns, path);
    stat_ids = stat_segment_ls(patterns);
    vpp_stats_free_patterns(patterns);

    if (!stat_ids)
        return -1;

    n_stats = stat_segment_vec_len(stat_ids);
    if (n_stats == 0) {
        stat_segment_vec_free(stat_ids);
        return -1;
    }

    data = stat_segment_dump(stat_ids);
    stat_segment_vec_free(stat_ids);
    if (!data)
        return -1;

    /* Sum across worker threads for each sw_if_index */
    if (data[0].type == STAT_DIR_TYPE_COUNTER_VECTOR_SIMPLE) {
        nthreads = stat_segment_vec_len(data[0].simple_counter_vec);
        for (t = 0; t < nthreads; t++) {
            counter_t *vec = data[0].simple_counter_vec[t];
            if (!vec)
                continue;
            vlen = stat_segment_vec_len(vec);
            for (sw_if = 0; sw_if <= max_sw_if && (int)sw_if < vlen; sw_if++)
                out[sw_if] += vec[sw_if];
        }
    }

    stat_segment_data_free(data);
    return 0;
}

/*
 * Load ipIfStatsTable -- one entry per IP version per interface.
 *
 * Uses /if/ip4 or /if/ip6 for InReceives (per-IP-version rx counter)
 * and /if/tx for OutTransmits (VPP doesn't split tx by IP version).
 */
static int
_systemstats_load_iftable(netsnmp_container *container, int ip_version)
{
    netsnmp_systemstats_entry *entry;
    vpp_if_counters_t *counters = NULL;
    uint64_t *ip_rx = NULL;
    int iface_count;
    uint32_t max_sw_if;
    uint32_t i;
    const char *rx_path;

    /* Authoritative interface count from VPP (no hard-coded bound). */
    iface_count = vpp_stats_iface_count();
    if (iface_count < 0)
        return -2;
    if (iface_count == 0)
        return 0; /* no interfaces yet -- valid, nothing to report */
    max_sw_if = (uint32_t)(iface_count - 1); /* highest sw_if_index */

    counters = calloc(max_sw_if + 1, sizeof(*counters));
    ip_rx = calloc(max_sw_if + 1, sizeof(*ip_rx));
    if (!counters || !ip_rx) {
        free(counters);
        free(ip_rx);
        return -3;
    }

    /* Read generic per-interface tx counters */
    if (vpp_stats_read_counters(max_sw_if, counters) < 0) {
        free(counters);
        free(ip_rx);
        return -2;
    }

    /* Read IP-version-specific rx counter */
    rx_path = (ip_version == 1) ? "/if/ip4" : "/if/ip6";
    _read_simple_counter(rx_path, ip_rx, max_sw_if);
    /* Non-fatal if this fails — ip_rx stays zero */

    for (i = 0; i <= max_sw_if; i++) {
        const vpp_if_counters_t *c = &counters[i];
        uint64_t in_pkts = ip_rx[i]; /* per-IP-version rx count */

        /* Skip interfaces with no traffic at all */
        if (c->rx_packets == 0 && c->tx_packets == 0 && in_pkts == 0)
            continue;

        /* SNMP ifIndex = sw_if_index + 1 */
        entry = netsnmp_access_systemstats_entry_create(ip_version, i + 1,
                                                        "ipIfStatsTable");
        if (!entry)
            continue;

        /* InReceives: use IP-version-specific counter */
        entry->stats.HCInReceives.low  = in_pkts & 0xffffffff;
        entry->stats.HCInReceives.high = in_pkts >> 32;
        entry->stats.columnAvail[IPSYSTEMSTATSTABLE_HCINRECEIVES] = 1;

        /* InOctets: not split by IP version; use total rx bytes */
        entry->stats.HCInOctets.low  = c->rx_bytes & 0xffffffff;
        entry->stats.HCInOctets.high = c->rx_bytes >> 32;
        entry->stats.columnAvail[IPSYSTEMSTATSTABLE_HCINOCTETS] = 1;

        entry->stats.HCOutTransmits.low  = c->tx_packets & 0xffffffff;
        entry->stats.HCOutTransmits.high = c->tx_packets >> 32;
        entry->stats.columnAvail[IPSYSTEMSTATSTABLE_HCOUTTRANSMITS] = 1;

        entry->stats.HCOutOctets.low  = c->tx_bytes & 0xffffffff;
        entry->stats.HCOutOctets.high = c->tx_bytes >> 32;
        entry->stats.columnAvail[IPSYSTEMSTATSTABLE_HCOUTOCTETS] = 1;

        entry->stats.HCOutRequests.low  = c->tx_packets & 0xffffffff;
        entry->stats.HCOutRequests.high = c->tx_packets >> 32;
        entry->stats.columnAvail[IPSYSTEMSTATSTABLE_HCOUTREQUESTS] = 1;

        /* InDelivers: same as InReceives for a router */
        entry->stats.HCInDelivers.low  = in_pkts & 0xffffffff;
        entry->stats.HCInDelivers.high = in_pkts >> 32;
        entry->stats.columnAvail[IPSYSTEMSTATSTABLE_HCINDELIVERS] = 1;

        if (CONTAINER_INSERT(container, entry) != 0) {
            netsnmp_access_systemstats_entry_free(entry);
            /* continue with remaining interfaces */
        }
    }

    free(counters);
    free(ip_rx);
    return 0;
}

/*
 * Public arch functions (systemstats_private.h)
 * -----------------------------------------------------------*/

void
netsnmp_access_systemstats_arch_init(void)
{
    /* Nothing to initialize -- VAPI connection is lazy. */
}

int
netsnmp_access_systemstats_container_arch_load(netsnmp_container *container,
                                               u_int load_flags)
{
    int rc1, rc2 = 0;

    DEBUGMSGTL(("access:systemstats:vpp:container",
                "load (flags %x)\n", load_flags));


    if (!container) {
        snmp_log(LOG_ERR, "systemstats_vpp: no container\n");
        return -1;
    }

    /*
     * systemstats only uses the VPP stats segment (via vpp_stats_read_counters),
     * not the VAPI message API.  Do NOT call vapi_connect_once() here -- an idle
     * VAPI session will be killed by VPP keepalive timeouts before the interface
     * module gets a chance to use it.
     */

    if (load_flags & NETSNMP_ACCESS_SYSTEMSTATS_LOAD_IFTABLE) {
        /* ipIfStatsTable */
        rc1 = _systemstats_load_iftable(container, 1 /* IPv4 */);
#if defined(NETSNMP_ENABLE_IPV6)
        rc2 = _systemstats_load_iftable(container, 2 /* IPv6 */);
#endif
    } else {
        /* ipSystemStatsTable */
        rc1 = _systemstats_load_global(container, 1 /* IPv4 */);
#if defined(NETSNMP_ENABLE_IPV6)
        rc2 = _systemstats_load_global(container, 2 /* IPv6 */);
#endif
    }

    /*
     * IPv4 result is authoritative.  An IPv6 failure is non-fatal (mirrors
     * route_vpp.c / ipaddress_vpp.c): the IPv4 table is still useful and we
     * must not abort the whole cache load just because IPv6 is unavailable.
     */
    if (rc1 < 0)
        return rc1;
    if (rc2 < 0)
        DEBUGMSGTL(("access:systemstats:vpp",
                    "IPv6 load failed (%d); reporting IPv4 results only\n",
                    rc2));
    return 0;
}
