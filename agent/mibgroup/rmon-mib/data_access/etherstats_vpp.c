/*
 * etherstats_vpp.c -- VPP-backed etherStatsTable data access layer.
 *
 * Provides etherStatsTable_container_load_vpp() using VPP stats-segment
 * counters.  Replaces etherstats_linux.c for VPP dataplane builds.
 *
 * Counter mapping:
 *   etherStatsOctets         <- /if/rx bytes (combined counter)
 *   etherStatsPkts           <- /if/rx packets (combined counter)
 *   etherStatsBroadcastPkts  <- /if/rx-broadcast packets (combined)
 *   etherStatsMulticastPkts  <- /if/rx-multicast packets (combined)
 *   etherStatsDropEvents     <- /if/drops (simple counter)
 *   etherStatsCRCAlignErrors <- /if/rx-error (simple counter)
 *   etherStatsUndersizePkts  <- 0 (not exposed)
 *   etherStatsOversizePkts   <- 0 (not exposed)
 *   etherStatsFragments      <- 0 (not exposed)
 *   etherStatsJabbers        <- 0 (not exposed)
 *   etherStatsCollisions     <- 0 (full duplex, N/A)
 *
 * The dataSource OID for each row is ifIndex.<sw_if_index+1>.
 */

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

/* Shared VPP helpers */
#include "if-mib/data_access/interface_vpp.h"

/* Parent table headers */
#include "rmon-mib/etherStatsTable/etherStatsTable.h"
#include "rmon-mib/etherStatsTable/etherStatsTable_data_access.h"

/* ifEntry OID prefix: 1.3.6.1.2.1.2.2.1.1 */
static const oid ifIndex_oid[] = {1, 3, 6, 1, 2, 1, 2, 2, 1, 1};
#define IFINDEX_OID_LEN  (sizeof(ifIndex_oid) / sizeof(oid))

/*
 * Build one row and insert into the container
 */

static void
_add_interface(netsnmp_container *container, uint32_t sw_if_index,
               vlib_counter_t rx, vlib_counter_t rx_mcast,
               vlib_counter_t rx_bcast,
               uint64_t drops, uint64_t rx_error)
{
    etherStatsTable_rowreq_ctx *row;
    long if_index = (long)(sw_if_index + 1);
    int rc;

    row = etherStatsTable_allocate_rowreq_ctx(NULL);
    if (!row)
        return;

    if (MFD_SUCCESS != etherStatsTable_indexes_set(row, if_index)) {
        etherStatsTable_release_rowreq_ctx(row);
        return;
    }

    memset(&row->data, 0, sizeof(row->data));

    /* dataSource = ifIndex OID for this interface */
    memcpy(row->data.etherStatsDataSource, ifIndex_oid,
           IFINDEX_OID_LEN * sizeof(oid));
    row->data.etherStatsDataSource[IFINDEX_OID_LEN] = (oid)if_index;
    row->data.etherStatsDataSource_len = IFINDEX_OID_LEN + 1;

    row->data.etherStatsDropEvents       = (u_long)drops;
    row->data.etherStatsOctets           = (u_long)rx.bytes;
    row->data.etherStatsPkts             = (u_long)rx.packets;
    row->data.etherStatsBroadcastPkts    = (u_long)rx_bcast.packets;
    row->data.etherStatsMulticastPkts    = (u_long)rx_mcast.packets;
    row->data.etherStatsCRCAlignErrors   = (u_long)rx_error;
    row->data.etherStatsUndersizePkts    = 0;
    row->data.etherStatsOversizePkts     = 0;
    row->data.etherStatsFragments        = 0;
    row->data.etherStatsJabbers          = 0;
    row->data.etherStatsCollisions       = 0;
    row->data.etherStatsPkts64Octets     = 0;
    row->data.etherStatsPkts65to127Octets    = 0;
    row->data.etherStatsPkts128to255Octets   = 0;
    row->data.etherStatsPkts256to511Octets   = 0;
    row->data.etherStatsPkts512to1023Octets  = 0;
    row->data.etherStatsPkts1024to1518Octets = 0;
    row->data.etherStatsStatus           = 1; /* valid(1) */
    strlcpy(row->data.etherStatsOwner, "VPP", sizeof(row->data.etherStatsOwner));
    row->data.etherStatsOwner_len = 3;

    row->column_exists_flags =
        COLUMN_ETHERSTATSINDEX_FLAG |
        COLUMN_ETHERSTATSDATASOURCE_FLAG |
        COLUMN_ETHERSTATSDROPEVENTS_FLAG |
        COLUMN_ETHERSTATSOCTETS_FLAG |
        COLUMN_ETHERSTATSPKTS_FLAG |
        COLUMN_ETHERSTATSBROADCASTPKTS_FLAG |
        COLUMN_ETHERSTATSMULTICASTPKTS_FLAG |
        COLUMN_ETHERSTATSCRCALIGNERRORS_FLAG |
        COLUMN_ETHERSTATSUNDERSIZEPKTS_FLAG |
        COLUMN_ETHERSTATSOVERSIZEPKTS_FLAG |
        COLUMN_ETHERSTATSFRAGMENTS_FLAG |
        COLUMN_ETHERSTATSJABBERS_FLAG |
        COLUMN_ETHERSTATSCOLLISIONS_FLAG |
        COLUMN_ETHERSTATSPKTS64OCTETS_FLAG |
        COLUMN_ETHERSTATSPKTS65TO127OCTETS_FLAG |
        COLUMN_ETHERSTATSPKTS128TO255OCTETS_FLAG |
        COLUMN_ETHERSTATSPKTS256TO511OCTETS_FLAG |
        COLUMN_ETHERSTATSPKTS512TO1023OCTETS_FLAG |
        COLUMN_ETHERSTATSPKTS1024TO1518OCTETS_FLAG |
        COLUMN_ETHERSTATSOWNER_FLAG |
        COLUMN_ETHERSTATSSTATUS_FLAG;

    rc = CONTAINER_INSERT(container, row);
    if (rc != 0)
        etherStatsTable_release_rowreq_ctx(row);
}

/*
 * Main entry point: called from etherStatsTable_data_access.c
 */

int
etherStatsTable_container_load_vpp(netsnmp_container *container)
{
    uint8_t **patterns = NULL;
    uint32_t *stat_ids = NULL;
    stat_segment_data_t *data = NULL;
    uint32_t n_stats;
    unsigned i;
    int max_sw_if = -1;

    /* indices into the data[] array */
    int idx_rx = -1, idx_rx_mcast = -1, idx_rx_bcast = -1;
    int idx_drops = -1, idx_rxerr = -1;

    DEBUGMSGTL(("access:etherStatsTable:vpp",
                "etherStatsTable_container_load_vpp called\n"));

    /* Ensure stats connection is up */
    if (vpp_stats_connect_once() != 0) {
        DEBUGMSGTL(("access:etherStatsTable:vpp",
                    "stats segment not available\n"));
        return MFD_RESOURCE_UNAVAILABLE;
    }

    /* Fetch counters */
    patterns = stat_segment_string_vector(NULL, "/if/rx");
    patterns = stat_segment_string_vector(patterns, "/if/rx-multicast");
    patterns = stat_segment_string_vector(patterns, "/if/rx-broadcast");
    patterns = stat_segment_string_vector(patterns, "/if/drops");
    patterns = stat_segment_string_vector(patterns, "/if/rx-error");

    stat_ids = stat_segment_ls(patterns);
    vpp_stats_free_patterns(patterns);
    if (!stat_ids) {
        DEBUGMSGTL(("access:etherStatsTable:vpp",
                    "stat_segment_ls returned nothing\n"));
        return MFD_SUCCESS; /* no interfaces = no rows */
    }

    n_stats = stat_segment_vec_len(stat_ids);
    data = stat_segment_dump(stat_ids);
    stat_segment_vec_free(stat_ids);
    if (!data) {
        DEBUGMSGTL(("access:etherStatsTable:vpp",
                    "stat_segment_dump failed\n"));
        return MFD_SUCCESS;
    }

    /* Identify each stat entry */
    for (i = 0; i < n_stats; i++) {
        if (!data[i].name)
            continue;
        if (strcmp(data[i].name, "/if/rx") == 0)
            idx_rx = i;
        else if (strcmp(data[i].name, "/if/rx-multicast") == 0)
            idx_rx_mcast = i;
        else if (strcmp(data[i].name, "/if/rx-broadcast") == 0)
            idx_rx_bcast = i;
        else if (strcmp(data[i].name, "/if/drops") == 0)
            idx_drops = i;
        else if (strcmp(data[i].name, "/if/rx-error") == 0)
            idx_rxerr = i;
    }

    /* Determine max interface index from /if/rx combined counter */
    if (idx_rx >= 0 && data[idx_rx].type == STAT_DIR_TYPE_COUNTER_VECTOR_COMBINED
        && data[idx_rx].combined_counter_vec) {
        int nthreads = stat_segment_vec_len(data[idx_rx].combined_counter_vec);
        if (nthreads > 0 && data[idx_rx].combined_counter_vec[0]) {
            int vlen = stat_segment_vec_len(data[idx_rx].combined_counter_vec[0]);
            max_sw_if = vlen - 1;
        }
    }

    if (max_sw_if < 1) {
        stat_segment_data_free(data);
        return MFD_SUCCESS;
    }

    /* Create a row for each interface (skip local0 = sw_if_index 0) */
    for (i = 1; (int)i <= max_sw_if; i++) {
        vlib_counter_t rx = {0, 0}, rx_mcast = {0, 0}, rx_bcast = {0, 0};
        uint64_t drops = 0, rx_error = 0;

        if (idx_rx >= 0)
            rx = vpp_sum_combined(&data[idx_rx], i);
        if (idx_rx_mcast >= 0)
            rx_mcast = vpp_sum_combined(&data[idx_rx_mcast], i);
        if (idx_rx_bcast >= 0)
            rx_bcast = vpp_sum_combined(&data[idx_rx_bcast], i);
        if (idx_drops >= 0)
            drops = vpp_sum_simple(&data[idx_drops], i);
        if (idx_rxerr >= 0)
            rx_error = vpp_sum_simple(&data[idx_rxerr], i);

        _add_interface(container, i, rx, rx_mcast, rx_bcast, drops, rx_error);
    }

    stat_segment_data_free(data);

    DEBUGMSGTL(("access:etherStatsTable:vpp",
                "loaded %d interfaces\n", max_sw_if));
    return MFD_SUCCESS;
}
