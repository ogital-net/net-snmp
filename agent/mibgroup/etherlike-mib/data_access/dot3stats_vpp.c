/*
 * dot3stats_vpp.c -- VPP-backed dot3StatsTable data access layer.
 *
 * Provides dot3StatsTable_container_load_impl() using VPP stats-segment
 * counters.  Replaces dot3stats_linux.c for VPP dataplane builds.
 *
 * Counter mapping:
 *   dot3StatsFCSErrors            <- /if/rx-error  (all RX errors)
 *   dot3StatsInternalMacTxErrors  <- /if/tx-error
 *   dot3StatsInternalMacRxErrors  <- 0 (intentionally unused;
 *      /if/rx-miss is a no-buffer discard, not a MAC sublayer error.
 *      Per RFC 3635, this counter is for genuine internal MAC errors,
 *      which VPP does not expose as a separate stats-segment path.)
 *   dot3StatsFrameTooLongs        <- 0 (not exposed by VPP)
 *   dot3StatsDuplexStatus         <- fullDuplex (always, for DPDK NICs)
 */

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

/* VPP VAPI for interface enumeration */
#include <vapi/vapi.h>
#include <vapi/interface.api.vapi.h>

/* Shared VPP helpers */
#include "if-mib/data_access/interface_vpp.h"

/* Parent table headers */
#include "etherlike-mib/dot3StatsTable/dot3StatsTable.h"
#include "etherlike-mib/dot3StatsTable/dot3StatsTable_data_access.h"

/* dot3StatsDuplexStatus values from EtherLike-MIB */
#define DOT3_DUPLEX_UNKNOWN    1
#define DOT3_DUPLEX_HALFDUPLEX 2
#define DOT3_DUPLEX_FULLDUPLEX 3

/*
 * VAPI callback context for sw_interface_dump
 */

typedef struct {
    netsnmp_container *container;
    int                error;
} dot3_dump_ctx_t;

/*
 * Read stats for a single interface and insert into container
 */

static void
_add_interface(netsnmp_container *container, uint32_t sw_if_index,
               uint64_t rx_error, uint64_t tx_error)
{
    dot3StatsTable_rowreq_ctx *row;
    int rc;
    long if_index = (long)(sw_if_index + 1);

    row = dot3StatsTable_allocate_rowreq_ctx(NULL);
    if (!row)
        return;

    dot3StatsTable_indexes_set(row, if_index);

    row->data.dot3StatsFCSErrors = (u_long)rx_error;
    row->data.dot3StatsInternalMacTransmitErrors = (u_long)tx_error;
    /*
     * dot3StatsInternalMacReceiveErrors: VPP does not expose a separate
     * per-interface MAC sublayer receive error counter.  /if/rx-miss is a
     * no-buffer discard (not a MAC error) -- it is intentionally not used
     * here, matching the rationale documented in interface_vpp.h.
     */
    row->data.dot3StatsInternalMacReceiveErrors = 0;
    row->data.dot3StatsFrameTooLongs = 0;
    row->data.dot3StatsDeferredTransmissions = 0;
    row->data.dot3StatsSingleCollisionFrames = 0;
    row->data.dot3StatsMultipleCollisionFrames = 0;
    row->data.dot3StatsLateCollisions = 0;
    row->data.dot3StatsExcessiveCollisions = 0;
    row->data.dot3StatsAlignmentErrors = 0;
    row->data.dot3StatsSQETestErrors = 0;
    row->data.dot3StatsCarrierSenseErrors = 0;
    row->data.dot3StatsSymbolErrors = 0;
    row->data.dot3StatsDuplexStatus = DOT3_DUPLEX_FULLDUPLEX;

    row->column_exists_flags =
        COLUMN_DOT3STATSINDEX_FLAG |
        COLUMN_DOT3STATSFCSERRORS_FLAG |
        COLUMN_DOT3STATSINTERNALMACTRANSMITERRORS_FLAG |
        COLUMN_DOT3STATSINTERNALMACRECEIVEERRORS_FLAG |
        COLUMN_DOT3STATSFRAMETOOLONGS_FLAG |
        COLUMN_DOT3STATSDEFERREDTRANSMISSIONS_FLAG |
        COLUMN_DOT3STATSSINGLECOLLISIONFRAMES_FLAG |
        COLUMN_DOT3STATSMULTIPLECOLLISIONFRAMES_FLAG |
        COLUMN_DOT3STATSLATECOLLISIONS_FLAG |
        COLUMN_DOT3STATSEXCESSIVECOLLISIONS_FLAG |
        COLUMN_DOT3STATSALIGNMENTERRORS_FLAG |
        COLUMN_DOT3STATSSQETESTERRORS_FLAG |
        COLUMN_DOT3STATSCARRIERSENSEERRORS_FLAG |
        COLUMN_DOT3STATSSYMBOLERRORS_FLAG |
        COLUMN_DOT3STATSDUPLEXSTATUS_FLAG;

    rc = CONTAINER_INSERT(container, row);
    if (rc != 0)
        dot3StatsTable_release_rowreq_ctx(row);
}

/*
 * Main entry point: called from dot3StatsTable_data_access.c
 */

int
dot3StatsTable_container_load_impl(netsnmp_container *container)
{
    uint8_t **patterns = NULL;
    uint32_t *stat_ids = NULL;
    stat_segment_data_t *data = NULL;
    uint32_t n_stats;
    unsigned i;
    int max_sw_if = -1;

    /* indices for the stats we care about */
    int idx_rxerr = -1, idx_txerr = -1;

    DEBUGMSGTL(("access:dot3StatsTable:vpp",
                "dot3StatsTable_container_load_impl called\n"));

    /* Ensure stats connection is up */
    if (vpp_stats_connect_once() != 0) {
        DEBUGMSGTL(("access:dot3StatsTable:vpp",
                    "stats segment not available\n"));
        return MFD_ERROR;
    }

    /* Fetch the two error counters we need */
    patterns = stat_segment_string_vector(NULL, "/if/rx-error");
    patterns = stat_segment_string_vector(patterns, "/if/tx-error");

    stat_ids = stat_segment_ls(patterns);
    vpp_stats_free_patterns(patterns);
    if (!stat_ids) {
        DEBUGMSGTL(("access:dot3StatsTable:vpp",
                    "stat_segment_ls returned nothing\n"));
        return MFD_SUCCESS;
    }

    n_stats = stat_segment_vec_len(stat_ids);
    data = stat_segment_dump(stat_ids);
    stat_segment_vec_free(stat_ids);
    if (!data) {
        DEBUGMSGTL(("access:dot3StatsTable:vpp",
                    "stat_segment_dump failed\n"));
        return MFD_SUCCESS;
    }

    /* Identify each stat entry and determine max interface count */
    for (i = 0; i < n_stats; i++) {
        if (!data[i].name)
            continue;
        if (strcmp(data[i].name, "/if/rx-error") == 0)
            idx_rxerr = i;
        else if (strcmp(data[i].name, "/if/tx-error") == 0)
            idx_txerr = i;

        /* Determine vector length (= number of interfaces) from any entry */
        if (data[i].type == STAT_DIR_TYPE_COUNTER_VECTOR_SIMPLE &&
            data[i].simple_counter_vec) {
            int nthreads = stat_segment_vec_len(data[i].simple_counter_vec);
            if (nthreads > 0 && data[i].simple_counter_vec[0]) {
                int vlen = stat_segment_vec_len(data[i].simple_counter_vec[0]);
                if (vlen - 1 > max_sw_if)
                    max_sw_if = vlen - 1;
            }
        }
    }

    if (max_sw_if < 0) {
        stat_segment_data_free(data);
        return MFD_SUCCESS;
    }

    /* Create a row for each interface (skip local0 = sw_if_index 0) */
    for (i = 1; (int)i <= max_sw_if; i++) {
        uint64_t rx_error = 0, tx_error = 0;

        if (idx_rxerr >= 0)
            rx_error = vpp_sum_simple(&data[idx_rxerr], i);
        if (idx_txerr >= 0)
            tx_error = vpp_sum_simple(&data[idx_txerr], i);

        _add_interface(container, i, rx_error, tx_error);
    }

    stat_segment_data_free(data);

    DEBUGMSGTL(("access:dot3StatsTable:vpp",
                "loaded %d interfaces\n", max_sw_if));
    return MFD_SUCCESS;
}
