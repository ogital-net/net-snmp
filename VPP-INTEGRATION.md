# VPP Data-Plane Integration for net-snmp

This document describes the VPP (Vector Packet Processing) integration added to
net-snmp for the latigo-gw appliance, where all data-plane interfaces are owned
by VPP rather than the Linux kernel.

## What Works

### IF-MIB (ifTable / ifXTable)
All VPP interfaces are enumerated via `sw_interface_dump` and exposed through
standard SNMP interface tables:

- **ifIndex**: VPP `sw_if_index + 1` (1-based per RFC 2863)
- **ifDescr / ifName**: VPP interface name (e.g. `GigabitEthernet2/0/0`, `tap4096`)
- **ifType**: Mapped from VPP type + name prefix to IANA ifType
- **ifMtu**: From `link_mtu`
- **ifSpeed / ifHighSpeed**: From `link_speed` (kbps in VPP 26.x, converted to bps)
- **ifPhysAddress**: L2 MAC address
- **ifAdminStatus / ifOperStatus**: From VPP flags; admin status is writable via `sw_interface_set_flags`
- **ifAlias**: From VPP tag field (`sw_interface_details.tag[64]`); writable via `sw_interface_tag_add_del`
- **ifHCInOctets, ifHCOutOctets, etc.**: 64-bit counters from VPP stats segment

### ipSystemStatsTable
Aggregated IP statistics derived from the VPP stats segment counters
(`/if/rx`, `/if/tx`). Reports `HCInReceives`, `HCInOctets`, `HCOutTransmits`,
`HCOutOctets`, etc. for both IPv4 and IPv6.

> Note: Uses `/if/ip4` and `/if/ip6` counters to properly split
> InReceives/InDelivers by address family for both the global
> ipSystemStatsTable and per-interface ipIfStatsTable.

### ipAddressTable
IP addresses assigned to VPP interfaces via `ip_address_dump` (per-interface
enumeration since VPP 26.06 does not support wildcard sw_if_index).

### inetCidrRouteTable (IP-FORWARD-MIB)
IPv4 and IPv6 routes from `ip_route_dump`. Read-only (SET returns error).

### inetNetToMediaTable (ARP/ND)
ARP and IPv6 neighbor entries from `ip_neighbor_dump`.

### NAT Session Health — NATV2-MIB (RFC 7659)
NAT44-ED session and translation statistics from VPP stats segment:

- **natv2GlobalActiveSessions**: Current active NAT sessions (`/nat44-ed/total-sessions`)
- **natv2GlobalMaxSessions**: Maximum configured sessions (`/nat44-ed/max-cfg-sessions`)
- **natv2GlobalInTranslates**: Total inside-to-outside translations
- **natv2GlobalOutTranslates**: Total outside-to-inside translations
- **natv2GlobalDrops**: Total NAT drops (session exhaustion, port exhaustion)
- **natv2ProtocolStatsTable**: Per-protocol (TCP/UDP/ICMP/other) translation counts

Key health metric: `natv2GlobalActiveSessions / natv2GlobalMaxSessions` gives
session table utilization percentage for proactive alerting.

### ARP/ND Statistics — VPP-DATAPLANE-MIB (private)
ARP and IPv6 Neighbor Discovery counters from VPP stats segment, useful for
detecting broadcast storms and resolution failures:

- **vppArpRxRequests**: ARP requests received (spike = storm/scan)
- **vppArpRxReplies**: ARP replies received
- **vppArpRxGratuitous**: Gratuitous ARP received (spike = IP conflict/failover)
- **vppArpTxRequests/Replies/Gratuitous**: Outbound ARP counters
- **vppNdRx/TxRequests/Replies/Gratuitous**: IPv6 ND equivalents

OID base: `1.3.6.1.4.1.8072.9999.9696.1` (netSnmpExperimental.9696.1)

### VPP Memory & Buffer Pool — VPP-DATAPLANE-MIB (private)
VPP internal memory and packet buffer statistics (does NOT replace
HOST-RESOURCES-MIB — host RAM/disk entries remain unchanged):

- **vppMainHeapTotal/Used/Free**: VPP heap in KB (~990 MB total on this system)
- **vppBufferPoolAvailable/Used/Cached**: Packet buffer counts

Key health metric: When `vppBufferPoolAvailable` approaches zero, VPP drops packets.
Alert on `vppMainHeapUsed / vppMainHeapTotal > 80%`.

OID base: `1.3.6.1.4.1.8072.9999.9696.2` (netSnmpExperimental.9696.2)

### Interface Error Counters — IF-MIB
Already part of standard ifTable, backed by VPP stats segment:

- **ifInErrors**: `/if/rx-error` per interface
- **ifOutErrors**: `/if/tx-error` per interface
- **ifInDiscards**: `/if/drops` per interface (packet drops)

### Route Table Size — IP-FORWARD-MIB
- **inetCidrRouteNumber**: Number of routes in VPP FIB (standard OID)

### ipDefaultRouterTable (IP-MIB)
Default gateway next-hops are now sourced from VPP route dump (table 0)
by selecting default routes (prefix length 0):

- **ipDefaultRouterAddressType/Address**: Next-hop from VPP path
- **ipDefaultRouterIfIndex**: VPP egress interface (`sw_if_index + 1`)
- **ipDefaultRouterLifetime/Preference**: exposed with stable defaults

### ipv6ScopeZoneIndexTable (IP-MIB)
Backed by VPP IPv6 addresses: each interface with a link-local address
(`fe80::/10`) gets a scope-zone entry.

Note: if no VPP link-local IPv6 addresses are configured, this table is empty.

### Build System
The `--with-vpp` configure option detects VPP headers and libraries,
defines `HAVE_VPP_DATAPLANE`, and links the required VPP libraries.

## What Doesn't Work (Yet)

All Tier 1 and Tier 2 MIBs described above are implemented. `dot3StatsTable`
(EtherLike-MIB) and `etherStatsTable` (RMON-MIB) are implemented in
`dot3stats_vpp.c` / `etherstats_vpp.c` but are only built when their MIB modules
are included via `--with-mib-modules` (they are not in the minimal default set).

## Architecture

### Files

| File | Purpose |
|------|---------|
| `agent/mibgroup/if-mib/data_access/interface_vpp.c` | IF-MIB backend: sw_interface_dump + stats segment counters |
| `agent/mibgroup/if-mib/data_access/interface_vpp.h` | Shared constants and types |
| `agent/mibgroup/ip-mib/data_access/ipaddress_vpp.c` | ipAddressTable: ip_address_dump |
| `agent/mibgroup/ip-mib/data_access/arp_vpp.c` | ARP/neighbor: ip_neighbor_dump |
| `agent/mibgroup/ip-mib/data_access/systemstats_vpp.c` | ipSystemStatsTable: stats segment aggregation |
| `agent/mibgroup/ip-mib/data_access/defaultrouter_vpp.c` | ipDefaultRouterTable: default routes from ip_route_dump |
| `agent/mibgroup/ip-mib/data_access/ipv6scopezone_vpp.c` | ipv6ScopeZoneIndexTable: link-local scope zones from VPP IPv6 addresses |
| `agent/mibgroup/ip-forward-mib/data_access/route_vpp.c` | Route table: ip_route_dump |
| `agent/mibgroup/nat-mib/nat_vpp.c` | NATV2-MIB: NAT session/protocol stats from stats segment |
| `agent/mibgroup/vpp-stats/vpp_stats.c` | ARP/ND counters + VPP memory/buffer pool stats |
| `mibs/NATV2-MIB.txt` | MIB definition for NATV2-MIB (RFC 7659 subset) |
| `mibs/VPP-DATAPLANE-MIB.txt` | MIB definition for ARP/ND stats and VPP memory |

### Shared State
- `g_vapi_ctx` — single VAPI context shared by all modules that need message API
- `g_stats_connected` — whether the stats segment is connected
- `vapi_connect_once()` — lazy-connect helper (defined in interface_vpp.c, extern'd by others)
- `vpp_stats_connect_once()` — lazy stats-segment connect; every stats-only
  module (systemstats, NAT, vpp-stats, dot3/etherstats) calls this itself
  rather than assuming another module connected first
- `vpp_stats_iface_count()` — authoritative interface count from VPP (length of
  the `/if/rx` counter vector). No module hard-codes an interface-count upper
  bound; the count is always queried from VPP.

### Build Wiring
The arch-backend swaps (interface/ipaddress/arp/route/etc.) are selected by
`HAVE_VPP_DATAPLANE` guards in the existing `data_access/*.h` selector headers.
The two private-MIB modules are wired in `agent/mibgroup/default_modules.h`:

```c
#ifdef HAVE_VPP_DATAPLANE
config_require(nat-mib/nat_vpp);
config_require(vpp-stats/vpp_stats);
config_add_mib(NATV2-MIB);
config_add_mib(VPP-DATAPLANE-MIB);
#endif
```

`default_modules.h` is always preprocessed by `configure` with the generated
config header in scope, so `HAVE_VPP_DATAPLANE` is honored and the modules'
`init_nat_vpp()` / `init_vpp_stats()` functions are auto-registered.

### VAPI Message ID Ownership
Each `DEFINE_VAPI_MSG_IDS_*_API_JSON` macro must appear in exactly one
translation unit:
- `INTERFACE_API` + `VPE_API` → `interface_vpp.c`
- `IP_API` → `ipaddress_vpp.c`
- `IP_NEIGHBOR_API` → `arp_vpp.c`

## Lessons Learned

### 1. VAPI is not reentrant — never call from inside a callback

The VAPI blocking-mode dispatch holds `vapi_producer_lock`. If a response
callback triggers another VAPI request (even indirectly through the net-snmp
framework), it deadlocks. This manifested when `local0` (sw_if_index=0) was
passed to `netsnmp_access_interface_entry_create()` — the framework treated
ifIndex=0 as "unknown" and called `netsnmp_arch_interface_index_find()`, which
issued a second `sw_interface_dump` from inside the first dump's callback.

**Rule**: Never pass ifIndex=0 to framework functions. Use `sw_if_index + 1`.

### 2. clib_mem_init() is required before using VPP vec operations

VPP's `stat_segment_string_vector()` internally uses `vec_add1()` which
requires the VPP heap allocator to be initialized. Without calling
`clib_mem_init(NULL, 64 << 20)` first, it segfaults.

**Rule**: Call `clib_mem_init()` once before any `stat_segment_*` vec operations.

### 3. Don't connect VAPI until you need it

VPP sends keepalive messages over the shared-memory API channel. If the client
doesn't respond (because net-snmp is busy loading MIB text files or doing other
init work), VPP marks the client as dead. With the connection then dead, the
next request would (in blocking mode) hang indefinitely — see lesson 8 for how
non-blocking mode bounds this with a timeout and triggers a reconnect.

**Rule**: Defer `vapi_connect_once()` to the first actual API call
(`container_load`), not to `init()`. Modules that only use the stats segment
(like systemstats) must not call `vapi_connect_once()` at all.

### 4. VPP stats paths changed in 26.x

The stats segment paths are `/if/rx`, `/if/tx`, `/if/drops`, `/if/rx-miss`,
`/if/tx-error`. Earlier VPP versions used `/interfaces/*`. Always verify with
a test program using `stat_segment_ls()` on a running VPP instance.

### 5. stat_segment and VAPI are independent connections

`stat_segment_connect()` opens a Unix socket to `/run/vpp/stats.sock` and maps
the stats shared memory. VAPI connects to `/run/vpp/api.sock` and maps the API
shared memory (`/dev/shm/vpe-api`). They don't interfere with each other and
can coexist, but each has its own initialization requirements.

### 6. net-snmp's interface framework calls index_find during cache init

The IF-MIB cache is populated during `init_ifTable()` (a startup callback),
not lazily on first request. This means your `container_load` WILL be called
during agent startup, so the VPP connection must work by that point.

### 7. autoconf quirks on minimal systems

If `autoconf`/`autoreconf` cannot be run (missing Perl `Autom4te` modules), you
must manually patch the generated `configure` script. Specifically, new
`--with-*` options need their names added to the `ac_user_opts` variable
(around line 1096 in the configure script).

### 8. Use non-blocking VAPI so timeouts actually work

VAPI **blocking** mode (`VAPI_MODE_BLOCKING`) has **no per-request timeout**.
Tracing the FD.io source: a blocking `vapi_*_dump()` ends in `vapi_dispatch()`
→ `vapi_dispatch_one_timedwait(ctx, 0)` → `vapi_recv(... SVM_Q_WAIT ...)` →
`svm_queue_sub()` with `SVM_Q_WAIT`, which is an unbounded `pthread_cond_wait()`.
If VPP wedges or dies *after* connect, the snmpd agent thread blocks **forever**.

We therefore connect with `VAPI_MODE_NONBLOCKING` and drive the dispatch loop
ourselves with a bounded deadline (the same pattern as the FRR dataplane plugin
in `latigo-gw/dplane-vpp`):

- Each dump's reply callback sets a `volatile bool done` flag on the
  end-of-dump sentinel (`is_last && !details`) — or on a transport error, or,
  for single-reply requests, when the reply arrives.
- `vapi_dump_dispatch(&done)` loops `vapi_dispatch_one_timedwait(ctx, 1s)`
  until `done` is set or `VPP_VAPI_REQUEST_TIMEOUT_S` (3s) elapses, then
  returns −1 on timeout.
- On timeout/error the caller calls `vapi_reset_connection()` (disconnect +
  free + NULL) so the next poll reconnects cleanly.

**Important**: the `wait_time` argument to `vapi_dispatch_one_timedwait()` is in
**seconds** (it is forwarded to `svm_queue_timedwait` as
`unix_time_now() + timeout`). In non-blocking mode the generated `vapi_*_dump()`
helper only *sends* — it returns `VAPI_OK` immediately and the caller **must**
pump the dispatch loop to collect replies.

Verified empirically: with no message queued, `vapi_dispatch_one_timedwait(ctx,1)`
returns `VAPI_EAGAIN` after exactly 1.0s; and `SIGSTOP`-ing VPP makes snmpd log
`VAPI dispatch timed out after 3s (VPP unresponsive)` and reconnect, instead of
hanging.

> The stats-segment modules (NAT, vpp-stats, systemstats, dot3/etherstats) are
> unaffected — they never use VAPI and `stat_segment_*` has its own timeout
> (`stat_segment_set_timeout()`).

## Build Instructions

```sh
./configure --with-vpp --with-defaults --disable-des \
    --with-out-transports="DTLSUDP TLSTCP" \
    --with-mib-modules="if-mib ip-mib ip-forward-mib"
make
```

Required packages: VPP 26.06 development headers and libraries
(`libvppinfra`, `libvapiclient`, `libvppapiclient`, `libvlibapi`,
`libvlibmemoryclient`, `libsvm`).

The `--disable-des` and `--with-out-transports` flags are needed on systems
using aws-lc instead of OpenSSL (aws-lc lacks DES and certain DTLS APIs).

## Testing

Start snmpd against a running VPP instance:

```sh
cat > /tmp/snmpd-test.conf << 'EOF'
rocommunity public 127.0.0.1
agentaddress udp:127.0.0.1:1611
EOF

export LD_LIBRARY_PATH="$PWD/snmplib/.libs:$PWD/agent/.libs:$PWD/agent/helpers/.libs"
export MIBDIRS="$PWD/mibs"
agent/.libs/snmpd -f -Lo -C -c /tmp/snmpd-test.conf
```

Walk interface table:
```sh
apps/.libs/snmpwalk -v2c -c public 127.0.0.1:1611 IF-MIB::ifDescr
apps/.libs/snmpwalk -v2c -c public 127.0.0.1:1611 IF-MIB::ifHCInOctets
apps/.libs/snmpwalk -v2c -c public 127.0.0.1:1611 IP-MIB::ipSystemStatsHCInReceives
```

## Future Work — Additional Health Data via Standard OIDs

The following are opportunities to expose more VPP data through standard SNMP
OIDs. All use well-known MIBs that NMS tools already understand.

### High Priority (health-check critical)

#### Transceiver Optical Levels — ENTITY-SENSOR-MIB (RFC 3433)

**MIB**: `entPhySensorTable` (OID 1.3.6.1.2.1.99.1.1)
**Data**: Rx/Tx optical power (dBm), temperature (°C), supply voltage, bias current

**Update (VPP 26.06+)**: VPP gerrit change
[43544](https://gerrit.fd.io/r/c/vpp/+/43544) — *"vnet: add SFF8472 and SFF8636
diagnostics"* (merged 2025-08-28, present in our build) — now decodes SFP/SFP+
(SFF-8472) and QSFP (SFF-8636) DOM data inside VPP. It adds:

- `show interface transceiver <itf> [module|diag|eeprom] [verbose]` CLI
- `vnet_interface_eeprom_t` (raw EEPROM) + a per-device-class
  `eeprom_read_function` hook (`vnet/interface.h`)
- `sff8472_diag_t` real-time values: temperature, Vcc, TX bias, TX power,
  RX power, plus alarm/warning thresholds (`vnet/ethernet/sfp_sff8472.h`)

**Remaining challenge for SNMP**: the diagnostics are exposed **only through the
CLI and in-process C functions** — there is still **no binary-API/VAPI message
and no stats-segment counter**. An external SNMP agent cannot consume the data
through the two transports this integration uses (VAPI + stats segment).

**Options (in preference order)**:
1. **Add a binary-API message upstream/in a plugin** (e.g.
   `sw_interface_transceiver_dump` returning the `sff8472_diag_t` /
   SFF-8636 fields). This is the clean path: it would generate a
   `vapi/transceiver.api.vapi.h` we consume exactly like `interface.api`,
   and feed `entPhySensorTable`.
2. **Scrape the CLI** over `/run/vpp/cli.sock`
   (`show interface transceiver <itf> diag`) and parse the text. Quick to
   build but brittle against output changes; acceptable as an interim.
3. **LCP mirror interfaces**: if the LCP plugin creates Linux netdevs, read
   `ethtool -m <dev>` / sysfs on the mirror.

Net: 43544 closes the *data-availability* gap inside VPP (DPDK's
`rte_eth_dev_get_module_eeprom()` is now surfaced), but a small amount of work
(option 1 or 2) is still required to bridge it to `entPhySensorTable`.

#### NAT Session Health — NATV2-MIB (RFC 7659) ✅ IMPLEMENTED

Implemented in `nat-mib/nat_vpp.c`. See "What Works" section above.

#### BFD Session State — BFD-MIB (RFC 7331)

**MIB**: `bfdSessTable` (OID 1.3.6.1.2.1.222.1.2)
**VPP data**: `/bfd/udp4/sessions`, `/bfd/udp6/sessions`

**Value**: BFD is used for fast failure detection. Exposing session state
(Up/Down/AdminDown) and diagnostic codes via SNMP gives NMS visibility into
adjacency health without needing CLI access.

#### LLDP Neighbor Discovery — LLDP-MIB (RFC 4623)

**MIB**: `lldpRemTable` (OID 1.0.8802.1.1.2.1.4.1.1), `lldpStatisticsTable`
**VPP data**: VAPI `lldp_dump` → `lldp_details`

**VAPI coverage** (`/usr/include/vapi/lldp.api.vapi.h`):

| VAPI field | LLDP-MIB column |
|---|---|
| `sw_if_index` | `lldpRemLocalPortNum` (ifIndex) |
| `chassis_id[64]` / `chassis_id_len` / `chassis_id_subtype` | `lldpRemChassisIdSubtype` + `lldpRemChassisId` |
| `port_id[64]` / `port_id_len` / `port_id_subtype` | `lldpRemPortIdSubtype` + `lldpRemPortId` |
| `ttl` | `lldpRemTimeMark` |
| `last_heard` (float64, unix time) | Can compute `lldpRemAge` |

The `lldpRemTable` — the most operationally valuable table ("what is plugged
into each port?") — is **fully implementable** today. VPP exposes everything
needed via a single `lldp_dump` message.

**Not yet available via VAPI**:
- **`lldpStatisticsTable`** (per-port TX/RX frame counters, errors, ageouts):
  no corresponding VAPI message or stats-segment path.
- **System name / description / capabilities** (TLVs): not decoded in
  `lldp_details`; would need TLV parsing or the `lldp_config` reply.

**Implementation approach**: Follow the `arp_vpp.c` pattern — issue
`lldp_dump` on `g_vapi_ctx`, process `lldp_details` callbacks, populate
rows into a `netsnmp_container` for the standard `lldpRemTable` columns.
Register `DEFINE_VAPI_MSG_IDS_LLDP_API_JSON` in the new translation unit.
The MIB text file (`mibs/LLDP-MIB.txt`) imports from the IEEE 802.1
OID tree (`1.0.8802`).

**Value**: Answers "who is my neighbor?" without CLI access — critical
for automated topology discovery and cabling verification.

### Medium Priority (operational visibility)

#### VPP Buffer Pool & Heap Memory ✅ IMPLEMENTED

Implemented in `vpp-stats/vpp_stats.c` as private scalars under
`netSnmpExperimental.9696.2`. Does NOT modify hrStorageTable — host memory
and disk entries remain unchanged. See "What Works" section above.

#### Per-Interface DPDK Counters — EtherLike-MIB (RFC 3635)

**MIB**: `dot3StatsTable` (OID 1.3.6.1.2.1.10.7.2)
**VPP data** (per named interface in stats segment):
- `/interfaces/GigabitEthernet2/0/0/rx_errors`
- `/interfaces/GigabitEthernet2/0/0/rx_missed_errors`
- `/interfaces/GigabitEthernet2/0/0/rx_mbuf_allocation_errors`
- `/interfaces/GigabitEthernet2/0/0/tx_errors`

**Value**: Ethernet-layer error counters (CRC, alignment, runt frames) are
essential for detecting cable/transceiver degradation before link goes down.

#### VPP Process Uptime — SNMPv2-MIB / ENTITY-MIB

**VPP data**: `/sys/boottime` (Unix epoch when VPP started)

**Value**: Distinguish VPP restart from OS restart. Could expose as
`entLastChangeTime` in ENTITY-MIB or as a custom `sysOREntry` description.

### Lower Priority (nice to have)

#### ARP/ND Statistics ✅ IMPLEMENTED

Implemented in `vpp-stats/vpp_stats.c` under `netSnmpExperimental.9696.1`.
12 Counter64 scalars for ARP rx/tx and IPv6 ND rx/tx. See "What Works".

**Relationship to standard MIBs**:

- **ARP**: No standard IETF MIB exposes ARP packet counters. `ipNetToPhysicalTable`
  (IP-MIB, RFC 4293) tracks only neighbor *state* (reachable/stale/etc.),
  MAC address, and last-updated timestamp — not packet counts. Gratuitous
  ARP has no standard MIB coverage at all. The private `vppArp*` counters
  fill a genuine gap.

- **IPv6 ND**: ICMPv6 types 135 (Neighbor Solicitation) and 136 (Neighbor
  Advertisement) appear in the standard `icmpMsgStatsTable` (IP-MIB,
  OID 1.3.6.1.2.1.5.30) as `Counter32` rows indexed by `(ipv6, 135)` and
  `(ipv6, 136)`. However, these are global (not per-interface), not split
  by direction label, and don't distinguish unsolicited/gratuitous ND.
  The private `vppNd*` counters provide finer granularity.

#### Routing Table Size ✅ IMPLEMENTED

Already exposed as standard `inetCidrRouteNumber` (IP-FORWARD-MIB) via
`route_vpp.c`. See "What Works" section.

#### VPP Vector Rate — no standard OID (informational only)

**VPP data**: `/sys/vector_rate`, `/sys/vector_rate_per_worker`

**Note**: No standard MIB maps to packet-processing batch efficiency. Would
require a private MIB enterprise subtree if needed.

#### ACL Hit Counters — no standard OID

**VPP data**: `/err/acl-plugin-in-ip4-fa/ACL deny packets`, etc.

**Note**: Useful for security monitoring but no standard SNMP MIB. Could use
`snmpd extend` scripts or a private MIB.

### Implementation Notes

For modules that only read the stats segment (NAT, BFD, buffer pools, memory),
follow the `systemstats_vpp.c` pattern:
- Call `clib_mem_init()` once (shared; already done in interface_vpp.c)
- Use `stat_segment_connect()` / `stat_segment_ls()` / `stat_segment_dump()`
- Do NOT call `vapi_connect_once()` — stats segment is independent

For modules that need VAPI messages (BFD session details, future optics
plugin), follow the `interface_vpp.c` pattern but be mindful of the VAPI
reentrancy constraint.
