# net-snmp VPP Interface Integration -- Discovery Document

This document catalogues every source location in the net-snmp tree that reads
kernel/Linux network-interface state and explains what must change to replace
those reads with queries to VPP so that SNMP exposes VPP interface counters and
ifIndex values directly.

---

## 0. Approach summary

net-snmp's Linux port reads interface data through three independent mechanisms:

| Mechanism | What uses it |
|-----------|-------------|
| **libnl-3 / rtnetlink** (`NETLINK_ROUTE`) | IF-MIB link info + stats, IP address table, dot3Stats |
| **`/proc/net/*` files** | Route table, ARP, IPv4/IPv6 system stats, IPv6 per-interface stats, TCP/UDP table |
| **ioctl** (`SIOCGIFCONF`, `SIOCGIFFLAGS`, `SIOCGIFHWADDR`, `SIOCGIFINDEX`, `SIOCETHTOOL`, `SIOCGMIIPHY`) | MAC addr, flags, ifIndex, link speed |

VPP has its own interface index space (sw_if_index) and its own counter
namespace.  The Linux kernel sees only the LCP TAP mirror interfaces
(`ge0-1-0`, etc.), which carry kernel-assigned ifIndex values that differ from
VPP sw_if_index values and have stale/zero counters.

The goal is: for every VPP-owned interface, return VPP sw_if_index as the SNMP
ifIndex and return VPP VAPI counters instead of kernel/netlink counters.

The cleanest integration point is the **data-access layer** -- the
`_arch_*` and `container_load` functions listed below.  Higher-level MIB
table code (ifTable, ifXTable, ipIfStatsTable, ...) is unchanged.

---

## 1. IF-MIB -- Interface table (RFC 2863)

### 1a. Primary data-access driver (Linux)

**File:** `agent/mibgroup/if-mib/data_access/interface_linux.c`

This is the **most important file**.  It owns the full lifecycle of
`netsnmp_interface_entry` objects for Linux.

| Function | What it does | VPP change needed |
|----------|-------------|-------------------|
| `netsnmp_arch_interface_container_load()` (line 867) | Top-level entry point.  Opens an `AF_INET` socket + netlink socket, calls `netsnmp_retrieve_link_info()` and `netsnmp_retrieve_addr_info()`. | Replace or supplement: enumerate VPP interfaces via VAPI `sw_interface_dump`, create `netsnmp_interface_entry` per sw_if, use VPP sw_if_index as `entry->index`. |
| `netsnmp_retrieve_link_info()` | Calls `rtnl_link_alloc_cache()` (libnl-3) then iterates links; for each creates an entry and calls `netsnmp_retrieve_one_link_info()`. | Replace libnl-3 cache walk with VPP VAPI dump. |
| `netsnmp_retrieve_one_link_info()` | Populates MAC, type, flags, MTU, speed, stats from `rtnl_link`. | Replace each field source: MAC from `sw_interface_get_mac_address`, flags/MTU from `sw_interface_dump`, stats from `vnet_get_combined_counter`. |
| `_retrieve_stats()` (line 621) | Reads RX/TX bytes, packets, errors, drops, collisions from `rtnl_link_get_stat()`. | Replace with `vnet_get_combined_counter` / `vnet_get_simple_counter` VAPI calls per sw_if_index. |
| `netsnmp_retrieve_link_speed()` (line 598) | Calls `netsnmp_linux_interface_get_if_speed()` which uses `SIOCETHTOOL` or `SIOCGMIIPHY`. | Replace with VPP `sw_interface_set_flags` state; speed available from `sw_interface_dump` `link_speed` field (Mbps). |
| `netsnmp_retrieve_addr_info()` | Calls `rtnl_addr_alloc_cache()` to set HAS_IPV4 / HAS_IPV6 flags per entry. | Query VPP `ip_address_dump` per sw_if_index to set the same flags. |
| `netsnmp_arch_interface_entry_copy()` | Copies arch-private fields (currently none for Linux). | No change needed unless VPP state is stored in arch-private area. |
| `netsnmp_arch_interface_entry_init/cleanup()` | Currently no-ops on Linux. | No change needed. |
| `_arch_interface_flags_v4_get()` / `_arch_interface_flags_v6_get()` | Reads `/proc/sys/net/ipv{4,6}/neigh/<ifname>/retrans_time_ms` and `base_reachable_time_ms`. | These are neighbor-reachability tunable fields. For VPP-owned interfaces the kernel proc files will not exist. Must either skip or synthesize defaults. |
| `netsnmp_linux_interface_get_if_speed()` (line 943) | Issues `SIOCETHTOOL` (`ETHTOOL_GSET` / `ETHTOOL_GLINKSETTINGS`) ioctl on the LCP TAP fd. | Replace: read `link_speed` from `sw_interface_dump` result (field is in Mbps). |
| `netsnmp_linux_interface_get_if_speed_mii()` (line 971) | Issues `SIOCGMIIPHY` / `SIOCGMIIREG` ioctls. | Fallback path; will return wrong speed for VPP-native interfaces. Replace with VPP speed field same as above. |

**libnl-3 dependency note:** `interface_linux.c` has a hard `#error` if
`HAVE_LIBNL3` is not defined.  The VPP replacement can either satisfy that
dependency (keep libnl for non-VPP interfaces, override for VPP interfaces) or
add a new compile-time path `HAVE_VPP_DATAPLANE` that bypasses libnl entirely.

---

### 1b. ioctl helpers

**File:** `agent/mibgroup/if-mib/data_access/interface_ioctl.c`

Used by `interface_linux.c` for fields libnl-3 does not provide.

| Function | ioctl | VPP change needed |
|----------|-------|-------------------|
| `netsnmp_access_interface_ioctl_physaddr_get()` (line ~155) | `SIOCGIFHWADDR` | Replace with `sw_interface_get_mac_address` VAPI. |
| `netsnmp_access_interface_ioctl_flags_get()` (line ~252) | `SIOCGIFFLAGS` | Replace with `link_up_down` + `admin_up_down` from `sw_interface_dump`. |
| `netsnmp_access_interface_ioctl_flags_set()` (line ~327) | `SIOCGIFFLAGS` | Admin-status write path; replace with `sw_interface_set_flags` VAPI. |
| `netsnmp_access_interface_ioctl_ifindex_get()` (line ~400) | `SIOCGIFINDEX` | Replace: return VPP sw_if_index for VPP interfaces; keep kernel ifIndex for non-VPP. |

---

### 1c. ifTable and ifXTable table modules

**Files:**
- `agent/mibgroup/if-mib/ifTable/ifTable_data_access.c`
- `agent/mibgroup/if-mib/ifXTable/ifXTable_data_access.c`

These call `netsnmp_access_interface_container_load()` (the generic wrapper
that calls the arch-specific `netsnmp_arch_interface_container_load()`).
**No changes needed here** provided the arch layer returns correct VPP data.

---

## 2. IP-MIB -- IP address table (RFC 4293)

### 2a. IP address data access (Linux)

**File:** `agent/mibgroup/ip-mib/data_access/ipaddress_linux.c`

| Function | Mechanism | VPP change needed |
|----------|-----------|-------------------|
| `netsnmp_arch_ipaddress_container_load()` (line ~122) | Opens a libnl-3 socket, calls `rtnl_link_alloc_cache()` + `rtnl_addr_alloc_cache()`. Iterates links to find per-interface addresses. | Replace link + addr enumeration with VPP `ip_address_dump` per sw_if_index. Must map VPP sw_if_index -> SNMP ifIndex (1:1 if VPP sw_if_index IS the SNMP ifIndex). |
| `netsnmp_arch_ipaddress_entry_init/cleanup/copy()` | Thin wrappers around ioctl helpers. | The ioctl helpers (`ipaddress_ioctl.c`) are used for add/delete operations; those still go through the LCP TAP kernel path, no VPP change needed for now. |

**Key fields populated from libnl-3:**
- `if_index` (from `rtnl_link_get_ifindex`)
- `if_name` (from `rtnl_link_get_name`)
- `flags` (from `rtnl_link_get_flags`)
- `ia_address` (from `rtnl_addr_get_local`)
- `ia_valid_lifetime` / `ia_preferred_lifetime` (from `rtnl_addr_get_valid_lifetime`)

All of these have VPP equivalents via `ip_address_dump` + `sw_interface_dump`.

---

### 2b. IP system and per-interface stats (ipSystemStatsTable, ipIfStatsTable)

**File:** `agent/mibgroup/ip-mib/data_access/systemstats_linux.c`

| Function | Proc file read | VPP change needed |
|----------|---------------|-------------------|
| `_systemstats_v4()` (line ~634) | `/proc/net/snmp` (global IPv4 IP/ICMP/TCP/UDP counters) | For ipSystemStatsTable (global): aggregate VPP `vnet_get_combined_counter` across all interfaces. More accurately use `ip_stats_dump` VAPI when available. |
| `_additional_systemstats_v4()` | `/proc/net/netstat` (IpExt: extended counters) | Same note: VPP does not expose all Linux IpExt fields; map what is available. |
| `_systemstats_v6()` / `_systemstats_v6_load_file()` (line ~438) | `/proc/net/snmp6` and `/proc/net/dev_snmp6/<ifname>` | ipIfStatsTable per-interface IPv6: read per-sw_if_index counters from VPP VAPI. The `dev_snmp6` walk must be replaced with a VPP interface iteration. |

The per-interface IPv6 stats path (`load_flags & NETSNMP_ACCESS_SYSTEMSTATS_LOAD_IFTABLE`)
currently reads `/proc/net/dev_snmp6/<ifindex>/` directories named by kernel
ifindex.  For VPP interfaces these directories do not exist.

---

### 2c. IPv6 scope zone table

**File:** `agent/mibgroup/ip-mib/data_access/ipv6scopezone_linux.c`

Reads `/proc/net/if_inet6` to enumerate link-local addresses per interface.
The ifindex field in this file is the **kernel** ifindex (LCP TAP index).

VPP change needed: replace the proc-file walk with a `ip6_address_dump` VAPI
call per sw_if_index and synthesize the `netsnmp_v6scopezone_entry` objects
using VPP sw_if_index as the scope zone identifier.

---

### 2d. Default router table

**File:** `agent/mibgroup/ip-mib/data_access/defaultrouter_linux.c`

Opens a raw `AF_NETLINK` / `NETLINK_ROUTE` socket, sends `RTM_GETROUTE` to
retrieve the default route.  For VPP deployments the kernel default route may
not match the VPP FIB default route.

VPP change needed: use `ip_route_dump` VAPI (prefix 0.0.0.0/0) to get the VPP
default gateway, and use `ip6_route_dump` for IPv6.

---

### 2e. ARP / neighbor table (inetNetToMediaTable)

**File:** `agent/mibgroup/ip-mib/data_access/arp_netlink.c`

Keeps a live `AF_NETLINK` / `NETLINK_ROUTE` socket (`RTMGRP_NEIGH` group) and
sends `RTM_GETNEIGH` for initial sync, then processes `RTM_NEWNEIGH` /
`RTM_DELNEIGH` notifications.

For VPP-owned interfaces the kernel ARP table (neighbor table) may be
incomplete or entirely empty (VPP handles ARP itself in the data plane).

VPP change needed:
- `netsnmp_access_arp_load()`: replace / supplement with VPP `ip_neighbor_dump`
  VAPI call (and optionally subscribe to `ip_neighbor_event` notifications).
- `fillup_entry_info()`: populate `netsnmp_arp_entry` fields from VAPI response
  instead of from `nlmsghdr` / `ndmsg`.

---

## 3. IP-FORWARD-MIB -- Route table (ipCidrRouteTable / inetCidrRouteTable)

**File:** `agent/mibgroup/ip-forward-mib/data_access/route_linux.c`

| Function | Proc file | VPP change needed |
|----------|-----------|-------------------|
| `_load_ipv4()` (line ~43) | `/proc/net/route` | Read VPP FIB via `ip_route_dump` VAPI (table_id 0, AF_INET). Map sw_if_index -> SNMP ifIndex for each next-hop. |
| `_load_ipv6()` (line ~218) | `/proc/net/ipv6_route` | Read VPP FIB via `ip6_route_dump` VAPI (table_id 0, AF_INET6). Same sw_if_index -> ifIndex mapping. |

Also: `mibII/var_route.c` (line 1302) reads `/proc/net/route` for the legacy
`ipRoutingTable` (RFC 1213).  Same replacement applies.

---

## 4. MIB-II -- Legacy interface table and IP address table

### 4a. Legacy interfaces.c

**File:** `agent/mibgroup/mibII/interfaces.c`

This is the **old** (pre-RFC-2863) interface code, used when
`config_exclude(mibII/interfaces)` is NOT set.  On modern Linux it is excluded
by `if-mib/data_access/interface.h` (`config_exclude(mibII/interfaces)`).

Key reads:
- `/proc/net/dev` (line 1557) -- RX/TX counters.
- `SIOCGIFFLAGS` (line 1695) -- flags.
- `SIOCGIFHWADDR` (line 1707) -- MAC address.

**Status:** This code path should remain excluded (`config_exclude` is already
set in `if-mib/data_access/interface.h`).  No VPP change needed.

---

### 4b. Legacy IP address scanner

**File:** `agent/mibgroup/mibII/ipAddr.c`

Uses `SIOCGIFCONF` ioctl (line 536) to enumerate interfaces and their IPv4
addresses.  This is an old MIB-II path used on platforms without the newer
ip-mib data access layer.

**Status:** Not used on Linux when the ip-mib data access layer is active.
No change needed.

---

### 4c. Kernel MIB stat caches

**File:** `agent/mibgroup/mibII/kernel_linux.c`

Reads `/proc/net/snmp` and `/proc/net/snmp6` into `cached_ip_mib`,
`cached_icmp_mib`, etc.  These are used by `ip.c`, `icmp.c`, `tcp.c`, `udp.c`
for the scalar MIB-II OIDs (ipInReceives, tcpActiveOpens, etc.).

VPP change needed (optional, lower priority): aggregate VPP IP counters into
these cached structs.  The global counters (ipInReceives, etc.) could be read
from VPP `ip_stats_dump` instead of from the kernel proc file.

---

### 4d. ARP/AT table (at.c legacy path)

**File:** `agent/mibgroup/mibII/data_access/at_linux.c`

Reads `/proc/net/arp` (line 67) to build the legacy `atTable`.

**Status:** The modern `inetNetToMediaTable` uses `arp_netlink.c` (section 2e
above).  The `atTable` path uses `at_linux.c` for backwards compat.

VPP change needed: supplement `at_linux.c` with VPP `ip_neighbor_dump` for
VPP-owned interfaces.

---

## 5. Etherlike-MIB (dot3StatsTable)

**File:** `agent/mibgroup/etherlike-mib/data_access/dot3stats_linux.c`

Opens a libnl-3 socket, calls `rtnl_link_alloc_cache()`, iterates links, and
for each calls `rtnl_link_get_stat()` for error/collision counters.

| Counter read | `RTNL_LINK_*` stat | VPP equivalent |
|-------------|---------------------|----------------|
| RX errors | `RTNL_LINK_RX_ERRORS` | `vnet_get_simple_counter(VNET_INTERFACE_COUNTER_RX_ERROR, sw_if_index)` |
| RX drop+missed | `RTNL_LINK_RX_DROPPED` + `RTNL_LINK_RX_MISSED_ERR` | `VNET_INTERFACE_COUNTER_DROP` |
| TX errors | `RTNL_LINK_TX_ERRORS` | `vnet_get_simple_counter(VNET_INTERFACE_COUNTER_TX_ERROR, sw_if_index)` |
| TX drop | `RTNL_LINK_TX_DROPPED` | `VNET_INTERFACE_COUNTER_DROP` |
| TX collisions (abort) | `RTNL_LINK_TX_ABORT_ERR` | No direct VPP equivalent; report 0 |
| Carrier errors | `RTNL_LINK_TX_CARRIER_ERR` | No direct VPP equivalent; report 0 |

VPP change needed: replace `dot3StatsTable_container_load_impl()` with a VPP
`sw_interface_dump` + `vnet_get_combined_counter` walk.

---

## 6. RMON-MIB (etherStatsTable)

**File:** `agent/mibgroup/rmon-mib/data_access/etherstats_linux.c`

Uses `getifaddrs()` (line 34) to build the interface name list, then issues a
`SIOCGIFINDEX` ioctl (line 130) per interface to get the kernel ifIndex.

VPP change needed: replace `getifaddrs()` + `SIOCGIFINDEX` with VPP
`sw_interface_dump` to enumerate interfaces and return VPP sw_if_index.  Stats
are read separately via `SIOCETHTOOL` elsewhere in this subsystem.

---

## 7. Transport layer (IPv6 scope ID in UDP/TCP sockets)

**File:** `snmplib/transports/snmpIPv6BaseDomain.c`

Functions `netsnmp_if_nametoindex()` (line 73) and `netsnmp_if_indextoname()`
(line 91) wrap the POSIX `if_nametoindex(3)` / `if_indextoname(3)` which look
up the **kernel** ifIndex by interface name.

These are used to bind IPv6 link-local sockets to a scope zone ID.  If the SNMP
management transport uses VPP LCP TAP names (e.g. `ge0-1-0`), the kernel
functions will work correctly against the LCP TAP interfaces and no change is
needed.  If the SNMP ifIndex space is remapped to VPP sw_if_index, a VPP-aware
lookup wrapper is required here.

---

## 8. SNMPv3 engine ID generation

**File:** `snmplib/snmpv3.c`

Uses `SIOCGIFHWADDR` ioctl (lines 550, 647, 769, 1316, 1369) to derive the
engine ID from a NIC MAC address.  This operates on `lo` or the first non-lo
interface found.

VPP change needed: none for correctness -- the LCP TAP for any physical
interface has the correct MAC address visible to the kernel.  If VPP-native
interfaces have no LCP pair, fall back to using the MAC from VPP VAPI
`sw_interface_dump`.

---

## 9. snmplib system.c -- SIOCGIFCONF

**File:** `snmplib/system.c`

`netsnmp_getNetSnmpAgentAddresses()` (line ~521) uses `SIOCGIFCONF` +
`SIOCGIFFLAGS` to enumerate local IP addresses for agent binding decisions.

VPP change needed: none -- this operates on the kernel interface table
(including LCP TAP interfaces) to decide which addresses the SNMP agent should
listen on.  LCP TAP interfaces surface the VPP-assigned addresses to the kernel,
so this code should work without modification.

---

## 10. Disman MIB (ping / traceroute source address)

**File:** `agent/mibgroup/disman/ping/pingCtlTable.c` (line 1916)
**File:** `agent/mibgroup/disman/traceroute/traceRouteCtlTable.c` (lines 6111, 6193)

Both use `SIOCGIFCONF` + `SIOCGIFFLAGS` + `SIOCGIFINDEX` to discover source
addresses and interface indexes for raw probe sockets.  These are management
plane operations (sending ICMP probes) that bypass VPP.

VPP change needed: none unless probes are expected to traverse VPP.

---

## 11. Summary: files requiring code changes

### Tier 1 -- Must change (directly exposes wrong ifIndex or stale counters)

| File | Section | Priority |
|------|---------|---------|
| `agent/mibgroup/if-mib/data_access/interface_linux.c` | IF-MIB link/stats | Highest |
| `agent/mibgroup/if-mib/data_access/interface_ioctl.c` | ioctl wrappers for flags/MAC/index | High |
| `agent/mibgroup/ip-mib/data_access/systemstats_linux.c` | IP system + per-if stats | High |
| `agent/mibgroup/ip-mib/data_access/ipaddress_linux.c` | IP address table | High |
| `agent/mibgroup/ip-mib/data_access/arp_netlink.c` | ARP / neighbor table | High |
| `agent/mibgroup/ip-forward-mib/data_access/route_linux.c` | Route table | High |
| `agent/mibgroup/etherlike-mib/data_access/dot3stats_linux.c` | dot3StatsTable | Medium |

### Tier 2 -- Should change (correctness / completeness)

| File | Section | Priority |
|------|---------|---------|
| `agent/mibgroup/ip-mib/data_access/ipv6scopezone_linux.c` | IPv6 scope zones | Medium |
| `agent/mibgroup/ip-mib/data_access/defaultrouter_linux.c` | Default router table | Medium |
| `agent/mibgroup/rmon-mib/data_access/etherstats_linux.c` | RMON etherStats ifIndex | Medium |
| `agent/mibgroup/mibII/data_access/at_linux.c` | Legacy ARP table | Low |
| `agent/mibgroup/mibII/kernel_linux.c` | IP/ICMP global scalar MIBs | Low |
| `agent/mibgroup/mibII/var_route.c` | Legacy ipRoutingTable | Low |

### Tier 3 -- No change needed (or minimal)

| File | Reason |
|------|--------|
| `agent/mibgroup/mibII/interfaces.c` | Excluded by `config_exclude` on Linux |
| `agent/mibgroup/mibII/ipAddr.c` | Old path, not used when ip-mib data access is active |
| `snmplib/system.c` | LCP TAP makes kernel interface list valid for agent binding |
| `snmplib/transports/snmpIPv6BaseDomain.c` | LCP TAP names work for scope-ID; revisit if ifIndex remapped |
| `snmplib/snmpv3.c` | Engine ID uses MAC visible on LCP TAP |
| `agent/mibgroup/disman/ping/pingCtlTable.c` | Management plane probes, bypass VPP |
| `agent/mibgroup/disman/traceroute/traceRouteCtlTable.c` | Same |
| `agent/mibgroup/if-mib/ifTable/ifTable_data_access.c` | Calls arch layer; no change needed |
| `agent/mibgroup/if-mib/ifXTable/ifXTable_data_access.c` | Same |

---

## 12. New files to create

| Proposed file | Purpose |
|---------------|---------|
| `agent/mibgroup/if-mib/data_access/interface_vpp.c` | VPP implementation of `netsnmp_arch_interface_container_load()` and helpers; replaces libnl-3 walk with VPP VAPI `sw_interface_dump` + counter reads. |
| `agent/mibgroup/if-mib/data_access/interface_vpp.h` | Header for `interface_vpp.c`. |
| `agent/mibgroup/ip-mib/data_access/ipaddress_vpp.c` | VPP implementation of `netsnmp_arch_ipaddress_container_load()`. |
| `agent/mibgroup/ip-mib/data_access/arp_vpp.c` | VPP implementation of `netsnmp_access_arp_load()` using `ip_neighbor_dump` VAPI. |
| `agent/mibgroup/ip-mib/data_access/systemstats_vpp.c` | VPP per-interface IPv6/IPv4 stats (ipIfStatsTable). |
| `agent/mibgroup/ip-forward-mib/data_access/route_vpp.c` | VPP FIB dump for ipCidrRouteTable / inetCidrRouteTable. |
| `agent/mibgroup/if-mib/data_access/interface.h` update | Add `config_require(if-mib/data_access/interface_vpp)` under a new `HAVE_VPP_DATAPLANE` guard; remove `config_require(interface_linux)` for that build. |

---

## 13. Key VPP VAPI calls mapping

| Data needed | VAPI message | Key response fields |
|-------------|-------------|---------------------|
| Interface list + sw_if_index | `sw_interface_dump` | `sw_if_index`, `interface_name`, `admin_up_down`, `link_up_down`, `link_speed`, `link_mtu`, `l2_address` |
| Combined (bytes/packets) RX/TX counters | `vnet_get_combined_counter` (`sw_if_index`) | `rx.packets`, `rx.bytes`, `tx.packets`, `tx.bytes` |
| Simple (error/drop) counters | `vnet_get_simple_counter` (`sw_if_index`) | counter value |
| IPv4 addresses | `ip_address_dump` (is_ipv6=0) + `sw_if_index` | `prefix` (address + len) |
| IPv6 addresses | `ip_address_dump` (is_ipv6=1) + `sw_if_index` | `prefix` |
| ARP / neighbor table | `ip_neighbor_dump` | `neighbor.ip_address`, `neighbor.mac_address`, `neighbor.sw_if_index` |
| IPv4 routes | `ip_route_dump` (table_id=0, is_ip6=0) | `route.prefix`, `route.paths[].sw_if_index`, `route.paths[].nh` |
| IPv6 routes | `ip_route_dump` (table_id=0, is_ip6=1) | Same |
| MAC address | `sw_interface_dump` `l2_address` field | 6-byte MAC |
| Admin up/down set | `sw_interface_set_flags` | -- |

---

## 14. ifIndex mapping strategy

**Decision required** before implementation:

**Option A -- Use VPP sw_if_index directly as SNMP ifIndex.**
- Simple 1:1 mapping.
- VPP sw_if_index starts at 1 for the first physical interface (0 is local/loopback).  SNMP ifIndex also starts at 1.  They are compatible in range.
- The kernel LCP TAP ifIndex values are discarded.
- Requires that the SNMP agent never calls kernel `if_nametoindex()` for VPP
  interfaces (update `netsnmp_if_nametoindex()` wrapper in `snmpIPv6BaseDomain.c`).

**Option B -- Maintain a sw_if_index -> SNMP ifIndex mapping table.**
- SNMP ifIndex is assigned sequentially by the agent; sw_if_index is stored as
  opaque arch data in `entry->if_index_private`.
- More flexible; can coexist with non-VPP (e.g. loopback) kernel interfaces.
- Adds a lookup table that must be kept in sync.

**Recommendation:** Option A for an appliance where all data-plane interfaces
are VPP-owned.  Option B if the agent must also report non-VPP kernel
interfaces (loopback, management port, etc.).

---

## 15. Counter precision notes

- `netsnmp_interface_entry` stores 32-bit `low` + 32-bit `high` counter pairs
  (`counter64`-like struct).  VPP counters are 64-bit natively.  Split with
  `low = val & 0xffffffff; high = val >> 32;`.
- The `ns_flags` bitmask controls which columns are marked valid:
  - `NETSNMP_INTERFACE_FLAGS_HAS_BYTES` -- set if bytes counters valid.
  - `NETSNMP_INTERFACE_FLAGS_HAS_HIGH_BYTES`, `HAS_HIGH_PACKETS` -- required for
    HC (High Capacity) 64-bit counters.
  - `NETSNMP_INTERFACE_FLAGS_HAS_DROPS`, `HAS_MCAST_PKTS` -- set if available.
  - `NETSNMP_INTERFACE_FLAGS_ACTIVE` -- must be set for the entry to be visible.
  - `NETSNMP_INTERFACE_FLAGS_CALCULATE_UCAST` -- tells the table code to compute
    unicast = all - multicast; set this because VPP exposes both.

---

## 16. Build system changes

Files to modify in the Buildroot package (`buildroot/package/latigo-dplane-vpp/`
or a new `latigo-netsnmp/` package):

1. Add `--with-vpp` or similar configure flag (new autoconf check in
   `configure.d/`) that enables `HAVE_VPP_DATAPLANE`.
2. Link `snmpd` against the VPP VAPI client library (`libvapiclient.so`) or
   our own `latigo-vpp-sys` Rust-generated C wrapper if calling from C.
3. Add `interface_vpp.c` and sibling files to the `NETSNMP_TRANSPORT_LIBS` or
   `agent_module_list` make variable.

---

*Generated 2026-06-25 -- latigo-gw VPP SNMP integration discovery.*
