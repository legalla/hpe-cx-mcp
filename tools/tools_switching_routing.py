"""VLAN, LLDP, routing-table, MAC/ARP, system-log, spanning-tree, BGP and OSPF
read-only tools."""

from core.server_core import mcp, _get_client

# ══════════════════════════════════════════════════════════════════════
# TOOLS — VLANs
# ══════════════════════════════════════════════════════════════════════

@mcp.tool()
async def get_vlans(device: str, vlan_id: int = None) -> dict:
    """List VLANs."""
    async with _get_client(device) as client:
        return await client.get_vlans(vlan_id)


# ══════════════════════════════════════════════════════════════════════
# TOOLS — LLDP
# ══════════════════════════════════════════════════════════════════════

@mcp.tool()
async def get_lldp_neighbors(device: str, interface: str = None) -> dict:
    """Discover directly-connected neighbors via LLDP — THE tool to build a
    physical topology / cabling map or answer "what is connected to this switch".
    Returns, per local interface, the neighbor's system name (chassis_name),
    description (chassis_description), chassis id, remote port id/description,
    management IPs and advertised VLANs. `interface` restricts to one local
    port. For a whole site at once, prefer run_on_site(operation=
    'get_lldp_neighbors'). Not related to system logs."""
    async with _get_client(device) as client:
        return await client.get_lldp_neighbors(interface=interface)


# ══════════════════════════════════════════════════════════════════════
# TOOLS — Routing
# ══════════════════════════════════════════════════════════════════════

@mcp.tool()
async def get_routing_table(device: str, vrf: str = "default") -> dict:
    """Routing table: vrf='default'/name for one VRF, 'all' for all. Each route:
    prefix, protocol, distance, metric, nexthops. Broken down by VRF and
    protocol."""
    async with _get_client(device) as client:
        return await client.get_routing_table(vrf)


@mcp.tool()
async def get_dhcp_relay(device: str, interface: str = None) -> dict:
    """DHCP relay (helper-address) config. Omit `interface` to discover ALL
    configured relays on the device (each with its VRF/port/server list);
    provide it to check a single L3 port/SVI. Pair with configure_dhcp_relay."""
    async with _get_client(device) as client:
        relays = await client.list_dhcp_relays(interface)
        return {"device": device, "relays": relays, "count": len(relays)}


@mcp.tool()
async def get_interface_groups(device: str, subsystem: str = None) -> dict:
    """Interface (port-group) speed settings — the CLI `show interface-group`.
    Each group lists its configured / applied / default speed and the speeds it
    supports. Interface groups are blocks of ports on a subsystem (line card /
    chassis) that share one selectable link speed (e.g. 10g OR 25g, not both).
    Omit `subsystem` to list every group on the device; provide it
    ('line_card,1/1' or bare '1/1') to scope to one. Pair with
    configure_interface_group. Empty on platforms without interface groups."""
    async with _get_client(device) as client:
        groups = await client.list_interface_groups(subsystem)
        return {"device": device, "interface_groups": groups, "count": len(groups)}


# ══════════════════════════════════════════════════════════════════════
# TOOLS — Tables MAC / ARP
# ══════════════════════════════════════════════════════════════════════

@mcp.tool()
async def get_mac_table(device: str, vlan_id: int = None) -> dict:
    """MAC table."""
    async with _get_client(device) as client:
        return await client.get_mac_table(vlan_id)


@mcp.tool()
async def get_arp_table(device: str, vrf: str = "default") -> dict:
    """ARP table."""
    async with _get_client(device) as client:
        return await client.get_arp_table(vrf)


# ══════════════════════════════════════════════════════════════════════
# TOOLS — Logs
# ══════════════════════════════════════════════════════════════════════

@mcp.tool()
async def get_logs(
    device: str,
    limit: int = 50,
    priority: str = None,
    daemon: str = None,
    since: str = None,
    until: str = None,
) -> dict:
    """System event log (syslog) messages: timestamped events, warnings and errors
    from the switch. Use ONLY for event/incident history or troubleshooting a
    fault — NOT for topology, neighbors or cabling (use get_lldp_neighbors for
    that). Results are newest-first, so `limit` alone already returns the N
    MOST RECENT logs. priority: 0-7 or a range e.g. '0..3' (lower = more severe).
    daemon: filter by the process/module name that generated the message (CLI
    'show events' PROCESS column, e.g. 'lldpd', 'bgpd', 'hpe-restd'). since/until:
    'YYYY-MM-DD hh:mm:ss' or relative words like 'today', '1 hour ago'."""
    async with _get_client(device) as client:
        return await client.get_logs(limit=limit, priority=priority, daemon=daemon, since=since, until=until)


# ══════════════════════════════════════════════════════════════════════
# TOOLS — Spanning Tree
# ══════════════════════════════════════════════════════════════════════

@mcp.tool()
async def get_spanning_tree(device: str) -> dict:
    """Spanning tree."""
    async with _get_client(device) as client:
        return await client.get_spanning_tree()


# ══════════════════════════════════════════════════════════════════════
# TOOLS — BGP
# ══════════════════════════════════════════════════════════════════════

@mcp.tool()
async def get_bgp_neighbors(device: str, vrf: str = "default") -> dict:
    """BGP neighbors."""
    async with _get_client(device) as client:
        return await client.get_bgp_neighbors(vrf)


@mcp.tool()
async def get_bgp_config(device: str, vrf: str = "default") -> dict:
    """BGP config."""
    async with _get_client(device) as client:
        return await client.get_bgp_config(vrf)


@mcp.tool()
async def get_bgp_routes(device: str, vrf: str = "default", address_family: str = "ipv4-unicast") -> dict:
    """BGP routes."""
    async with _get_client(device) as client:
        return await client.get_bgp_routes(vrf, address_family)


@mcp.tool()
async def get_bgp_neighbor_routes(device: str, vrf: str = "default", neighbor: str = None,
                                  address_family: str = "ipv4-unicast",
                                  direction: str = "all") -> dict:
    """BGP advertised / received routes per neighbor, with path attributes
    (AS-path, origin, local-pref, MED, flags). `direction`: advertised | received
    | all. `neighbor` filters to a single peer IP. Backs the CLI
    `show bgp <af> neighbors <ip> advertised-routes` / `received-routes`."""
    async with _get_client(device) as client:
        return await client.get_bgp_neighbor_routes(vrf, neighbor, address_family, direction)


# ══════════════════════════════════════════════════════════════════════
# TOOLS — OSPF
# ══════════════════════════════════════════════════════════════════════

@mcp.tool()
async def get_ospf_overview(device: str, vrf: str = "default") -> dict:
    """OSPF overview."""
    async with _get_client(device) as client:
        return await client.get_ospf_overview(vrf)


@mcp.tool()
async def get_ospf_neighbors(device: str, vrf: str = "default") -> dict:
    """OSPF neighbors."""
    async with _get_client(device) as client:
        return await client.get_ospf_neighbors(vrf)


@mcp.tool()
async def get_ospf_interfaces(device: str, vrf: str = "default") -> dict:
    """OSPF interfaces."""
    async with _get_client(device) as client:
        return await client.get_ospf_interfaces(vrf)


