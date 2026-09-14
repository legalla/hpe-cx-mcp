"""EVPN/VXLAN overlay and VSX/VSF redundancy read-only tools."""

from core.server_core import mcp, _get_client

# ══════════════════════════════════════════════════════════════════════
# TOOLS — EVPN
# ══════════════════════════════════════════════════════════════════════

@mcp.tool()
async def get_evpn_config(device: str, vni_id: int = None) -> dict:
    """EVPN config."""
    async with _get_client(device) as client:
        return await client.get_evpn_config(vni_id)


@mcp.tool()
async def get_evpn_routes(device: str, vrf: str = "default", route_type: int = None) -> dict:
    """EVPN routes."""
    async with _get_client(device) as client:
        return await client.get_evpn_routes(vrf, route_type)


@mcp.tool()
async def get_evpn_multihoming(device: str) -> dict:
    """EVPN multihoming (RFC 7432 Ethernet Segments): global multihoming-system-id
    plus, per Ethernet Segment, its ESI, mode (all-active), operational status,
    RD/import-RT, ES port, local/peer VTEPs and the per-VLAN Designated Forwarder
    election (which VTEP is the DF for each EVPN VLAN). Returns configured=False
    (no error) when the feature is not supported/configured."""
    async with _get_client(device) as client:
        return await client.get_evpn_multihoming()



# ══════════════════════════════════════════════════════════════════════
# TOOLS — VXLAN
# ══════════════════════════════════════════════════════════════════════

@mcp.tool()
async def get_vxlan_config(device: str) -> dict:
    """VXLAN config."""
    async with _get_client(device) as client:
        return await client.get_vxlan_config()


@mcp.tool()
async def get_vxlan_tunnels(device: str) -> dict:
    """Established VXLAN tunnels (EVPN + static) with traffic statistics."""
    async with _get_client(device) as client:
        return await client.get_vxlan_tunnels()


@mcp.tool()
async def get_vxlan_static_peers(device: str) -> dict:
    """Statically configured VXLAN peers (ingress replication list)."""
    async with _get_client(device) as client:
        return await client.get_vxlan_static_peers()


@mcp.tool()
async def get_evpn_vtep_neighbors(device: str, vrf: str = "default") -> dict:
    """VTEP neighbors learned dynamically via EVPN."""
    async with _get_client(device) as client:
        return await client.get_evpn_vtep_neighbors(vrf)


# ══════════════════════════════════════════════════════════════════════
# TOOLS — VSX (Virtual Switching Extension)
# ══════════════════════════════════════════════════════════════════════

@mcp.tool()
async def get_vsx_status(device: str) -> dict:
    """VSX status and member details (roles, system-mac, ISL, keepalive, peer).
    If VSX is not supported/configured, returns configured=False (no error)."""
    async with _get_client(device) as client:
        return await client.get_vsx_status()


@mcp.tool()
async def get_vsx_config(device: str) -> dict:
    """VSX configuration: role, system-mac, ISL and keepalive ports, timers, options.
    If VSX is not supported/configured, returns configured=False (no error)."""
    async with _get_client(device) as client:
        return await client.get_vsx_config()


@mcp.tool()
async def get_vsx_sync(device: str) -> dict:
    """Elements synchronized between VSX cluster members (vsx-sync).
    If VSX is not supported/configured, returns configured=False (no error)."""
    async with _get_client(device) as client:
        return await client.get_vsx_sync()


# ══════════════════════════════════════════════════════════════════════
# TOOLS — VSF (Virtual Switching Framework / stacking)
# ══════════════════════════════════════════════════════════════════════

@mcp.tool()
async def get_vsf_status(device: str) -> dict:
    """VSF stack status: members (role, status, memory), stack links, topology
    (ring/chain/standalone) and split detection. A single member = standalone."""
    async with _get_client(device) as client:
        return await client.get_vsf_status()


@mcp.tool()
async def get_vsf_config(device: str) -> dict:
    """VSF config: members (role, status, links), topology and split detection
    (method, secondary_member, traps). A single member = standalone."""
    async with _get_client(device) as client:
        return await client.get_vsf_config()


