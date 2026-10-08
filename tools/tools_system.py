"""System/hardware, maintenance-mode, containers, licensing and Aruba Central
cloud-management tools, plus the interface-level tools (physical interfaces,
transceivers, PoE, loopbacks, routed ports, SVIs, LAG)."""

from core.server_core import mcp, _get_client

# ══════════════════════════════════════════════════════════════════════
# TOOLS — System
# ══════════════════════════════════════════════════════════════════════

@mcp.tool()
async def get_system_info(device: str) -> dict:
    """System info + synthetic hardware status (modules, PSU, fans, sensors)."""
    async with _get_client(device) as client:
        return await client.get_system_info()


@mcp.tool()
async def get_hardware_health(device: str) -> dict:
    """Detailed hardware status: modules, PSU, fans, temperature sensors, LEDs,
    with the list of detected anomalies."""
    async with _get_client(device) as client:
        return await client.get_hardware_health()


@mcp.tool()
async def get_capacities(device: str) -> dict:
    """System resource capacities and their current consumption (grouped):
    `capacities` (scale/hardware limits) + `capacities_status` (amount currently
    consumed). Equivalent to CLI `show capacities` + `show capacities-status`.
    Returns a `utilization` list (most-used first, with utilization_pct) plus the
    raw `capacities` and `capacities_status` maps."""
    async with _get_client(device) as client:
        return await client.get_capacities()


@mcp.tool()
async def get_boot_history(device: str) -> dict:
    """Reboot history: per module (management_module, line_card), list of reboots
    (timestamp, reason, version), last boot and cause counters
    (reboot_statistics)."""
    async with _get_client(device) as client:
        return await client.get_boot_history()


@mcp.tool()
async def list_troubleshoot_features(device: str, feature_name: str = None) -> dict:
    """List the on-device troubleshoot features and their components (AOS-CX
    Troubleshoot API, firmware 10.18+). Source: the
    `troubleshoot_feature_components` resource. Each feature exposes components
    with the check types they support (basic health / config check / operations).
    Pass `feature_name` to inspect a single feature. Returns supported=False on
    firmware older than 10.18 (Troubleshoot is unavailable there)."""
    async with _get_client(device) as client:
        return await client.list_troubleshoot_features(feature_name)


@mcp.tool()
async def run_troubleshoot(
    device: str,
    feature_name: str,
    choice: str = "health",
    component_name: str = None,
    user_input: str = None,
    verbose: bool = False,
    timeout: float = 120.0,
) -> dict:
    """Run an on-device automated troubleshoot/diagnostic (AOS-CX Troubleshoot
    API, firmware 10.18+) and return the structured result.

    - `feature_name`: feature to troubleshoot — discover valid names via
      list_troubleshoot_features (e.g. 'l3', 'multicast', 'system').
    - `choice`: run depth — 'basic-health' (health checks only), 'config'
      (configuration checks), 'health' (basic + config, default), 'operations'
      or 'detailed' (advanced feature troubleshoot).
    - `component_name` / `user_input`: optional narrowing / extra context.
    - `verbose`: also return verbose logs and raw error reports.

    Launches the run (POST), polls until completion (or `timeout` seconds), then
    removes the volatile instance. Returns the alerts (basic / config / advanced,
    each with severity, root cause and recommendation) plus the health, config
    and troubleshoot text results. Returns supported=False on firmware older than
    10.18."""
    async with _get_client(device) as client:
        return await client.run_troubleshoot(
            feature_name,
            choice=choice,
            component_name=component_name,
            user_input=user_input,
            verbose=verbose,
            timeout=timeout,
        )


@mcp.tool()
async def get_ssh_config(device: str) -> dict:
    """SSH server config: global parameters (port, algos, allow-list) and, per VRF,
    the activation (ssh_enable/ssh_server_status) and the source-interface."""
    async with _get_client(device) as client:
        return await client.get_ssh_config()



@mcp.tool()
async def get_transceivers(device: str, interface: str = None) -> dict:
    """Transceiver status (SFP/QSFP): connector, vendor, optical diagnostics (DOM)
    and alarms. `interface` to target a port, otherwise all."""
    async with _get_client(device) as client:
        return await client.get_transceivers(interface)


# ══════════════════════════════════════════════════════════════════════
# TOOLS — Interfaces
# ══════════════════════════════════════════════════════════════════════

@mcp.tool()
async def get_interfaces(device: str, interface: str = None) -> dict:
    """List interfaces."""
    async with _get_client(device) as client:
        return await client.get_interfaces(interface)


@mcp.tool()
async def get_interface_counters(device: str, interface: str = None) -> dict:
    """Interface traffic counters: rx/tx bytes & packets, error counters
    (CRC/frame/runts/giants), drops and aggregate totals. `interface` to target a
    port, otherwise all."""
    async with _get_client(device) as client:
        return await client.get_interface_counters(interface)


@mcp.tool()
async def get_supported_transceivers(device: str, search: str = None) -> dict:
    """Catalog of transceivers (SFP/QSFP/DAC ...) supported by the device
    (`show supported-transceivers`). `search` filters by product number or
    description."""
    async with _get_client(device) as client:
        return await client.get_supported_transceivers(search)


@mcp.tool()
async def get_poe_status(device: str, interface: str = None) -> dict:
    """PoE (Power over Ethernet) status: per-port power draw (watts/current/
    voltage), powering state (delivering/searching/denied/fault/…), powered-
    device type/class, plus the chassis-wide PoE power budget (available/
    drawn/reserved/redundant/failover power, in watts, supplied by the PSUs).
    `interface` to target a single port, otherwise every PoE-capable port is
    scanned. Use this to answer 'how much power is this site/switch/port
    drawing over PoE'."""
    async with _get_client(device) as client:
        return await client.get_poe_status(interface)


@mcp.tool()
async def get_loopbacks(device: str) -> dict:
    """List the loopback interfaces (loopback0/1, …): VRF and IP addresses.
    Loopbacks are typically used as router-id and VTEP source."""
    async with _get_client(device) as client:
        return await client.get_loopbacks()


@mcp.tool()
async def get_routed_ports(device: str, include_unconfigured: bool = False) -> dict:
    """List the routed (L3) ports: physical/LAG/sub-interfaces with routing
    enabled AND an IP address or a non-default VRF (point-to-point uplinks, L3
    links). Excludes L2 switched ports, VLAN SVIs and loopbacks.
    `include_unconfigured=true` also lists ports that are only routing-capable
    by default (e.g. every port of an 8360) without any L3 configuration."""
    async with _get_client(device) as client:
        return await client.get_routed_ports(include_unconfigured=include_unconfigured)


@mcp.tool()
async def get_vlan_interfaces(device: str) -> dict:
    """List the VLAN interfaces / SVIs (vlanN): the L3 gateways of the VLANs,
    with their VRF and IP addresses."""
    async with _get_client(device) as client:
        return await client.get_vlan_interfaces()


@mcp.tool()
async def get_lag(device: str, lag: str = None) -> dict:
    """Link aggregation (LAG / port-channel) status — for STATIC and LACP bonds.
    Returns each LAG's mode (static / lacp-active / lacp-passive), aggregate
    speed and state, member count, and per-member LACP actor/partner flags
    (synchronization / collecting / distributing) to pinpoint a degraded member.
    `lag` optional (e.g. 'lag256' or '256') — omit for all LAGs."""
    async with _get_client(device) as client:
        return await client.get_lag(lag)


# ══════════════════════════════════════════════════════════════════════
# TOOLS — Maintenance Mode
# ══════════════════════════════════════════════════════════════════════

@mcp.tool()
async def get_maintenance_mode(device: str) -> dict:
    """Maintenance Mode status: configured or not, active or not, applied profiles
    and units (BGP/OSPF feature-sets) under maintenance."""
    async with _get_client(device) as client:
        return await client.get_maintenance_mode()


# ══════════════════════════════════════════════════════════════════════
# TOOLS — Containers (on-switch application hosting)
# ══════════════════════════════════════════════════════════════════════

@mcp.tool()
async def get_containers(device: str, name: str = None) -> dict:
    """On-switch application containers: per container the enable flag, runtime
    `status`, `image_status`/version/location, manifest status, CPU/memory limits
    and attached VRF networks. Optional `name` to target one container. Returns
    supported=False (no error) when the container feature is absent."""
    async with _get_client(device) as client:
        return await client.get_containers(name)


# ══════════════════════════════════════════════════════════════════════
# TOOLS — Licensing (feature pack)
# ══════════════════════════════════════════════════════════════════════

@mcp.tool()
async def get_feature_pack(device: str) -> dict:
    """Licensing / feature-pack (subscription) state: installed pack name, type,
    management mode (cloud_managed/file_based/honor), validity `state`, expiration,
    designated platform/serials, and per-feature enforcement mode/state
    (active/strict/honor). Returns supported=False (no error) when licensing is
    not available on the platform/firmware."""
    async with _get_client(device) as client:
        return await client.get_feature_pack()


# ══════════════════════════════════════════════════════════════════════
# TOOLS — Aruba Central (HPE ANW Central) cloud management
# ══════════════════════════════════════════════════════════════════════

@mcp.tool()
async def get_aruba_central(device: str) -> dict:
    """HPE ANW Central (formerly Aruba Central) cloud-management state: whether the
    switch is connected, instantiation (public/on_premise), config source
    (cli/activate/dhcp), connected location, VRF and source IP used, plus
    operational status (connection state, disconnection reason, Activate
    connectivity). Returns supported=False (no error) when Central is not
    available on the platform/firmware."""
    async with _get_client(device) as client:
        return await client.get_aruba_central()




