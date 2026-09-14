"""NAE, port-access (802.1X / MAC-Auth), RADIUS/TACACS+/AAA and
GBP/ABP/App-Recognition read-only tools."""

from core.server_core import mcp, _get_client

# ══════════════════════════════════════════════════════════════════════
# TOOLS — NAE (Network Analytics Engine)
# ══════════════════════════════════════════════════════════════════════

@mcp.tool()
async def get_nae_scripts(device: str) -> dict:
    """List of installed NAE scripts with validation status and number of agents."""
    async with _get_client(device) as client:
        return await client.get_nae_scripts()


@mcp.tool()
async def get_nae_script(device: str, name: str, include_script: bool = False) -> dict:
    """NAE script detail (checksum, validation, errors). include_script=True
    includes the decoded content.
    """
    async with _get_client(device) as client:
        return await client.get_nae_script(name, include_script=include_script)


@mcp.tool()
async def get_nae_agents(device: str, script: str = None) -> dict:
    """NAE agents (policies) with state, alert level and errors. Filterable by script."""
    async with _get_client(device) as client:
        return await client.get_nae_agents(script)


@mcp.tool()
async def get_nae_agent(device: str, script: str, agent: str) -> dict:
    """Full detail of a NAE agent: status, alerts, errors, statistics, monitors, rules."""
    async with _get_client(device) as client:
        return await client.get_nae_agent(script, agent)


# ══════════════════════════════════════════════════════════════════════
# TOOLS — Port-Access (802.1X / MAC-Auth)
# ══════════════════════════════════════════════════════════════════════

@mcp.tool()
async def get_port_access_clients(
    device: str,
    interface: str = None,
    auth_method: str = None,
    status: str = None,
) -> dict:
    """Port-access clients: authentication status, method (802.1X/MAC-Auth/
    Web-Auth), applied role, assigned VLAN and RADIUS server."""
    async with _get_client(device) as client:
        return await client.get_port_access_clients(
            interface=interface, auth_method=auth_method, status=status
        )


@mcp.tool()
async def get_port_access_auth_config(device: str, interface: str = None) -> dict:
    """Per-port authentication config: configured methods (802.1X/MAC-Auth/
    Web-Auth), activation, reauth and RADIUS group — even without a connected
    client. `interface` to target a port."""
    async with _get_client(device) as client:
        return await client.get_port_access_auth_config(interface=interface)



@mcp.tool()
async def get_port_access_summary(device: str) -> dict:
    """Port-access summary."""
    async with _get_client(device) as client:
        return await client.get_port_access_summary()


@mcp.tool()
async def get_port_access_client_detail(device: str, interface: str, mac: str) -> dict:
    """Full detail of an authenticated client: VLAN, role, RADIUS attributes,
    failure reason, EAP method, 802.1X stats. `interface` (e.g. '1/1/5'), `mac`.
    """
    async with _get_client(device) as client:
        return await client.get_port_access_client_detail(interface, mac)


# ══════════════════════════════════════════════════════════════════════
# TOOLS — RADIUS / TACACS+ / AAA
# ══════════════════════════════════════════════════════════════════════

@mcp.tool()
async def get_radius_servers(device: str, vrf: str = None) -> dict:
    """RADIUS servers: address, port, reachability, group, tracking, auth/accounting
    stats. By default searches ALL VRFs (servers are usually in the mgmt VRF);
    pass `vrf` only to restrict to a single VRF.
    """
    async with _get_client(device) as client:
        return await client.get_radius_servers(vrf)


@mcp.tool()
async def get_tacacs_servers(device: str, vrf: str = None) -> dict:
    """TACACS+ servers: address, TCP port, reachability, group, auth stats. By
    default searches ALL VRFs (servers are usually in the mgmt VRF); pass `vrf`
    only to restrict to a single VRF.
    """
    async with _get_client(device) as client:
        return await client.get_tacacs_servers(vrf)


@mcp.tool()
async def get_aaa_authentication(device: str) -> dict:
    """AAA config: server groups and lookup order per session type
    (802.1x, MAC-auth, mgmt…) for auth/authz/accounting.
    """
    async with _get_client(device) as client:
        return await client.get_aaa_authentication()


@mcp.tool()
async def get_aaa_accounting(device: str, with_logs: bool = False, limit: int = 50) -> dict:
    """AAA accounting config per session type. with_logs=True includes the latest
    logs (limit, default 50).
    """
    async with _get_client(device) as client:
        return await client.get_aaa_accounting(with_logs=with_logs, limit=limit)


# ══════════════════════════════════════════════════════════════════════
# TOOLS — Port-Access Policies / Roles
# ══════════════════════════════════════════════════════════════════════

@mcp.tool()
async def get_port_access_policies(device: str, policy_name: str = None) -> dict:
    """Port Access Policies: rules (QoS, ACL, redirection) applied to clients.
    `policy_name` for the detail of a policy.
    """
    async with _get_client(device) as client:
        return await client.get_port_access_policies(policy_name)


@mcp.tool()
async def get_port_access_roles(device: str, role_name: str = None) -> dict:
    """Port Access Roles: profiles assigned to clients (VLAN, QoS, reauth, policy,
    captive portal…). `role_name` for the full detail.
    """
    async with _get_client(device) as client:
        return await client.get_port_access_roles(role_name)


# ══════════════════════════════════════════════════════════════════════
# TOOLS — GBP / ABP / App Recognition
# ══════════════════════════════════════════════════════════════════════

@mcp.tool()
async def get_port_access_gbps(device: str, gbp_name: str = None) -> dict:
    """Group-Based Policies: policies between groups (SGT/GBP tag). `gbp_name` for
    the detail (class/drop/reflect entries, stats).
    """
    async with _get_client(device) as client:
        return await client.get_port_access_gbps(gbp_name)


@mcp.tool()
async def get_gbp_role_maps(device: str) -> dict:
    """Mapping GBP role name ↔ role-id (interprets the SGT/GBP tags of clients).
    """
    async with _get_client(device) as client:
        return await client.get_gbp_role_maps()


@mcp.tool()
async def get_port_access_abps(device: str, abp_name: str = None) -> dict:
    """Application-Based Policies (ABP): policies based on ARC (QoS, drop,
    mirroring per application). `abp_name` for the detail (entries, stats).
    """
    async with _get_client(device) as client:
        return await client.get_port_access_abps(abp_name)


@mcp.tool()
async def get_app_recognition(device: str, include_apps: bool = False) -> dict:
    """ARC (Application Recognition and Control): status, detection mode, ABP
    session limit. include_apps=True adds the list of applications (large).
    """
    async with _get_client(device) as client:
        return await client.get_app_recognition(include_apps=include_apps)


@mcp.tool()
async def get_app_visibility(
    device: str,
    top_n: int = 10,
    include_flows: bool = True,
    include_monitors: bool = True,
) -> dict:
    """Application visibility collector (Traffic Insight + ARC), 100% via REST API
    (no SSH). First checks the prerequisites — App Recognition (ARC) active and
    operational, Traffic Insight enabled, ARC applied on interfaces or
    user-roles — then collects the application flows and returns the top talkers
    (by client, destination, application, category) as well as the TopN reports
    of the Traffic Insight monitors. The `blockers` field details any missing prerequisite.

    top_n: number of entries per ranking. include_flows / include_monitors:
    enable collection of application flows and TopN monitors respectively.
    """
    async with _get_client(device) as client:
        return await client.get_app_visibility(
            top_n=top_n,
            include_flows=include_flows,
            include_monitors=include_monitors,
        )


