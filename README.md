# ArubaOS-CX MCP Server (`hpe-cx-mcp`)

A [Model Context Protocol](https://modelcontextprotocol.io) (MCP) server that
exposes **Aruba CX (AOS-CX)** switches to MCP-capable AI agents (Claude, VS Code
Copilot, etc.). It turns the switch REST API (`/rest/v10.x`) and the SSH CLI into
a curated set of safe, structured tools for **observability, troubleshooting and
configuration** of a campus / data-center fabric (VLANs, routing, BGP/OSPF,
EVPN-VXLAN, VSX/VSF, port access / 802.1X, NAE, ARC…).

The server runs as a Docker container, speaks MCP over **streamable HTTP**, and
ships with optional **named Bearer-token authentication** and **JSON audit
logging**.

---

## Quick start

```bash
cd cx-mcp

# 1) Provide credentials (git-ignored)
cp .env.example .env                 # then edit: set ARUBA_DEFAULT_PASSWORD (and any source tokens)

# 2) Provide the device list (git-ignored)
cp inventory/inventory.example.yaml inventory/inventory.yaml   # then edit: your switches & IPs

# 3) Build and start
docker compose up -d --build

# 4) Watch it come up
docker compose logs -f hpe-cx-mcp    # wait for "✅ hpe-cx-mcp server is up and running"
```

The MCP endpoint is then available at **`http://<docker-host>:8002/mcp`**. Point
your MCP client at it (see [§10](#10-connecting-an-mcp-client)). Full details and
platform notes are in [§3](#3-installation-macos--linux--windows).

---

## Table of contents

1. [What this server does](#1-what-this-server-does)
2. [Available tools](#2-available-tools)
3. [Installation (macOS / Linux / Windows)](#3-installation-macos--linux--windows)
4. [Volumes](#4-volumes)
5. [Environment variables](#5-environment-variables)
6. [Inventory management](#6-inventory-management)
7. [Security: Bearer auth & audit logging](#7-security-bearer-auth--audit-logging)
8. [Token management](#8-token-management)
9. [Operations runbook](#9-operations-runbook)
10. [Connecting an MCP client](#10-connecting-an-mcp-client)
11. [Prompts (guided operations) & skills](#11-prompts-guided-operations--skills)

---

## 1. What this server does

- **Single entry point** to a fleet of AOS-CX switches described in an inventory.
- **Read (observe)**: interfaces, VLANs, routing/ARP/MAC tables, BGP/OSPF/EVPN,
  VXLAN tunnels, VSX/VSF stack state, hardware health, logs, 802.1X / port-access,
  NAE scripts, application recognition (ARC), full configs.
- **Write (configure)**: VLAN services, VLANs/SVIs/trunks, LAGs (static, LACP,
  MC-LAG, EVPN multihoming), loopbacks, routed ports, VRFs, static routes,
  BGP, OSPF, redistribution, EVPN/VXLAN, VSX, DHCP relay, port groups,
  port authentication, virtual-MAC, ARC — each paired with a **`verify_*`**
  read-back tool.
- **Orchestrate**: multi-step workflows (VSX pair, L3 links, access ports,
  RADIUS/802.1X, VXLAN overlay and VLAN services, full fabric underlay/overlay)
  in one plan → apply call, with a per-device checkpoint.
- **Safety rails**:
  - Per-device **`access_mode`** (`read-only` by default; writes are denied unless
    a device is explicitly `read-write`).
  - **Site-scoped** operations (`site` parameter) to act on a group of devices.
  - **SSH write-command detection** to block configuration changes via raw CLI on
    read-only devices.
- **Dynamic inventory**: merge the local file with **NetBox / Nautobot** sources of
  truth, with optional **HashiCorp Vault** credential resolution.

---

## 2. Available tools

Tools are grouped by purpose. Read tools require a device to be reachable; write
tools additionally require the device to be `read-write`.

### Inventory & sessions
| Tool | Role |
|------|------|
| `list_devices` | List inventory devices (optional `site` filter). |
| `list_sites` | List sites and their attached devices. |
| `list_inventory_sources` | List configured sources and their priority (`probe` to test reachability). |
| `find_devices` | Search devices by name/site/tenant/tag/custom field across sources. |
| `resolve_device` | Resolve a device by name or management IP across all sources. |
| `refresh_inventory` | Reload the local file and re-pull external sources. |
| `run_on_site` | Run a read-only diagnostic on every device of a site. |
| `logout` | Close pooled REST/SSH sessions (call at end of a workflow). |

### Raw access (escape hatches)
| Tool | Role |
|------|------|
| `run_ssh_command` / `run_ssh_commands` | **Primary** CLI escape hatch: run arbitrary CLI command(s) over SSH (output not exposed by REST). |
| `run_cli_command` | **Fallback** for `show` commands via `/cli` (REST/443) — use when SSH/22 is unavailable; `/cli` is limited and refuses many commands. |
| `get_cli_supported_commands` | Try to list CLI commands supported via REST `/cli`. |
| `get_raw_api` | Raw GET against an arbitrary REST path. |

### System & hardware
`get_system_info`, `get_hardware_health`, `get_boot_history`, `get_transceivers`,
`get_ssh_config`, `get_logs`, `get_poe_status` (Power-over-Ethernet: per-port
draw in watts/amps/volts, powering state, powered-device class, plus the
chassis-wide PoE power budget).

### Containers & licensing
`get_containers` (on-switch application containers: status, image, CPU/memory
limits, VRF networks), `get_feature_pack` (licensing / subscription state:
management mode, validity, expiration, per-feature enforcement).

### Cloud management
`get_aruba_central` (HPE ANW Central / Aruba Central connection state: connected,
instantiation, config source, location, VRF/source IP, Activate connectivity).

### L2 / L3 state
`get_interfaces`, `get_loopbacks`, `get_routed_ports`, `get_vlan_interfaces`,
`get_vlans`, `get_lldp_neighbors`, `get_mac_table`, `get_arp_table`,
`get_routing_table`, `get_spanning_tree`.

### Routing protocols
`get_bgp_neighbors`, `get_bgp_config`, `get_bgp_routes`, `get_ospf_overview`,
`get_ospf_neighbors`, `get_ospf_interfaces`.

### EVPN / VXLAN
`get_evpn_config`, `get_evpn_routes`, `get_evpn_multihoming`, `get_vxlan_config`,
`get_vxlan_tunnels`, `get_vxlan_static_peers`, `get_evpn_vtep_neighbors`.

### High availability (VSX / VSF)
`get_vsx_status`, `get_vsx_config`, `get_vsx_sync`, `get_vsf_status`,
`get_vsf_config`, `get_maintenance_mode`.

### NAE (Network Analytics Engine)
`get_nae_scripts`, `get_nae_script`, `get_nae_agents`, `get_nae_agent`.

### Port access / AAA / 802.1X
`get_port_access_clients`, `get_port_access_client_detail`,
`get_port_access_auth_config`, `get_port_access_summary`,
`get_port_access_policies`, `get_port_access_roles`, `get_port_access_gbps`,
`get_gbp_role_maps`, `get_port_access_abps`, `get_radius_servers`,
`get_tacacs_servers`, `get_aaa_authentication`, `get_aaa_accounting`.

### Application Recognition & Control (ARC)
`get_app_recognition`, `get_app_visibility`.

### Configuration management
`list_configs`, `get_config`, `get_full_config`, `compare_configs`,
`manage_config` (save / checkpoint / rollback), `backup_config` (export
campaign to an external SFTP/TFTP server, see [§5](#5-environment-variables)).

### Configure (write) + verify pairs
Each `configure_*` tool has a matching `verify_*` read-back tool:

| Configure | Verify | Scope |
|-----------|--------|-------|
| `create_vlan_service` / `delete_vlan_service` | — | VLAN + optional SVI |
| `configure_loopback` | `verify_loopback` | Loopback (router-id / VTEP source) |
| `configure_routed_port` | `verify_routed_port` | L3 port |
| `configure_vxlan_interface` | `verify_vxlan_interface` | VTEP |
| `configure_evpn` | `verify_evpn` | Global EVPN |
| `configure_ospf` | `verify_ospf` | OSPF instance |
| `configure_bgp` | `verify_bgp` | BGP router |
| `configure_vrf` | `verify_vrf` | VRF + route-targets |
| `configure_port_auth` | `verify_port_auth` | 802.1X / MAC-Auth |
| `configure_app_recognition` | `verify_app_recognition` | ARC |
| `configure_virtual_mac` | `verify_virtual_mac` | Global EVPN virtual-MAC |
| `configure_vlan` | `verify_vlan` | VLAN(s), single or batch (`vlans=[…]`) |
| `configure_svi` | `verify_svi` | SVI + active-gateway |
| `configure_trunk` | `verify_trunk` | Trunk port allowed / native VLANs |
| `configure_lag` | `verify_lag` | LAG: static, LACP, MC-LAG (VSX), EVPN multihoming (ESI) |
| `configure_interface_admin` | `verify_interface_admin` | Port admin up/down |
| `configure_interface_group` | `verify_interface_group` | Port-group speed (`system interface-group`) |
| `configure_dhcp_relay` | `verify_dhcp_relay` | DHCP relay (IP helper) per interface/VRF |
| `configure_hostname` | `verify_hostname` | Hostname (single or batch) |
| `configure_static_route` | `verify_static_route` | Static routes + next-hops |
| `configure_redistribute` | `verify_redistribute` | BGP/OSPF redistribution |
| `configure_vsx` | `verify_vsx` | VSX pairing (asymmetric per peer) |
| `configure_aaa` / `configure_user_roles` | `verify_aaa` / `verify_user_roles` | AAA, local user roles |

### Orchestrators (multi-step writes)
Each orchestrator builds one ordered step list per device, runs it inside a
single auto-checkpoint and stops at the first failing step (the switch then
reverts). Plan mode shows every step and, for the fabric tools, the IP
allocation, without writing anything.

| Orchestrator | Verify | Does |
|--------------|--------|------|
| `orchestrate_vsx_pair` | `verify_vsx_cluster` | Keepalive VRF/port, ISL LAG, VSX pairing (or full teardown with `delete=true`). |
| `orchestrate_l3_link` | `verify_routed_port` | Routed P2P link(s) + optional VRF/OSPF; batch with `links=[…]`. |
| `orchestrate_access_port` | `verify_access_port` | L2 access port(s) + STP guards + 802.1X. |
| `orchestrate_radius_dot1x` | `verify_radius_dot1x` | RADIUS servers/group + global AAA + per-port 802.1X. |
| `orchestrate_overlay` | `verify_overlay` | Device-level VTEP: VXLAN interface, global EVPN, virtual-MAC, optional BGP-EVPN (`mode` = `evpn`/`stub`/`static`). |
| `orchestrate_overlay_service` | `verify_overlay_service` | Batch of VLAN → L2VNI → EVPN RT and/or static peers (`attach` = `evpn`/`static`/`stub`). |
| `orchestrate_evpn_vlan` / `orchestrate_static_vxlan` | `verify_evpn_vlan` / `verify_static_vxlan` | Legacy single-service variants (prefer `overlay_service`). |
| `orchestrate_fabric_underlay` | — | Whole fabric underlay: loopback0/1 and /31 P2P addressing from pools, OSPF P2P, cabling from LLDP or explicit. |
| `orchestrate_fabric_overlay` | — | Whole iBGP-EVPN control plane (spines as route reflectors), VXLAN interface and virtual-MAC on every leaf. |

Per-device values (`ip_address`, `source_ip`, `virtual_mac`, `router_id`) accept
a `{device: value}` mapping or `loopback0`/`auto`. A shared literal is refused
unless the devices sharing it are one VSX pair. VSF secondary members are refused
as targets (address the conductor instead).

> **Write protection**: a `configure_*` / `create_*` / `delete_*` / `manage_config`
> call on a `read-only` device is refused. Mark the device `access_mode: read-write`
> in the inventory to allow changes.

### Tool exposure: flat toolset (default) vs legacy atomic tools

The server can expose its capabilities in two **mutually exclusive** ways, chosen
by the `CX_FLAT_TOOLSET` flag (see [§5](#5-environment-variables)):

**Flat toolset (`CX_FLAT_TOOLSET=true` — the default).** The atomic tools
listed above are collapsed into **19 flat dispatchers** (plus the 10 kept-atomic
tools below — 29 tools advertised in total) driven by a `scope` (and, for
writes, an `action`) argument. The underlying REST client code is
unchanged — the dispatchers only *route* to it, so there is no behavioural
regression. Every read dispatcher also accepts **`device: str | list`**, **`site`**
or **`source`** (an external source-of-truth query) and fans the call out in
parallel, returning one envelope `{scope, results, errors, summary}`. An optional
`limit` caps long list fields in the response.

| Dispatcher | `scope` values |
|------------|----------------|
| `get_system` | `info`, `environment`, `capacity`, `boot`, `maintenance`, `containers`, `feature_pack`, `central`, `ssh`, `supported_transceivers` |
| `get_interfaces` | `physical` (incl. `l1_state` / down reason), `transceivers`, `counters`, `supported_transceivers`, `poe`, `loopbacks`, `routed`, `svi`, `lag`, `dhcp_relay`, `interface_group` |
| `get_switching` | `vlans`, `mac`, `lldp`, `spanning_tree` |
| `get_routing` | `bgp_summary`, `bgp_neighbors`, `bgp_config`, `bgp_routes`, `neighbor_routes`, `ospf_overview`, `ospf_neighbors`, `ospf_interfaces`, `route_table`, `arp` |
| `get_overlay` | `evpn_config`, `evpn_routes`, `evpn_multihoming`, `vtep_neighbors`, `vxlan_config`, `vxlan_tunnels`, `vxlan_static_peers` |
| `get_redundancy` | `vsx_status`, `vsx_config`, `vsx_sync`, `vsf_status`, `vsf_config` |
| `get_access` | `clients`, `client_detail`, `auth_config`, `summary`, `roles`, `gbp`, `gbp_maps`, `abp`, `policies`, `radius`, `tacacs`, `authentication`, `accounting` |
| `get_automation` | `nae_scripts`, `nae_script`, `nae_agents`, `nae_agent` |
| `get_apps` | `recognition`, `visibility` |
| `get_config` | `running`, `startup`, `full`, `list`, `compare`, `raw` |
| `manage_inventory` | `sources`, `resolve`, `refresh`, `find` |
| `configure_interface` | `loopback`, `routed_port`, `lag`, `vxlan`, `virtual_mac`, `vlan`, `svi`, `trunk`, `admin`, `dhcp_relay`, `interface_group`, `hostname`, `l3_link`, `access_port`, `static_vxlan`, `overlay`, `overlay_service` — `action`: `plan`/`apply`/`verify` |
| `configure_routing` | `ospf`, `bgp`, `vrf`, `evpn`, `static_route`, `redistribute`, `evpn_vlan` — `action`: `plan`/`apply`/`verify` |
| `configure_security` | `port_auth`, `aaa`, `user_roles`, `app_recognition`, `radius_dot1x` — `action`: `plan`/`apply`/`verify` |
| `configure_redundancy` | `vsx`, `vsx_pair` — `action`: `plan`/`apply`/`verify` |
| `configure_service` | `vlan` — `action`: `plan`/`apply`/`delete`/`delete_plan`/`verify` |
| `orchestrator` | `name`: `vsx_pair`, `l3_link`, `access_port`, `static_vxlan`, `evpn_vlan`, `radius_dot1x`, `overlay`, `overlay_service` — same orchestrators as the scopes above, one entry point |
| `diagnose` | `device`, `evpn`, `client` (deterministic multi-check bundle) |
| `troubleshoot` | omit `feature_name` to list supported features/components; pass it to run (`choice`: `basic-health`/`config`/`health`/`operations`/`detailed`) — AOS-CX 10.18+ |

Plus 10 kept-atomic tools: `list_devices`, `list_sites`, `get_logs`,
`run_ssh_commands`, `manage_config`, `backup_config`, `logout`, `rollback`,
`orchestrate_fabric_underlay`, `orchestrate_fabric_overlay` (these two take
`spines`/`leafs` lists instead of a single `device`). Write dispatchers keep
the **plan → apply → verify** lifecycle and the per-device read-only guard. Domain
fields are passed in a `params` object (keys documented in each dispatcher's
docstring).

**Legacy atomic tools (`CX_FLAT_TOOLSET=false`).** The full per-tool catalog above
is exposed instead, optionally shaped by the three layers below. Use this for an
instant rollback to the previous behaviour.

### Progressive disclosure, functional prefixes & write safety (legacy mode only)

Three optional layers (active only when `CX_FLAT_TOOLSET=false`, each gated
by its own env flag — see [§5](#5-environment-variables)) shape how the legacy
tools are exposed:

**1. Progressive disclosure (`CX_DEFERRED_TOOLS`)** — instead of advertising the
full catalog (100+ tools), the server publishes only ~27 **Tier-1** tools (the
most-used read/diagnostic tools, the escape hatches, the orchestrators and the
meta-tools). Every other tool is **deferred (Tier-2)** and reached on demand via
two meta-tools:

| Meta-tool | Role |
|-----------|------|
| `search_tools` | Discover deferred tools by keyword. Returns each match's name, description, tags, `write` flag and JSON-Schema parameters. |
| `invoke_tool` | Execute a deferred tool by name with an `arguments` object matching its schema. Returns `{ok, tool, result}`. |

This keeps the agent's tool list small and cheap while leaving the entire surface
reachable.

**2. Functional prefixes (`CX_TOOL_PREFIXES`)** — advertised tools are renamed
`<domain>__<tool>` to group them by domain, e.g. `routing__get_bgp_neighbors`,
`overlay__configure_evpn`, `service__create_vlan_service`, `meta__invoke_tool`.
Domains: `inventory`, `exec`, `system`, `interface`, `switching`, `routing`,
`overlay`, `redundancy`, `security`, `app`, `nae`, `config`, `service`, `meta`.
`invoke_tool` accepts either the prefixed or the bare name.

**3. Write safety (`CX_WRITE_SAFETY`)** — a preview→apply workflow with rollback:

| Meta-tool | Role |
|-----------|------|
| `apply_plan` | Apply a previewed write by its `dry_run_token`. Re-previews to confirm the plan is unchanged (TOCTOU guard), then applies and returns a `rollback_id` when the plan is reversible. |
| `rollback` | Undo a reversible applied write by its `rollback_id` (replays inverse actions last-created-first; currently the VLAN-service workflow). |

Workflow: call any write tool with `apply=false` (the default) to get a plan **and**
a `dry_run_token`; then call `apply_plan(dry_run_token=…)` to apply that exact plan.
Idempotent `configure_*` merges have no automatic inverse and are reported as
`unsupported` by `rollback`. When `CX_REQUIRE_DRY_RUN_TOKEN=true` (the shipped
default), a direct apply is refused on **every** write path:

- **Flat toolset** (`configure_interface` / `configure_routing` /
  `configure_security` / `configure_service`): `action=plan` returns a
  `dry_run_token`; `action=apply` (or `delete`) must pass `dry_run_token=…`
  with the same `params`. The plan is re-computed and hash-compared before the
  write (TOCTOU guard), the token is single-use, and a `rollback_id` is
  attached when the plan is reversible.
- **Legacy layer**: `apply=true` through `invoke_tool` is refused — use the
  preview→`apply_plan` path.

---

## 3. Installation (macOS / Linux / Windows)

### Prerequisites
- **Docker** and **Docker Compose v2** (`docker compose …`).
  - macOS / Windows: [Docker Desktop](https://www.docker.com/products/docker-desktop/).
  - Linux: Docker Engine + the Compose plugin.
- Network reachability from the Docker host to the switches' management IPs
  (HTTPS/443 for REST, TCP/22 for SSH).
- **REST access must be configured on the target devices and in the correct VRF**:
  in **Read-Write** mode for Read and Write access, and **Read-only** mode for
  read-only access.
- **SSH access must also be configured** on the target devices for the tools that
  require it.

### Configure (first run)

Secrets and deployment-specific settings live **outside** `docker-compose.yml`,
in files that are **git-ignored** so they are never committed. Two templates are
shipped — copy each one and fill it in:

```bash
cd cx-mcp

# 1) Credentials & external source tokens  →  .env  (git-ignored)
cp .env.example .env
#    then edit .env and set at least ARUBA_DEFAULT_PASSWORD

# 2) Device inventory  →  inventory/inventory.yaml  (git-ignored)
cp inventory/inventory.example.yaml inventory/inventory.yaml
#    then edit it: list your switches, their IPs and per-device access_mode
```

`.env` is injected into the container via `env_file:` in `docker-compose.yml`.
Minimum content (see [`.env.example`](.env.example) for the full list):

```dotenv
ARUBA_DEFAULT_USERNAME=admin
ARUBA_DEFAULT_PASSWORD=your-switch-password
ARUBA_API_VERSION=latest
# Optional external sources of truth (leave empty if unused):
NETBOX_URL=
NETBOX_TOKEN=
INFRAHUB_URL=
INFRAHUB_TOKEN=
```

> **Never commit `.env` or `inventory/inventory.yaml`** — they hold real
> credentials and device IPs. Only the `*.example` templates are tracked by git.

### Build & start (all platforms)
```bash
cd cx-mcp
docker compose up -d --build
```
The server listens on **`http://<host>:8002/mcp`** (host port `8002` → container
`8000`, see `docker-compose.yml`). The image is built as `hpe-cx-mcp:latest` and
runs as the container `hpe-cx-mcp`.

Check it is running:
```bash
docker compose logs -f hpe-cx-mcp
# look for, in order:
#   "Uvicorn running on http://0.0.0.0:8000"
#   "✅ hpe-cx-mcp server is up and running on http://0.0.0.0:8000 — if your agent
#    already has an open MCP connection, reset it (MCP: Disconnect → Connect) …"
```
The `✅ … server is up and running` line is emitted once the listener is ready.
If startup fails instead, the server logs `❌ hpe-cx-mcp server failed to start`
followed by the full traceback (then exits non-zero).

> **Note:** every `docker compose up -d --build` rebuilds the image and restarts
> the server, which invalidates any existing MCP session. After a rebuild,
> reconnect your client (**MCP: Disconnect → Connect**) to pick up the current tools.

### Platform notes

**Linux**
- Bind-mounted folders are owned by your host user. The container runs as
  **uid 1000**; if your host user is not uid 1000, make the writable folders
  readable/writable by uid 1000:
  ```bash
  mkdir -p logs secrets
  sudo chown -R 1000:1000 logs secrets
  chmod 700 secrets
  ```
- To reach switches on the host's local L2 network you may uncomment
  `network_mode: host` in `docker-compose.yml` (Linux only).

**macOS (Docker Desktop)**
- File sharing is handled by the VM; bind mounts work out of the box and uid
  remapping is automatic — no manual `chown` needed in most cases.
- `network_mode: host` is **not** supported the same way as on Linux; keep the
  default `ports:` mapping (`8002:8000`).

**Windows (Docker Desktop + WSL2)**
- Run the commands from a **WSL2** shell or PowerShell. Storing the project
  **inside the WSL2 filesystem** (e.g. `\\wsl$\…` / `~/cx-mcp`) is strongly
  recommended for correct file permissions and performance.
- Use forward slashes in `docker-compose.yml` volume paths (`./inventory:/app/inventory:ro`).
- `network_mode: host` is not available; keep the `ports:` mapping.

---

## 4. Volumes

Three host folders are mounted into the container:

| Host path | Container path | Mode | Purpose |
|-----------|----------------|------|---------|
| `./inventory` | `/app/inventory` | **read-only** (`:ro`) | Device inventory (`inventory.yaml`). Read-only so the server can never alter it. |
| `./logs` | `/app/logs` | read-write | Audit log output (`audit.jsonl`) when audit is enabled. |
| `./secrets` | `/app/secrets` | read-write | Named Bearer tokens (`.tokens`, perms `0600`). |

```yaml
volumes:
  - ./inventory:/app/inventory:ro
  - ./logs:/app/logs
  - ./secrets:/app/secrets
```

> The application **code is baked into the image** — only these data folders are
> mounted. After changing any `*.py`, rebuild with `docker compose up -d --build`
> (a plain restart is not enough).

**Ownership** (Linux): `logs/` and `secrets/` must be writable by container uid
1000. `secrets/` should be `0700` and its `.tokens` file is written `0600` by the
server itself.

---

## 5. Environment variables

Secrets and deployment-specific values (credentials, external-source tokens) are
provided through the git-ignored **`.env`** file, which `docker-compose.yml`
loads via `env_file:` (copy [`.env.example`](.env.example) to `.env`, see
[§3](#3-installation-macos--linux--windows)). Non-secret operational flags
(`MCP_*`, `CX_*`, `INVENTORY_FILE`) are set directly in `docker-compose.yml`
under `environment:`. Booleans accept `true/1/yes/on`.

### Transport
| Variable | Default | Description |
|----------|---------|-------------|
| `MCP_TRANSPORT` | `streamable-http` | MCP transport. |
| `MCP_HOST` | `0.0.0.0` | Bind address inside the container. |
| `MCP_PORT` | `8000` | Bind port inside the container (mapped to host `8002`). |
| `CX_MCP_PATH` | `/mcp` | URL path guarded by the security middleware. |

### Device credentials & API (set in `.env`; overridable per device in the inventory)
| Variable | Default | Description |
|----------|---------|-------------|
| `ARUBA_DEFAULT_USERNAME` | `admin` | Default REST/SSH username. |
| `ARUBA_DEFAULT_PASSWORD` | *(empty)* | Default password. **Required** unless set per device. |
| `ARUBA_API_VERSION` | `v10.09` | Default REST API version (`latest` = auto-detect). |
| `ARUBA_SSH_PORT` | `22` | Default SSH port. |

### Inventory & external sources
| Variable | Default | Description |
|----------|---------|-------------|
| `INVENTORY_FILE` | `/app/inventory/inventory.yaml` | Path to the inventory file (YAML/JSON/TOML). |
| `NETBOX_URL` / `NETBOX_TOKEN` | — | NetBox source connection (set in `.env`). |
| `NAUTOBOT_URL` / `NAUTOBOT_TOKEN` | — | Nautobot source connection (set in `.env`). |
| `INFRAHUB_URL` / `INFRAHUB_TOKEN` | — | Infrahub source connection (GraphQL API; set in `.env`). |
| `<NAME>_URL` / `<NAME>_TOKEN` | — | Generic per-named-source connection. |
| `VAULT_ADDR` / `VAULT_TOKEN` | — | HashiCorp Vault for credential resolution. |

### SFTP/TFTP configuration backups
| Variable | Default | Description |
|----------|---------|-------------|
| `CX_BACKUP_SFTP_HOST` | — | Approved SFTP backup server. A `server` passed to `backup_config` must match it. |
| `CX_BACKUP_SFTP_USERNAME` / `CX_BACKUP_SFTP_PASSWORD` | — | SFTP credentials; set in `.env`, never in MCP arguments. |
| `CX_BACKUP_SFTP_PORT` | `22` | SFTP port. |
| `CX_BACKUP_SFTP_DIRECTORY` | `/` | Default absolute directory on the SFTP server. |
| `CX_BACKUP_SFTP_ALLOWED_HOSTS` | — | Optional comma-separated target allow-list. |
| `CX_BACKUP_SFTP_TIMEOUT` | `30` | Connection and transfer timeout in seconds. |
| `CX_BACKUP_TFTP_HOST` | — | Approved TFTP backup server. A `server` passed to `backup_config(protocol="tftp")` must match it. |
| `CX_BACKUP_TFTP_PORT` | `69` | TFTP port. |
| `CX_BACKUP_TFTP_DIRECTORY` | `/` | Default relative directory prefix on the TFTP server. |
| `CX_BACKUP_TFTP_ALLOWED_HOSTS` | — | Optional comma-separated target allow-list. |
| `CX_BACKUP_TFTP_TIMEOUT` | `30` | Transfer timeout in seconds. |

Use `backup_config` to run an export campaign for a `device` or an entire
`site`. `protocol="sftp"` is the default; `protocol="tftp"` is available for
legacy backup servers but has neither encryption nor authentication, so use it
only on a trusted management network. It transfers `running-config` by default (or `startup-config`) and
returns the remote path and byte count per device, never the configuration
content. The default filename is `{hostname}_{timestamp}_config.cfg`; pass
`filename_format` to change it. Only `{hostname}` and UTC `{timestamp}`
(`YYYYMMDDTHHMMSSZ`) are permitted.

### TLS verification towards the switches
| Variable | Default | Description |
|----------|---------|-------------|
| `ARUBA_VERIFY_SSL` | `true` | Default `verify_ssl` for every device and inventory source. Inventory `defaults.verify_ssl` / per-device `verify_ssl` override it. Keep `true` in production; opt out per lab inventory, not globally. |
| `ARUBA_CA_BUNDLE` | `/app/certs/ca-bundle.pem` | PEM chain of the internal CA that signed the switch certificates (mount `./certs:/app/certs:ro`). Falls back to the system trust store when the file is absent. |

### Bearer authentication (ON in the shipped compose)
| Variable | Default | Description |
|----------|---------|-------------|
| `CX_AUTH_ENABLED` | `false` | Require a valid Bearer token on every request. **If enabled with no token yet, the server starts in LOCKED mode and refuses every MCP request with HTTP 503 until you create the first token and hot-reload (`security/cx_reload.py`).** Issue **one token per client**; revoke on off-boarding. |
| `CX_TOKENS_FILE` | `/app/secrets/.tokens` | Token store path. |
| `CX_TRUST_FORWARDED_FOR` | `false` | Trust `X-Forwarded-For` (first hop) for client IP. Set `true` **only** behind a trusted reverse proxy. |

### Audit logging (ON in the shipped compose, `writes`)
| Variable | Default | Description |
|----------|---------|-------------|
| `CX_AUDIT_ENABLED` | `false` | Emit a JSON record per tool call. |
| `CX_AUDIT_FILE` | `/app/logs/audit.jsonl` | Output file (rotating, 10 MB × 5) on the `./logs` volume. |
| `CX_AUDIT_LEVEL` | `all` | `all` = every call; `writes` = only state-changing tools. |
| `CX_AUDIT_STDOUT` | `false` | Also mirror records to stdout so the Docker logging driver can ship them (Loki/SIEM). |

### Progressive disclosure, prefixes & write safety (optional)
| Variable | Default | Description |
|----------|---------|-------------|
| `CX_FLAT_TOOLSET` | `true` | Collapse the atomic tools into 19 flat `scope`/`action` dispatchers (29 tools advertised total, incl. 10 kept-atomic). Takes precedence: when on, the three layers below are skipped. Set `false` to opt back into the legacy atomic tools. |
| `CX_DEFERRED_TOOLS` | `false` | (Legacy mode only) Advertise only Tier-1 tools; reach the rest via `search_tools` / `invoke_tool`. |
| `CX_TOOL_PREFIXES` | `false` | (Legacy mode only) Rename advertised tools `<domain>__<tool>` (e.g. `routing__get_bgp_neighbors`). |
| `CX_INVOKE_WRITES` | `true` | Allow write tools to run through `invoke_tool`. |
| `CX_WRITE_SAFETY` | `false` | Enable the `dry_run_token` preview + `apply_plan` / `rollback` meta-tools. |
| `CX_REQUIRE_DRY_RUN_TOKEN` | `false` | Refuse any apply without a valid `dry_run_token` (flat `configure_*` dispatchers **and** `invoke_tool`); force the plan → apply path. The shipped compose sets it to `true`. |
| `CX_DRY_RUN_TTL` | `900` | Lifetime (seconds) of a `dry_run_token`. |
| `CX_TOKEN_SESSION_BOUND` | `false` | A token is bound to (operation, plan hash, TTL), not to a caller. `true` also refuses a token issued by another MCP session; `false` only reports it (`dry_run_token_origin` + warning). |
| `CX_SECRETS_DIR` | `<app>/secrets` | Directory for the write-safety stores (`.dry_run_plans.json`, `.rollback_journal.json`). Set to a writable, mounted dir (e.g. `/app/logs`). |

### Apply-time safety rails
| Variable | Default | Description |
|----------|---------|-------------|
| `CX_AUTO_CHECKPOINT` | `true` | Wrap every `configure_*` apply in a firmware auto-checkpoint (confirmed commit): armed before the write, confirmed on success. A failed/interrupted apply is reverted by the switch after the timer. Set `false` to disable globally; each call can override with `auto_checkpoint=true|false`. |
| `CX_AUTO_CHECKPOINT_MINUTES` | `10` | Auto-checkpoint timer (1-60). |
| `CX_PROTECTED_OBJECTS` | *(empty)* | Comma-separated fnmatch globs on the URL-decoded REST path; matching resources refuse PUT/DELETE unless the call passes `force=true`. E.g. `/system/vrfs/mgmt,*/bgp_neighbors/spine-RR,/system/interfaces/lag*`. |
| `CX_VERSION` | from `VERSION` | Build/runtime version reported by `/healthz` and the image label. |

---

## 6. Inventory management

The inventory file ([inventory/inventory.yaml](inventory/inventory.yaml)) declares the
devices and how to reach them. It is **git-ignored** (it holds real IPs and
credentials); create it once from the shipped template:

```bash
cp inventory/inventory.example.yaml inventory/inventory.yaml
```

**Values in the file override environment variables.** Supported formats: YAML,
JSON, TOML.

### Minimal example
```yaml
defaults:
  username: admin
  password: "secret"
  api_version: latest        # auto-detect the newest REST version
  verify_ssl: false          # lab only (self-signed certs); default is true
  timeout: 30
  access_mode: read-only     # writes denied unless overridden per device

devices:
  Spine1:
    host: 192.0.2.21
    description: "Core switch"
    tags: [core, spine]
    site: campus-principal
    access_mode: read-write   # allow configuration changes on this device
  Access-01:
    host: 192.0.2.23
    site: campus-principal
```

### Per-device options
`host` (required), `username`, `password`, `api_version`, `verify_ssl`, `timeout`,
`tags`, `description`, `site`, `ssh_port`, `ssh_username`, `ssh_password`,
`access_mode` (`read-only` | `read-write`), `vault` (`true` to fetch credentials
from Vault).

### Sites
The `site` concept is **optional** and lets tools target a group of devices
(`list_devices(site=…)`, `run_on_site(site, …)`). Use either a per-device `site:`
field or a top-level `sites:` block grouping devices.

### Inventory source options

There are several ways to decide **where the device list comes from**:

1. **Local only (default)** — devices from the file:
   ```yaml
   source: local        # may be omitted
   ```
2. **Single external source** — pull from a source of truth:
   ```yaml
   source: netbox
   sources:
     netbox:
       type: netbox            # netbox | nautobot | infrahub
       url: https://netbox.example.com
       token: "<api-token>"    # or via NETBOX_TOKEN env var
       verify_ssl: false
   ```
3. **Merged sources with priority** — a device present in several sources is taken
   from the higher-priority one:
   ```yaml
   source: [local, netbox]
   source_priority: [local, netbox]   # local wins over netbox
   ```

**Credential resolution priority** (highest first):
1. Device-specific credentials set on the device entry.
2. HashiCorp Vault (when `vault` is enabled globally or per device).
3. Environment variables / inventory defaults.

After editing the inventory, apply changes without rebuilding via the
`refresh_inventory` tool, or restart the container.

### Startup validation (fail-fast)

The inventory file is **validated at startup**. If it cannot be parsed (YAML/JSON/
TOML syntax error) or violates the expected schema (e.g. a mis-indented `source:`
key, or `source` set to a non-string/list value), the server logs a specific
English error and **refuses to start** rather than silently running with an empty
or partial inventory:

```text
❌ Inventory file '/app/inventory/inventory.yaml' failed validation — the server will NOT start.
   YAML syntax error: expected '<document start>', but found '<block mapping start>'
     in "<unicode string>", line 22, column 1
   Fix the inventory file, then restart the container.
```

The container exits with a non-zero status code (visible in `docker logs` /
`docker compose ps`). Fix the reported line and restart. Notes:

- A **missing** inventory file is only a warning (it can be mounted later) — the
  server still starts.
- External source reachability (NetBox / Nautobot / Infrahub being down) is **not**
  fatal: the parsed local inventory remains usable and the dynamic merge degrades
  gracefully.
- The runtime `refresh_inventory` tool applies the same validation but never
  crashes a running server: on a bad file it returns an error and keeps the
  previously loaded inventory.

---

## 7. Security: Bearer auth & audit logging

Both features are **disabled by default** and fully backward compatible.

- **Authentication** (`CX_AUTH_ENABLED=true`): every request to `/mcp` must carry
  `Authorization: Bearer <token>`. Missing/invalid tokens get **HTTP 401**. The
  token's **name** becomes the `actor` recorded in the audit log, so you always
  know *who did what*. If auth is enabled but **no token exists yet**, the server
  still starts but in **LOCKED mode**: every MCP request is refused with
  **HTTP 503** (fail-closed) so the services are unreachable. Create the first
  token (see §8) and **restart the container** to unlock — the token store is
  loaded once at startup.
- **Audit** (`CX_AUDIT_ENABLED=true`): one JSON line per tool call in
  `logs/audit.jsonl`, including `actor`, `src_ip`, `tool`, `category`
  (read/write), targeted `device`, redacted `arguments`, `outcome`, HTTP
  `status_code` and `duration_ms`. Secrets (passwords/tokens) are masked.

Enable both:
```yaml
# docker-compose.yml
CX_AUTH_ENABLED:  "true"
CX_AUDIT_ENABLED: "true"
```
```bash
docker compose up -d --build
```

---

## 8. Token management

Tokens are stored in `secrets/.tokens` (perms `0600`). Manage them **inside the
running container** with the bundled CLI:

```bash
# Create a named token (prints the secret once — save it)
docker compose exec hpe-cx-mcp python security/cx_token_manager.py generate --name vscode-dev

# List tokens (names, descriptions, created — secret truncated)
docker compose exec hpe-cx-mcp python security/cx_token_manager.py list

# Show one token
docker compose exec hpe-cx-mcp python security/cx_token_manager.py show --name vscode-dev

# Revoke a token
docker compose exec hpe-cx-mcp python security/cx_token_manager.py revoke --name vscode-dev
```

Generated tokens are prefixed `cx_`. Use one distinct token per client/agent to
get per-actor attribution in the audit log.

> **First token:** when authentication is enabled, the server starts LOCKED
> (HTTP 503 on every request) until a token exists. After creating the **first**
> token, apply it without a restart by hot-reloading (see below):
> ```bash
> docker compose exec hpe-cx-mcp python security/cx_reload.py
> ```
> (a `docker compose restart hpe-cx-mcp` also works).

### Hot reload (no rebuild / no restart)

Token and inventory files are loaded into memory at startup. After editing
`secrets/.tokens` (via the CLI above) or `inventory/inventory.yaml`, apply the
changes to the **running** server by sending it a reload signal:

```bash
docker compose exec hpe-cx-mcp python security/cx_reload.py
```

This reloads **both** the tokens and the inventory in place — adding/revoking a
token, or adding/updating a device, takes effect on the next request. The
command only sends the signal; the outcome (counts, errors) is written to the
logs:

```bash
docker compose logs --tail=20 hpe-cx-mcp
```

Reloading is **manual** and explicit — there is no automatic file watching.

> If clients connect through a shared relay, all calls appear under the relay's
> single token; for per-agent attribution, connect directly to `hpe-cx-mcp` with
> distinct tokens.

---

## 9. Operations runbook

Day-2 procedures for a production deployment. Every command runs from the
`cx-mcp/` directory on the Docker host.

### 9.1 Health & version
```bash
curl -s http://localhost:8002/healthz | jq        # 200 ok/degraded, 503 unavailable
docker inspect --format '{{.State.Health.Status}}' hpe-cx-mcp
docker inspect --format '{{index .Config.Labels "org.opencontainers.image.version"}}' hpe-cx-mcp
```
`/healthz` needs no token and never returns secrets. `problems[]` names the
cause (`locked`, `inventory: 0 devices`, `inventory reload failed`). It is what
the Docker `HEALTHCHECK` and any load balancer should probe.

### 9.2 Upgrade / rollback of the server
```bash
# upgrade: bump ./VERSION, add a CHANGELOG entry, then
export CX_VERSION=$(cat VERSION) && docker compose up -d --build
# rollback: re-run with the previous, still-present image tag
CX_VERSION=1.0.0 docker compose up -d --no-build
```
Images are tagged `hpe-cx-mcp:<version>` (never `latest`). After any rebuild,
MCP clients must **reconnect** (tool schemas are cached client-side).

### 9.3 Token lifecycle (one token per client)
```bash
docker compose exec hpe-cx-mcp python security/cx_token_manager.py generate --name <client>
docker compose exec hpe-cx-mcp python security/cx_token_manager.py list
docker compose exec hpe-cx-mcp python security/cx_token_manager.py revoke --name <client>
docker compose exec hpe-cx-mcp python security/cx_reload.py   # apply without restart
```
Rotate: generate the new token, hand it over, revoke the old one, reload.
If `/healthz` reports `locked`, no token exists: generate one and reload.

### 9.4 Inventory change
Edit `inventory/inventory.yaml`, then `python security/cx_reload.py` (as above).
A syntax/schema error keeps the **previous** inventory in memory and is
reported in `/healthz` → `inventory.last_error` and the logs. Fix and reload.

### 9.5 Applying a change safely (what the agent goes through)
1. `configure_*(action='plan', …)` → plan + `dry_run_token` (TTL `CX_DRY_RUN_TTL`).
2. `configure_*(action='apply', dry_run_token=…, same params)` → the plan is
   recomputed and hash-compared; the write runs inside a firmware
   **auto-checkpoint**; on success the checkpoint is confirmed and a
   `rollback_id` is returned.
3. Protected objects (`CX_PROTECTED_OBJECTS`) are refused unless `force=true`.

If an apply fails mid-way the response says *auto-checkpoint left ARMED*: the
switch reverts by itself after `CX_AUTO_CHECKPOINT_MINUTES`. To keep the partial
state instead, call `manage_config(device, action='confirm')` before the
deadline. The safety net is on by default; disable it globally with
`CX_AUTO_CHECKPOINT=false`, or for one call with `auto_checkpoint=false`
(the per-device result then reports `checkpoint: disabled`).

### 9.6 Undoing a change
```text
rollback(rollback_id='rb_…')                       # objects CREATED by the apply
manage_config(device, action='list_checkpoints')   # otherwise: firmware checkpoints
manage_config(device, action='restore_checkpoint', name='<checkpoint>')
```
`rollback` only removes objects the apply created (VLAN-service steps,
loopbacks, VRFs, L3 VNIs). Updates of pre-existing objects are listed as
`unsupported` — restore a checkpoint (or `startup-config`) for those.

### 9.7 Reading the audit trail
```bash
tail -f logs/audit.jsonl | jq '{ts,actor,src_ip,tool,category,outcome,duration_ms}'
jq -c 'select(.category=="write" and .outcome!="completed")' logs/audit.jsonl
docker compose logs -f hpe-cx-mcp | grep '"tool"'      # same records on stdout
```
One JSON line per call (`CX_AUDIT_LEVEL=writes` → writes only); `actor` is the
token name, `arguments` are redacted. Files rotate 10 MB × 5 under `./logs`.

### 9.8 Incident checklist
| Symptom | Check | Action |
|---|---|---|
| Clients get 401 | `/healthz` → `auth.tokens` | Token revoked/typo → issue a new one (§9.3). |
| Clients get 503 | `/healthz` → `problems` | `locked` → create a token; `0 devices` → fix inventory + reload. |
| Tool returns `dry_run_token required` | — | Expected: run `action='plan'` first. |
| `matches protected object pattern` | `CX_PROTECTED_OBJECTS` | Intentional guard; re-run with `force=true` only after review. |
| `auto-checkpoint could not be armed` | pending checkpoint on the switch | `manage_config(action='confirm')` on the device, or `CX_AUTO_CHECKPOINT=false` (not recommended). |
| Stale MCP session / 404 after rebuild | container logs | Disconnect → Connect the MCP server in the client. |
| Switch unreachable / TLS error | `verify_ssl`, `ARUBA_CA_BUNDLE` | Mount the CA chain in `./certs`, or set `verify_ssl: false` for that lab device only. |

---

## 10. Connecting an MCP client

Point your MCP client at the streamable-HTTP endpoint:

```
URL:  http://<docker-host>:8002/mcp
```

When authentication is enabled, add the header:
```
Authorization: Bearer cx_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

Example (VS Code `mcp.json` style):
```json
{
  "servers": {
    "hpe-cx-mcp": {
      "type": "http",
      "url": "http://localhost:8002/mcp",
      "headers": { "Authorization": "Bearer cx_xxxxxxxxxxxxxxxxxxxx" }
    }
  }
}
```

---

## 11. Prompts (guided operations) & skills

### Prompts

Beyond individual tools, the server exposes **MCP prompts** (`tools/prompts.py`)
— reusable, multi-step operation guides an agent can follow end-to-end instead
of being told which tool to call at each step. Each prompt returns a short plan
referencing the tools/dispatchers above; the agent still asks for confirmation
before any `apply`-mode write.

**Data Center**
| Prompt | Purpose |
|--------|---------|
| `fabric_health_check(site)` | Site-wide fabric health: system/interfaces/vlans/logs, VXLAN tunnels, EVPN routes, VSX sync, underlay BGP. |
| `provision_vlan_service_guide(device, vlan_id)` | Guided plan → apply → verify walkthrough of `configure_service` (VLAN/L2VNI/EVPN RT/SVI). |
| `verify_vsx_pair(device_a, device_b)` | Cross-check both VSX peers for role/sync/keepalive consistency. |
| `capacity_and_license_review(device)` | Hardware scale-limit utilization, feature-pack licensing state, container review. |

**Campus**
| Prompt | Purpose |
|--------|---------|
| `rollout_8021x_guide(device, interfaces)` | Guided 802.1X/MAC-Auth rollout: RADIUS/TACACS+ reachability check, then plan → apply → verify. |
| `poe_budget_check(device)` | PoE power budget audit (per-port draw + chassis-wide budget). |
| `campus_topology_audit(site)` | Site-wide LLDP-based topology mapping and cabling/loop anomaly detection. |
| `guest_network_audit(device)` | Review guest/BYOD role, GBP/ABP and policy bindings for over-broad access. |

**Cross-domain (DC + Campus)**
| Prompt | Purpose |
|--------|---------|
| `diagnostic_equipement(device)` | Full health check of a single switch (system, interfaces, VLANs, logs). |
| `troubleshoot_routing(device, vrf)` | Diagnose BGP + OSPF (neighbor state, route table). |
| `troubleshoot_client_8021x(device, interface)` | Troubleshoot a client that can't authenticate (802.1X/MAC-Auth). |
| `verifier_evpn_vxlan(device)` | Check EVPN/VXLAN overlay health on one switch. |
| `localiser_client(device, mac)` | Locate a MAC/client (MAC table, ARP, LLDP, port-access). |
| `audit_configuration(device)` | Configuration + AAA audit against best practices. |
| `hardening_compliance_check(device)` | Audit against the official **AOS-CX 10.17 Hardening Guide** (see the matching skill below). |
| `pre_change_safety_guide(device)` | Checkpoint → change → diff → restore-if-needed safety workflow. |
| `spanning_tree_loop_check(site)` | Site-wide STP state cross-referenced with LLDP to spot loops/instability. |

### Skills

`skills/` holds installable `SKILL.md` domain-knowledge packages (playbooks,
gotchas, thresholds) that complement the prompts above:

| Skill | Covers |
|-------|--------|
| `aoscx-hardening-compliance` | Full control-domain checklist from the official AOS-CX 10.17 Hardening Guide (mgmt access, AAA, SSH, SNMP, NTP, PKI, CoPP, L2 hardening, routing-protocol security, multicast, NAE scripts). |
| `aoscx-dc-fabric-ops` | EVPN/VXLAN tunnel-down triage, VSX split-brain/config-sync diagnosis. |
| `aoscx-campus-nac-ops` | 802.1X/MAC-Auth rollout checklist and client-authentication troubleshooting. |
| `aoscx-change-management` | Checkpoint/diff/restore workflow, PUT-replaces-wholesale gotcha, auto-checkpoint safety net. |
| `aoscx-capacity-planning` | Capacity/feature-pack/PoE-budget thresholds and what counts as a real gap. |
| `aoscx-inventory-targeting` | Efficient `device`/`site`/`source` batching, the "device serialized as a string" client gotcha, envelope shape. |
| `aoscx-legacy-to-fabric-migration` | Safety-gated migration of a legacy network (VSX core, LAGs, VLANs, static routes) to a VXLAN-EVPN fabric (OSPF underlay, BGP-EVPN with spine RRs) using the orchestrators. |

Each skill is a self-contained `SKILL.md` (YAML frontmatter `name`+`description`
plus a Markdown body) — install/copy it into your assistant's skills directory
to load the domain knowledge alongside this MCP server's tools.
