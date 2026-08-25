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
your MCP client at it (see [§9](#9-connecting-an-mcp-client)). Full details and
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
9. [Connecting an MCP client](#9-connecting-an-mcp-client)

---

## 1. What this server does

- **Single entry point** to a fleet of AOS-CX switches described in an inventory.
- **Read (observe)**: interfaces, VLANs, routing/ARP/MAC tables, BGP/OSPF/EVPN,
  VXLAN tunnels, VSX/VSF stack state, hardware health, logs, 802.1X / port-access,
  NAE scripts, application recognition (ARC), full configs.
- **Write (configure)**: VLAN services, loopbacks, routed ports, VRFs, BGP, OSPF,
  EVPN/VXLAN, port authentication, virtual-MAC, ARC — each paired with a
  **`verify_*`** read-back tool.
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
`get_ssh_config`, `get_logs`.

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
`manage_config` (save / checkpoint / rollback).

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

> **Write protection**: a `configure_*` / `create_*` / `delete_*` / `manage_config`
> call on a `read-only` device is refused. Mark the device `access_mode: read-write`
> in the inventory to allow changes.

### Tool exposure: flat toolset (default) vs legacy atomic tools

The server can expose its capabilities in two **mutually exclusive** ways, chosen
by the `CX_FLAT_TOOLSET` flag (see [§5](#5-environment-variables)):

**Flat toolset (`CX_FLAT_TOOLSET=true` — the default).** The ~101 atomic tools
listed above are collapsed into **~23 flat dispatchers** driven by a `scope`
(and, for writes, an `action`) argument. The underlying REST client code is
unchanged — the dispatchers only *route* to it, so there is no behavioural
regression. Every read dispatcher also accepts **`device: str | list`**, **`site`**
or **`source`** (an external source-of-truth query) and fans the call out in
parallel, returning one envelope `{scope, results, errors, summary}`. An optional
`limit` caps long list fields in the response.

| Dispatcher | `scope` values |
|------------|----------------|
| `get_system` | `info`, `inventory`, `environment`, `capacity`, `boot`, `maintenance`, `containers`, `feature_pack`, `central`, `ssh` |
| `get_interfaces` | `physical`, `transceivers`, `loopbacks`, `routed`, `svi`, `lag` |
| `get_switching` | `vlans`, `mac`, `lldp`, `spanning_tree` |
| `get_routing` | `bgp_summary`, `bgp_neighbors`, `bgp_config`, `bgp_routes`, `ospf_overview`, `ospf_neighbors`, `ospf_interfaces`, `route_table`, `arp` |
| `get_overlay` | `evpn_config`, `evpn_routes`, `evpn_multihoming`, `vtep_neighbors`, `vxlan_config`, `vxlan_tunnels`, `vxlan_static_peers` |
| `get_redundancy` | `vsx_status`, `vsx_config`, `vsx_sync`, `vsf_status`, `vsf_config` |
| `get_access` | `clients`, `client_detail`, `auth_config`, `summary`, `roles`, `gbp`, `gbp_maps`, `abp`, `policies`, `radius`, `tacacs`, `authentication`, `accounting` |
| `get_automation` | `nae_scripts`, `nae_script`, `nae_agents`, `nae_agent` |
| `get_apps` | `recognition`, `visibility` |
| `get_config` | `running`, `startup`, `full`, `list`, `compare`, `raw` |
| `manage_inventory` | `sources`, `resolve`, `refresh`, `find` |
| `configure_interface` | `loopback`, `routed_port`, `vxlan`, `virtual_mac` — `action`: `plan`/`apply`/`verify` |
| `configure_routing` | `ospf`, `bgp`, `vrf`, `evpn` — `action`: `plan`/`apply`/`verify` |
| `configure_security` | `port_auth`, `aaa`, `user_roles`, `app_recognition` — `action`: `plan`/`apply`/`verify` |
| `configure_service` | `vlan` — `action`: `plan`/`apply`/`delete`/`delete_plan`/`verify` |
| `diagnose` | `device`, `evpn`, `client` (deterministic multi-check bundle) |

Plus 7 kept-atomic tools: `list_devices`, `list_sites`, `get_logs`,
`run_ssh_commands`, `manage_config`, `logout`, `rollback`. Write dispatchers keep
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
`unsupported` by `rollback`. When `CX_REQUIRE_DRY_RUN_TOKEN=true`, a direct apply
(`apply=true`) through `invoke_tool` is refused — callers must go through the
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

### Bearer authentication (optional, OFF by default)
| Variable | Default | Description |
|----------|---------|-------------|
| `CX_AUTH_ENABLED` | `false` | Require a valid Bearer token on every request. **If enabled with no token yet, the server starts in LOCKED mode and refuses every MCP request with HTTP 503 until you create the first token and restart.** |
| `CX_TOKENS_FILE` | `/app/secrets/.tokens` | Token store path. |
| `CX_TRUST_FORWARDED_FOR` | `false` | Trust `X-Forwarded-For` (first hop) for client IP. Set `true` **only** behind a trusted reverse proxy. |

### Audit logging (optional, OFF by default)
| Variable | Default | Description |
|----------|---------|-------------|
| `CX_AUDIT_ENABLED` | `false` | Emit a JSON record per tool call. |
| `CX_AUDIT_FILE` | `/app/logs/audit.jsonl` | Output file (rotating, 10 MB × 5). |
| `CX_AUDIT_LEVEL` | `all` | `all` = every call; `writes` = only state-changing tools. |
| `CX_AUDIT_STDOUT` | `false` | Also mirror records to stdout (`docker logs`). |

### Progressive disclosure, prefixes & write safety (optional)
| Variable | Default | Description |
|----------|---------|-------------|
| `CX_FLAT_TOOLSET` | `true` | Collapse the ~101 atomic tools into ~23 flat `scope`/`action` dispatchers. Takes precedence: when on, the three layers below are skipped. Set `false` to opt back into the legacy atomic tools. |
| `CX_DEFERRED_TOOLS` | `false` | (Legacy mode only) Advertise only Tier-1 tools; reach the rest via `search_tools` / `invoke_tool`. |
| `CX_TOOL_PREFIXES` | `false` | (Legacy mode only) Rename advertised tools `<domain>__<tool>` (e.g. `routing__get_bgp_neighbors`). |
| `CX_INVOKE_WRITES` | `true` | Allow write tools to run through `invoke_tool`. |
| `CX_WRITE_SAFETY` | `false` | Enable the `dry_run_token` preview + `apply_plan` / `rollback` meta-tools. |
| `CX_REQUIRE_DRY_RUN_TOKEN` | `false` | Refuse a direct `apply=true` via `invoke_tool`; force the preview → `apply_plan` path. |
| `CX_DRY_RUN_TTL` | `900` | Lifetime (seconds) of a `dry_run_token`. |
| `CX_SECRETS_DIR` | `<app>/secrets` | Directory for the write-safety stores (`.dry_run_plans.json`, `.rollback_journal.json`). Set to a writable, mounted dir (e.g. `/app/logs`). |

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
  verify_ssl: false
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
docker compose exec hpe-cx-mcp python cx_token_manager.py generate --name vscode-dev

# List tokens (names, descriptions, created — secret truncated)
docker compose exec hpe-cx-mcp python cx_token_manager.py list

# Show one token
docker compose exec hpe-cx-mcp python cx_token_manager.py show --name vscode-dev

# Revoke a token
docker compose exec hpe-cx-mcp python cx_token_manager.py revoke --name vscode-dev
```

Generated tokens are prefixed `cx_`. Use one distinct token per client/agent to
get per-actor attribution in the audit log.

> **First token:** when authentication is enabled, the server starts LOCKED
> (HTTP 503 on every request) until a token exists. After creating the **first**
> token, apply it without a restart by hot-reloading (see below):
> ```bash
> docker compose exec hpe-cx-mcp python cx_reload.py
> ```
> (a `docker compose restart hpe-cx-mcp` also works).

### Hot reload (no rebuild / no restart)

Token and inventory files are loaded into memory at startup. After editing
`secrets/.tokens` (via the CLI above) or `inventory/inventory.yaml`, apply the
changes to the **running** server by sending it a reload signal:

```bash
docker compose exec hpe-cx-mcp python cx_reload.py
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

## 9. Connecting an MCP client

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
