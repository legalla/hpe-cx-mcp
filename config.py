"""
Load the ArubaOS-CX device inventory.
Supported formats: YAML (.yaml/.yml), JSON (.json), TOML (.toml)
"""

import json
import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Default credentials from environment variables
ENV_DEFAULT_USER = os.environ.get("ARUBA_DEFAULT_USERNAME", "admin")
ENV_DEFAULT_PASS = os.environ.get("ARUBA_DEFAULT_PASSWORD", "")
ENV_DEFAULT_API  = os.environ.get("ARUBA_API_VERSION", "v10.09")
ENV_DEFAULT_SSH_PORT = int(os.environ.get("ARUBA_SSH_PORT", "22"))

_API_VERSION_RE = re.compile(r"^v?\d+\.\d+$", re.IGNORECASE)

# Inventory source types supported for dynamic inventory.
LOCAL_SOURCE = "local"
SUPPORTED_SOURCE_TYPES = ("local", "netbox", "nautobot", "infrahub")


class InventoryError(Exception):
    """Raised when the inventory file cannot be parsed or fails validation.

    Carries a human-readable, English message describing exactly what is wrong
    (e.g. a YAML syntax error with its line/column, or a schema/conformance
    violation) so the server can refuse to start with a clear diagnostic.
    """


def normalize_api_version(value: str) -> str:
    raw = (value or ENV_DEFAULT_API).strip()
    if not raw:
        raw = ENV_DEFAULT_API
    if raw.lower() == "latest":
        return "latest"
    if not _API_VERSION_RE.match(raw):
        raise ValueError(
            f"Invalid api_version '{value}'. Use 'latest' or an explicit version like 'v10.13'."
        )
    if not raw.lower().startswith("v"):
        raw = f"v{raw}"
    return raw.lower()


@dataclass
class DeviceConfig:
    name: str
    host: str
    username: str = field(default_factory=lambda: ENV_DEFAULT_USER)
    password: str = field(default_factory=lambda: ENV_DEFAULT_PASS)
    api_version: str = field(default_factory=lambda: ENV_DEFAULT_API)
    verify_ssl: bool = False
    timeout: int = 30
    tags: list[str] = field(default_factory=list)
    description: str = ""
    site: str = ""
    # SSH (CLI) access. Defaults to the same credentials as the REST API.
    ssh_port: int = field(default_factory=lambda: ENV_DEFAULT_SSH_PORT)
    ssh_username: str = ""
    ssh_password: str = ""
    # Access control: read-only by default, read-write to allow modifications.
    access_mode: str = "read-only"
    # Dynamic inventory provenance: which source provided this device.
    source: str = LOCAL_SOURCE
    # Whether credentials for this device must be fetched from HashiCorp Vault.
    vault: bool = False
    # Names of the credential fields that were explicitly provided for this
    # device (vs. inherited from defaults/env). Used to give device-specific
    # credentials priority over Vault/env/defaults.
    explicit: set = field(default_factory=set)
    # Free-form extra attributes coming from an external source (site/tenant/
    # location/rack/tags/custom fields…), kept for inspection/filtering.
    extra: dict = field(default_factory=dict)

    def __post_init__(self):
        # SSH credentials fall back to the REST API ones when not explicitly
        # defined for the device.
        if not self.ssh_username:
            self.ssh_username = self.username
        if not self.ssh_password:
            self.ssh_password = self.password
        self.api_version = normalize_api_version(self.api_version)
        mode = (self.access_mode or "read-only").strip().lower()
        aliases = {
            "ro": "read-only",
            "readonly": "read-only",
            "read-only": "read-only",
            "rw": "read-write",
            "readwrite": "read-write",
            "read-write": "read-write",
        }
        normalized = aliases.get(mode)
        if normalized is None:
            raise ValueError(
                f"Invalid access_mode '{self.access_mode}' for device '{self.name}'. "
                "Use 'read-only' or 'read-write'."
            )
        self.access_mode = normalized

    @property
    def can_write(self) -> bool:
        return self.access_mode == "read-write"


@dataclass
class SourceConfig:
    """Connection settings for an inventory source (local or external)."""
    name: str
    type: str  # local | netbox | nautobot | infrahub
    url: str = ""
    token: str = ""
    verify_ssl: bool = False
    timeout: int = 15
    priority: int = 0  # lower number = higher priority
    options: dict = field(default_factory=dict)

    @property
    def is_local(self) -> bool:
        return self.type == LOCAL_SOURCE

    @property
    def has_token(self) -> bool:
        return bool(self.token)


@dataclass
class VaultConfig:
    """HashiCorp Vault settings for credential resolution."""
    enabled: bool = False
    url: str = ""
    token: str = ""
    mount: str = "secret"
    path_template: str = "{device}"
    kv_version: int = 2
    verify_ssl: bool = True
    timeout: int = 10
    username_field: str = "username"
    password_field: str = "password"
    ssh_username_field: str = "ssh_username"
    ssh_password_field: str = "ssh_password"

    @property
    def has_token(self) -> bool:
        return bool(self.token)


@dataclass
class Inventory:
    """Parsed inventory.

    - `devices`      : the resolved device map.
    - `sources`      : the selected inventory sources (local and/or external).
    - `source_order` : source selection priority (highest priority first).
                       This is a general inventory notion and applies even to a
                       purely local inventory (local is not "dynamic").
    - `vault`        : optional HashiCorp Vault credential settings.
    """
    devices: dict[str, DeviceConfig] = field(default_factory=dict)
    sources: dict[str, SourceConfig] = field(default_factory=dict)
    source_order: list[str] = field(default_factory=lambda: [LOCAL_SOURCE])
    vault: VaultConfig = field(default_factory=VaultConfig)

    @property
    def has_external_sources(self) -> bool:
        return any(s.type != LOCAL_SOURCE for s in self.sources.values())


def _env(*names: str) -> str:
    """Return the first non-empty environment variable among `names`."""
    for n in names:
        val = os.environ.get(n)
        if val:
            return val
    return ""


def _parse_vault(data: dict) -> VaultConfig:
    raw = data.get("vault")
    if raw is None or raw is False:
        return VaultConfig(enabled=False)
    if raw is True:
        cfg = {}
    elif isinstance(raw, dict):
        cfg = raw
    else:
        raise ValueError("'vault' must be a boolean or a mapping.")
    enabled = bool(cfg.get("enabled", True))
    return VaultConfig(
        enabled=enabled,
        url=cfg.get("url") or cfg.get("address") or _env("VAULT_ADDR", "VAULT_URL"),
        token=cfg.get("token") or _env("VAULT_TOKEN"),
        mount=cfg.get("mount", "secret"),
        path_template=cfg.get("path_template", cfg.get("path", "{device}")),
        kv_version=int(cfg.get("kv_version", 2)),
        verify_ssl=bool(cfg.get("verify_ssl", True)),
        timeout=int(cfg.get("timeout", 10)),
        username_field=cfg.get("username_field", "username"),
        password_field=cfg.get("password_field", "password"),
        ssh_username_field=cfg.get("ssh_username_field", "ssh_username"),
        ssh_password_field=cfg.get("ssh_password_field", "ssh_password"),
    )


def _infer_source_type(name: str, raw: dict | None) -> str:
    if raw and raw.get("type"):
        t = str(raw["type"]).strip().lower()
    else:
        t = name.strip().lower()
    if t in SUPPORTED_SOURCE_TYPES:
        return t
    # Allow arbitrary instance names whose type is given explicitly; otherwise
    # the bare name must match a supported backend.
    raise ValueError(
        f"Unknown source type for '{name}'. Supported: {', '.join(SUPPORTED_SOURCE_TYPES)} "
        "(set an explicit 'type' for custom source names)."
    )


def _build_source(name: str, raw: dict | None) -> SourceConfig:
    raw = raw or {}
    stype = _infer_source_type(name, raw)
    if stype == LOCAL_SOURCE:
        return SourceConfig(name=name, type=LOCAL_SOURCE)
    upper = name.upper().replace("-", "_")
    type_upper = stype.upper()
    url = (
        raw.get("url")
        or raw.get("address")
        or _env(f"{upper}_URL", f"{type_upper}_URL", f"{upper}_ADDRESS")
    )
    token = (
        raw.get("token")
        or raw.get("api_token")
        or _env(f"{upper}_TOKEN", f"{type_upper}_TOKEN", f"{type_upper}_API_TOKEN")
    )
    options = {
        k: v for k, v in raw.items()
        if k not in ("type", "url", "address", "token", "api_token", "verify_ssl", "timeout", "priority")
    }
    return SourceConfig(
        name=name,
        type=stype,
        url=str(url or "").rstrip("/"),
        token=str(token or ""),
        verify_ssl=bool(raw.get("verify_ssl", False)),
        timeout=int(raw.get("timeout", 15)),
        options=options,
    )


def _parse_sources(data: dict) -> tuple[dict[str, SourceConfig], list[str]]:
    """Parse inventory source selection and priority.

    `source` / `source_priority` select WHICH source(s) provide the device list
    and in which priority order — a general inventory notion that applies even
    to a purely local inventory. `sources` then carries the connection details
    that are only meaningful for external (dynamic) sources.

    Returns (sources_by_name, ordered_names) where ordered_names is the
    priority order (highest priority first)."""
    source_key = data.get("source", LOCAL_SOURCE)
    if isinstance(source_key, str):
        selected = [source_key.strip()]
    elif isinstance(source_key, list):
        selected = [str(s).strip() for s in source_key if str(s).strip()]
    else:
        raise ValueError("'source' must be a string or a list of strings.")
    if not selected:
        selected = [LOCAL_SOURCE]

    defs = data.get("sources", {}) or {}
    if not isinstance(defs, dict):
        raise ValueError("'sources' must be a mapping of source-name -> settings.")

    sources: dict[str, SourceConfig] = {}
    for name in selected:
        raw = defs.get(name)
        sources[name] = _build_source(name, raw)

    # Also register any source defined in `sources:` but referenced via priority.
    priority = data.get("source_priority")
    if priority is not None:
        if isinstance(priority, str):
            priority = [priority]
        if not isinstance(priority, list):
            raise ValueError("'source_priority' must be a string or list.")
        order = [str(p).strip() for p in priority if str(p).strip()]
        # Make sure every prioritized source is known.
        for name in order:
            if name not in sources:
                sources[name] = _build_source(name, defs.get(name))
        # Append any selected source missing from the explicit priority.
        for name in selected:
            if name not in order:
                order.append(name)
    else:
        order = list(sources.keys())

    for idx, name in enumerate(order):
        if name in sources:
            sources[name].priority = idx
    return sources, order


def load_inventory(path: str) -> Inventory:
    """Load the full inventory: devices + source selection/priority + optional
    Vault settings. External (dynamic) source connection details are only used
    when a non-local source is selected."""
    filepath = Path(path)
    if not filepath.exists():
        raise FileNotFoundError(f"Inventory file not found: {path}")

    suffix = filepath.suffix.lower()
    raw = filepath.read_text(encoding="utf-8")
    try:
        if suffix in (".yaml", ".yml"):
            data = _load_yaml(raw)
        elif suffix == ".json":
            data = json.loads(raw)
        elif suffix == ".toml":
            data = _load_toml(raw)
        else:
            data = _auto_detect(raw, path)
    except InventoryError:
        raise
    except Exception as exc:
        raise InventoryError(f"Could not parse inventory file '{path}': {exc}") from exc

    if not isinstance(data, dict):
        data = {"devices": data}

    # The local `devices:` block is only loaded when `local` is one of the
    # selected sources. If only external sources are selected (e.g. `source:
    # netbox`), the local block is ignored and devices come solely from the
    # external source(s) — no merge with the local file.
    try:
        sources, order = _parse_sources(data)
        vault = _parse_vault(data)
        local_selected = any(
            s.type == LOCAL_SOURCE for name, s in sources.items() if name in order
        )
        devices = _parse_inventory(data) if local_selected else {}
    except InventoryError:
        raise
    except ValueError as exc:
        raise InventoryError(
            f"Invalid inventory configuration in '{path}': {exc}"
        ) from exc
    return Inventory(devices=devices, sources=sources, source_order=order, vault=vault)


def load_devices(path: str) -> dict[str, DeviceConfig]:
    """
    Load the inventory from a YAML, JSON or TOML file.
    Returns a dict { device_name: DeviceConfig }.
    """
    filepath = Path(path)
    if not filepath.exists():
        raise FileNotFoundError(f"Inventory file not found: {path}")

    suffix = filepath.suffix.lower()
    raw = filepath.read_text(encoding="utf-8")

    if suffix in (".yaml", ".yml"):
        data = _load_yaml(raw)
    elif suffix == ".json":
        data = json.loads(raw)
    elif suffix == ".toml":
        data = _load_toml(raw)
    else:
        # Attempt automatic detection
        data = _auto_detect(raw, path)

    return _parse_inventory(data)


def _load_yaml(raw: str) -> dict:
    try:
        import yaml
    except ImportError:
        raise RuntimeError("The 'pyyaml' module is required for YAML files. Install it with: pip install pyyaml")
    try:
        return yaml.safe_load(raw) or {}
    except yaml.YAMLError as exc:
        raise InventoryError(f"YAML syntax error: {exc}") from exc


def _load_toml(raw: str) -> dict:
    try:
        import tomllib  # Python 3.11+
        return tomllib.loads(raw)
    except ImportError:
        try:
            import tomli
            return tomli.loads(raw)
        except ImportError:
            raise RuntimeError("The 'tomli' module is required for TOML files. Install it with: pip install tomli")


def _auto_detect(raw: str, path: str) -> dict:
    """Try JSON then YAML when the extension is unknown."""
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        pass
    try:
        return _load_yaml(raw)
    except Exception:
        pass
    raise ValueError(f"Unrecognized file format: {path}. Use .yaml, .json or .toml")


def _parse_inventory(data: dict) -> dict[str, DeviceConfig]:
    """
    Supported formats:
    
    Format 1 — list of devices:
      devices:
        - name: sw-core-01
          host: 192.168.1.1
          username: admin
          password: secret

    Format 2 — dict of devices:
      devices:
        sw-core-01:
          host: 192.168.1.1
          username: admin
          password: secret

    Format 3 — flat (list at the root):
      - name: sw-core-01
        host: 192.168.1.1

    Format 4 — flat dict at the root:
      sw-core-01:
        host: 192.168.1.1
    """
    result: dict[str, DeviceConfig] = {}

    # Extract global defaults
    defaults = data.get("defaults", {})
    global_user = defaults.get("username", ENV_DEFAULT_USER)
    global_pass = defaults.get("password", ENV_DEFAULT_PASS)
    global_api  = defaults.get("api_version", ENV_DEFAULT_API)
    global_ssl  = defaults.get("verify_ssl", False)
    global_timeout = defaults.get("timeout", 30)
    global_site = defaults.get("site", "")

    base_defaults = {
        "username": global_user,
        "password": global_pass,
        "api_version": global_api,
        "verify_ssl": global_ssl,
        "timeout": global_timeout,
        "site": global_site,
        "ssh_port": defaults.get("ssh_port", ENV_DEFAULT_SSH_PORT),
        "ssh_username": defaults.get("ssh_username", ""),
        "ssh_password": defaults.get("ssh_password", ""),
        "access_mode": defaults.get("access_mode", "read-only"),
        "vault": defaults.get("vault", False),
    }

    # "sites" format — explicit per-site grouping (optional):
    #   sites:
    #     campus-paris:
    #       devices:
    #         Border: { host: 192.0.2.20 }
    # The site defined here is propagated to each device (unless overridden locally).
    sites_raw = data.get("sites")
    if isinstance(sites_raw, dict):
        for site_name, site_data in sites_raw.items():
            if not isinstance(site_data, dict):
                continue
            site_defaults = {**base_defaults, **{
                k: site_data[k] for k in ("username", "password", "api_version", "verify_ssl", "timeout", "ssh_port", "ssh_username", "ssh_password", "access_mode")
                if k in site_data
            }, "site": site_data.get("site", site_name)}
            site_devices = site_data.get("devices", {})
            for cfg in _iter_devices(site_devices, site_defaults):
                result[cfg.name] = cfg

    devices_raw = data.get("devices", data if "sites" not in data else {})  # supports the direct root

    for cfg in _iter_devices(devices_raw, base_defaults):
        result[cfg.name] = cfg

    return result


def _iter_devices(devices_raw: Any, defaults: dict):
    """Iterate over a block of devices (list or dict) and yield DeviceConfig objects."""
    if isinstance(devices_raw, list):
        for item in devices_raw:
            yield _build_device(item, defaults)
    elif isinstance(devices_raw, dict):
        for dev_name, dev_data in devices_raw.items():
            if dev_name in ("defaults", "sites"):
                continue
            if isinstance(dev_data, dict):
                item = {"name": dev_name, **dev_data}
            else:
                # Simple IP string: sw-core-01: 192.168.1.1
                item = {"name": dev_name, "host": str(dev_data)}
            yield _build_device(item, defaults)
    elif devices_raw:
        raise ValueError("Invalid inventory format. See the documentation.")



def _build_device(item: dict, defaults: dict) -> DeviceConfig:
    name = item.get("name") or item.get("hostname") or item.get("host", "unknown")
    host = item.get("host") or item.get("ip") or item.get("address") or name

    if not host:
        raise ValueError(f"Device '{name}' has no IP address or hostname defined.")

    # Track which credential fields were explicitly set on the device so that
    # device-specific credentials win over Vault/env/defaults.
    explicit = {f for f in ("username", "password", "ssh_username", "ssh_password")
                if item.get(f) not in (None, "")}

    return DeviceConfig(
        name=name,
        host=host,
        username=item.get("username", defaults.get("username", ENV_DEFAULT_USER)),
        password=item.get("password", defaults.get("password", ENV_DEFAULT_PASS)),
        api_version=item.get("api_version", defaults.get("api_version", ENV_DEFAULT_API)),
        verify_ssl=item.get("verify_ssl", defaults.get("verify_ssl", False)),
        timeout=int(item.get("timeout", defaults.get("timeout", 30))),
        tags=item.get("tags", []),
        description=item.get("description", ""),
        site=item.get("site", defaults.get("site", "")),
        ssh_port=int(item.get("ssh_port", defaults.get("ssh_port", ENV_DEFAULT_SSH_PORT))),
        ssh_username=item.get("ssh_username", defaults.get("ssh_username", "")),
        ssh_password=item.get("ssh_password", defaults.get("ssh_password", "")),
        access_mode=item.get("access_mode", defaults.get("access_mode", "read-only")),
        source=item.get("source", defaults.get("source", LOCAL_SOURCE)),
        vault=bool(item.get("vault", defaults.get("vault", False))),
        explicit=explicit,
    )


def local_defaults() -> dict:
    """Base defaults (env-driven) used when building devices from an external
    source that does not carry credentials/timeouts of its own."""
    return {
        "username": ENV_DEFAULT_USER,
        "password": ENV_DEFAULT_PASS,
        "api_version": ENV_DEFAULT_API,
        "verify_ssl": False,
        "timeout": 30,
        "site": "",
        "ssh_port": ENV_DEFAULT_SSH_PORT,
        "ssh_username": "",
        "ssh_password": "",
        "access_mode": "read-only",
        "source": LOCAL_SOURCE,
        "vault": False,
    }


def build_device_from_source(item: dict, source_name: str, defaults: dict | None = None) -> DeviceConfig:
    """Build a DeviceConfig from an external-source record (NetBox/Nautobot/…).

    `item` must contain at least `name` and `host`; any extra metadata is kept
    under `.extra`. `source_name` marks the provenance."""
    base = {**local_defaults(), **(defaults or {})}
    base["source"] = source_name
    dev = _build_device({k: v for k, v in item.items() if k != "extra"}, base)
    dev.source = source_name
    if isinstance(item.get("extra"), dict):
        dev.extra = item["extra"]
    return dev
