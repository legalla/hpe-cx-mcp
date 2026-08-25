"""
Dynamic inventory sources for the ArubaOS-CX MCP server.

Supports pulling device connection details (name + management IP) from external
sources of truth in addition to (or instead of) the local YAML inventory:

  - local     : the devices declared in the inventory file.
  - netbox    : NetBox DCIM (REST API).
  - nautobot  : Nautobot DCIM (REST API).
  - infrahub  : Infrahub (OpsMill) via its GraphQL API.

Credentials to connect to a device are resolved with the following priority:

  1. device-specific credentials (explicitly set on the device record)
  2. HashiCorp Vault (when `vault: true` globally or on the device)
  3. environment variables / inventory defaults

Connection settings (URL + token) for each source and for Vault can be given
statically in the inventory file or via environment variables.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Optional

import aiohttp

from config import (
    DeviceConfig,
    Inventory,
    SourceConfig,
    VaultConfig,
    LOCAL_SOURCE,
    build_device_from_source,
)

logger = logging.getLogger(__name__)

# Native NetBox/Nautobot device filter keys. Anything else provided by the user
# is treated as a custom field (cf_<name>) or a tag.
_NATIVE_FILTER_KEYS = {
    "name", "site", "tenant", "location", "rack", "region", "role",
    "device_role", "manufacturer", "platform", "status", "tag",
}


class InventorySourceError(Exception):
    """Raised when an external inventory source cannot be queried."""


def _mask(token: str) -> str:
    if not token:
        return ""
    if len(token) <= 6:
        return "***"
    return f"{token[:3]}…{token[-2:]}"


def _strip_prefix_len(address: str) -> str:
    """'10.0.0.1/24' -> '10.0.0.1'."""
    if not address:
        return ""
    return address.split("/", 1)[0].strip()


class InventorySource:
    """Base class for an inventory source backend."""

    def __init__(self, cfg: SourceConfig):
        self.cfg = cfg

    @property
    def name(self) -> str:
        return self.cfg.name

    @property
    def type(self) -> str:
        return self.cfg.type

    async def query(self, filters: dict | None = None, limit: int = 100) -> list[dict]:
        """Return a list of normalized device records:
        {name, host, source, extra}."""
        raise NotImplementedError

    async def get_device(self, identifier: str) -> Optional[dict]:
        """Find a single device by name or management IP."""
        raise NotImplementedError

    async def health(self) -> dict:
        """Best-effort reachability probe."""
        return {"source": self.name, "type": self.type, "reachable": None}


# ─── HTTP-based sources (NetBox / Nautobot) ──────────────────────────────────


class _RestDeviceSource(InventorySource):
    """Shared logic for NetBox/Nautobot-style DCIM REST APIs."""

    devices_path = "/api/dcim/devices/"

    def __init__(self, cfg: SourceConfig):
        super().__init__(cfg)
        if not cfg.url:
            raise InventorySourceError(
                f"Source '{cfg.name}' ({cfg.type}) has no URL "
                f"(set it in the inventory or via the *_URL env var)."
            )

    def _headers(self) -> dict:
        headers = {"Accept": "application/json"}
        if self.cfg.token:
            headers["Authorization"] = f"Token {self.cfg.token}"
        return headers

    def _build_params(self, filters: dict | None, limit: int) -> dict:
        params: dict[str, Any] = {"limit": limit}
        for key, value in (filters or {}).items():
            if value in (None, ""):
                continue
            lkey = key.lower()
            if lkey in _NATIVE_FILTER_KEYS:
                params[lkey] = value
            else:
                # Non-native attribute => custom field lookup.
                params[f"cf_{key}"] = value
        return params

    async def _request(self, path: str, params: dict | None = None) -> dict:
        connector = aiohttp.TCPConnector(ssl=self.cfg.verify_ssl if self.cfg.verify_ssl else False)
        timeout = aiohttp.ClientTimeout(total=self.cfg.timeout)
        url = f"{self.cfg.url}{path}"
        try:
            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                async with session.get(url, params=params, headers=self._headers()) as resp:
                    text = await resp.text()
                    if resp.status == 401:
                        raise InventorySourceError(
                            f"{self.type} '{self.name}': authentication failed (401). Check the token."
                        )
                    if resp.status >= 400:
                        raise InventorySourceError(
                            f"{self.type} '{self.name}': HTTP {resp.status} on {path} — {text[:200]}"
                        )
                    return await resp.json()
        except asyncio.TimeoutError as exc:
            raise InventorySourceError(
                f"{self.type} '{self.name}': timeout after {self.cfg.timeout}s querying {url}."
            ) from exc
        except aiohttp.ClientError as exc:
            raise InventorySourceError(
                f"{self.type} '{self.name}': connection error to {url}: {type(exc).__name__} — {exc}"
            ) from exc

    @staticmethod
    def _extract_primary_ip(record: dict) -> str:
        for key in ("primary_ip", "primary_ip4", "primary_ip6"):
            ref = record.get(key)
            if isinstance(ref, dict) and ref.get("address"):
                return _strip_prefix_len(ref["address"])
        # Nautobot may expose host/name fields directly.
        return ""

    @staticmethod
    def _ref_name(value: Any) -> Any:
        if isinstance(value, dict):
            return value.get("name") or value.get("slug") or value.get("display")
        return value

    def _normalize(self, record: dict) -> Optional[dict]:
        name = record.get("name") or record.get("display")
        if not name:
            return None
        host = self._extract_primary_ip(record)
        tags = []
        for t in record.get("tags", []) or []:
            tags.append(self._ref_name(t) if isinstance(t, dict) else t)
        extra = {
            "site": self._ref_name(record.get("site")) or self._ref_name(record.get("location")),
            "tenant": self._ref_name(record.get("tenant")),
            "location": self._ref_name(record.get("location")),
            "rack": self._ref_name(record.get("rack")),
            "role": self._ref_name(record.get("role") or record.get("device_role")),
            "status": self._ref_name(record.get("status")),
            "tags": tags,
            "custom_fields": record.get("custom_fields", {}) or {},
        }
        item: dict[str, Any] = {
            "name": name,
            "host": host or name,
            "source": self.name,
            "tags": tags,
            "extra": extra,
        }
        if extra.get("site"):
            item["site"] = extra["site"]
        return item

    async def _resolve_filters(self, filters: dict | None) -> dict:
        """Hook to translate human-friendly filter values (e.g. object names)
        into the representation the backend expects. Base: no translation."""
        return dict(filters or {})

    async def query(self, filters: dict | None = None, limit: int = 100) -> list[dict]:
        resolved = await self._resolve_filters(filters)
        params = self._build_params(resolved, limit)
        data = await self._request(self.devices_path, params)
        results = data.get("results", data if isinstance(data, list) else [])
        out: list[dict] = []
        for record in results:
            norm = self._normalize(record)
            if norm:
                out.append(norm)
        return out

    async def get_device(self, identifier: str) -> Optional[dict]:
        # Try by name first.
        by_name = await self.query({"name": identifier}, limit=5)
        for d in by_name:
            if str(d["name"]).lower() == identifier.lower():
                return d
        if by_name:
            return by_name[0]
        # Then by management IP.
        for ip_key in ("primary_ip_address", "address"):
            try:
                data = await self._request(self.devices_path, {ip_key: identifier, "limit": 5})
            except InventorySourceError:
                continue
            results = data.get("results", [])
            for record in results:
                norm = self._normalize(record)
                if norm and (norm["host"] == identifier or norm["name"] == identifier):
                    return norm
        return None

    async def health(self) -> dict:
        try:
            await self._request(self.devices_path, {"limit": 1})
            return {"source": self.name, "type": self.type, "reachable": True}
        except InventorySourceError as exc:
            return {"source": self.name, "type": self.type, "reachable": False, "error": str(exc)}


class NetBoxSource(_RestDeviceSource):
    """NetBox DCIM source.

    NetBox device filters such as `site`, `tenant`, `location`, `region`,
    `role`, `manufacturer`, `platform` and `tag` expect the object SLUG, and
    NetBox returns HTTP 400 when a non-existent slug is given. To accept the
    human-friendly NAME a user naturally types (e.g. tenant "Campus"), those
    filters are resolved to their slug via the matching NetBox endpoint before
    the device query is issued."""

    # filter key -> NetBox endpoint used to resolve a name into a slug.
    _SLUG_ENDPOINTS = {
        "site": "/api/dcim/sites/",
        "location": "/api/dcim/locations/",
        "region": "/api/dcim/regions/",
        "tenant": "/api/tenancy/tenants/",
        "role": "/api/dcim/device-roles/",
        "device_role": "/api/dcim/device-roles/",
        "manufacturer": "/api/dcim/manufacturers/",
        "platform": "/api/dcim/platforms/",
        "tag": "/api/extras/tags/",
    }

    async def _lookup_slug(self, endpoint: str, value: str) -> Optional[str]:
        """Resolve a single value (name or slug) to its slug. Tries a
        case-insensitive name match first, then an exact slug match."""
        for params in ({"name__ie": value}, {"slug": value}):
            params["limit"] = 1
            try:
                data = await self._request(endpoint, params)
            except InventorySourceError:
                continue
            results = data.get("results", [])
            if results:
                return results[0].get("slug") or results[0].get("name") or value
        return None

    async def _resolve_filters(self, filters: dict | None) -> dict:
        resolved = dict(filters or {})
        unresolved: list[str] = []
        for key, endpoint in self._SLUG_ENDPOINTS.items():
            if key not in resolved or resolved[key] in (None, ""):
                continue
            value = resolved[key]
            values = value if isinstance(value, (list, tuple)) else [value]
            out = []
            for v in values:
                slug = await self._lookup_slug(endpoint, str(v))
                if slug is None:
                    unresolved.append(f"{key}='{v}'")
                else:
                    out.append(slug)
            resolved[key] = out if isinstance(value, (list, tuple)) else (out[0] if out else value)
        if unresolved:
            raise InventorySourceError(
                f"netbox '{self.name}': no matching object for "
                f"{', '.join(unresolved)} (check spelling/case)."
            )
        return resolved


class NautobotSource(_RestDeviceSource):
    def _build_params(self, filters: dict | None, limit: int) -> dict:
        params = super()._build_params(filters, limit)
        # Nautobot 2.x replaced `site` with `location`; accept either by
        # mirroring the value so the query works on both generations.
        if "site" in params and "location" not in params:
            params["location"] = params["site"]
        return params


class InfrahubSource(InventorySource):
    """Infrahub (OpsMill) source — queried through its GraphQL API.

    Devices are pulled from a configurable node kind (default ``InfraDevice``)
    and the human-friendly search criteria are translated into GraphQL filter
    arguments. The defaults below match the common Infrahub data model and can
    be overridden per-source via the ``options`` block of the inventory file::

        source: infrahub
        sources:
          infrahub:
            type: infrahub
            url: https://infrahub.example.com   # or INFRAHUB_URL env var
            token: <api-token>                  # or INFRAHUB_TOKEN env var
            branch: main
            device_kind: InfraDevice
            # logical criterion -> GraphQL filter argument (override as needed)
            filter_map:
              zone: location__zone__name__value
            # relationships pulled into each result's `extra` block
            metadata_relationships: [site, location, rack, zone]

    Supported search criteria (logical name -> default GraphQL filter):

      - ``device`` / ``name`` -> ``name__value``
      - ``device_group``      -> ``member_of_groups__name__value``
      - ``location``          -> ``location__name__value``
      - ``site``              -> ``site__name__value``
      - ``rack``              -> ``rack__name__value``
      - ``zone``              -> ``zone__name__value``

    Filters and the result selection set are independent: an unknown criterion
    surfaces a clear GraphQL error so the mapping can be adjusted in ``options``
    without code changes.
    """

    DEFAULT_DEVICE_KIND = "InfraDevice"
    DEFAULT_BRANCH = "main"
    DEFAULT_AUTH_HEADER = "X-INFRAHUB-KEY"

    # logical search criterion -> GraphQL filter argument.
    DEFAULT_FILTER_MAP = {
        "device": "name__value",
        "name": "name__value",
        "device_group": "member_of_groups__name__value",
        "group": "member_of_groups__name__value",
        "location": "location__name__value",
        "site": "site__name__value",
        "rack": "rack__name__value",
        "zone": "zone__name__value",
        "role": "role__name__value",
        "status": "status__value",
        "platform": "platform__name__value",
        "manufacturer": "platform__manufacturer__name__value",
        "tenant": "tenant__name__value",
        "tag": "tags__name__value",
    }

    # Cardinality-one relationships rendered into each node selection set and
    # surfaced under `extra` (each as `<rel> { node { name { value } } }`).
    DEFAULT_METADATA_RELATIONSHIPS = ["site", "location", "rack", "zone", "role"]

    def __init__(self, cfg: SourceConfig):
        super().__init__(cfg)
        if not cfg.url:
            raise InventorySourceError(
                f"Source '{cfg.name}' (infrahub) has no URL "
                f"(set it in the inventory or via the INFRAHUB_URL env var)."
            )
        opts = cfg.options or {}
        self.branch = str(opts.get("branch") or self.DEFAULT_BRANCH)
        self.device_kind = str(
            opts.get("device_kind") or opts.get("kind") or self.DEFAULT_DEVICE_KIND
        )
        self.auth_header = str(opts.get("auth_header") or self.DEFAULT_AUTH_HEADER)
        self.address_relationship = opts.get("address_relationship", "primary_address")
        self.address_attribute = str(opts.get("address_attribute") or "address")
        self.name_attribute = str(opts.get("name_attribute") or "name")

        self.filter_map = dict(self.DEFAULT_FILTER_MAP)
        extra_map = opts.get("filter_map")
        if isinstance(extra_map, dict):
            self.filter_map.update({str(k).lower(): str(v) for k, v in extra_map.items()})

        rels = opts.get("metadata_relationships")
        if rels is None:
            self.metadata_relationships = list(self.DEFAULT_METADATA_RELATIONSHIPS)
        elif isinstance(rels, (list, tuple)):
            self.metadata_relationships = [str(r) for r in rels]
        else:
            self.metadata_relationships = []
        # Retry with a minimal selection set when the rich one references a
        # relationship that is absent from a customized schema.
        self._allow_minimal_fallback = bool(opts.get("minimal_fallback", True))

    # -- endpoint / auth ------------------------------------------------------

    @property
    def _graphql_url(self) -> str:
        return f"{self.cfg.url}/graphql/{self.branch}"

    def _headers(self) -> dict:
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self.cfg.token:
            headers[self.auth_header] = self.cfg.token
        return headers

    # -- GraphQL transport ----------------------------------------------------

    async def _graphql(self, query: str) -> dict:
        connector = aiohttp.TCPConnector(
            ssl=self.cfg.verify_ssl if self.cfg.verify_ssl else False
        )
        timeout = aiohttp.ClientTimeout(total=self.cfg.timeout)
        url = self._graphql_url
        try:
            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                async with session.post(url, json={"query": query}, headers=self._headers()) as resp:
                    text = await resp.text()
                    if resp.status in (401, 403):
                        raise InventorySourceError(
                            f"infrahub '{self.name}': authentication failed "
                            f"(HTTP {resp.status}). Check the API token."
                        )
                    if resp.status >= 400:
                        raise InventorySourceError(
                            f"infrahub '{self.name}': HTTP {resp.status} on {url} — {text[:200]}"
                        )
                    try:
                        payload = await resp.json()
                    except (aiohttp.ContentTypeError, ValueError) as exc:
                        raise InventorySourceError(
                            f"infrahub '{self.name}': invalid JSON response — {text[:200]}"
                        ) from exc
        except asyncio.TimeoutError as exc:
            raise InventorySourceError(
                f"infrahub '{self.name}': timeout after {self.cfg.timeout}s querying {url}."
            ) from exc
        except aiohttp.ClientError as exc:
            raise InventorySourceError(
                f"infrahub '{self.name}': connection error to {url}: {type(exc).__name__} — {exc}"
            ) from exc

        if isinstance(payload, dict) and payload.get("errors"):
            messages = "; ".join(
                str(e.get("message", e)) for e in payload["errors"] if isinstance(e, dict)
            ) or str(payload["errors"])
            raise InventorySourceError(f"infrahub '{self.name}': GraphQL error — {messages}")
        return payload.get("data", {}) if isinstance(payload, dict) else {}

    # -- query building -------------------------------------------------------

    def _build_filter_args(self, filters: dict | None) -> str:
        args: list[str] = []
        for key, value in (filters or {}).items():
            if value in (None, ""):
                continue
            lkey = str(key).lower()
            if lkey in self.filter_map:
                gql_key = self.filter_map[lkey]
            elif "__" in str(key):
                gql_key = str(key)              # already a GraphQL filter path
            else:
                gql_key = f"{key}__value"       # plain attribute fallback
            args.append(f"{gql_key}: {json.dumps(value)}")
        return ", ".join(args)

    def _selection_set(self, rich: bool = True) -> str:
        parts = ["id", "display_label", f"{self.name_attribute} {{ value }}"]
        if self.address_relationship:
            parts.append(
                f"{self.address_relationship} "
                f"{{ node {{ {self.address_attribute} {{ value }} }} }}"
            )
        if rich:
            for spec in self.metadata_relationships:
                rel, attr = self._rel_spec(spec)
                parts.append(f"{rel} {{ node {{ {attr} {{ value }} }} }}")
        return "\n          ".join(parts)

    def _build_query(self, filters: dict | None, limit: int, rich: bool = True) -> str:
        call_args = [f"limit: {int(limit)}"]
        filter_args = self._build_filter_args(filters)
        if filter_args:
            call_args.append(filter_args)
        args_str = ", ".join(call_args)
        return (
            "query {\n"
            f"  {self.device_kind}({args_str}) {{\n"
            "    count\n"
            "    edges {\n"
            "      node {\n"
            f"          {self._selection_set(rich)}\n"
            "      }\n"
            "    }\n"
            "  }\n"
            "}"
        )

    # -- response normalization ----------------------------------------------

    @staticmethod
    def _attr_value(attr: Any) -> Any:
        """Infrahub attributes are wrapped: ``{ "value": <x> }``."""
        if isinstance(attr, dict):
            return attr.get("value")
        return attr

    @staticmethod
    def _rel_node(rel: Any) -> Optional[dict]:
        """Cardinality-one relationships are wrapped: ``{ "node": {...} }``."""
        if isinstance(rel, dict):
            node = rel.get("node")
            if isinstance(node, dict):
                return node
        return None

    @staticmethod
    def _rel_spec(spec: str) -> tuple:
        """Parse a metadata-relationship spec into ``(relationship, attribute)``.

        ``"zone"`` -> ``("zone", "name")`` ; ``"location:shortname"`` ->
        ``("location", "shortname")``. Lets a source point at the attribute
        that actually identifies a related node (some Infrahub kinds expose
        ``shortname`` rather than ``name``)."""
        rel, _sep, attr = str(spec).partition(":")
        return rel.strip(), (attr.strip() or "name")

    def _normalize(self, node: dict) -> Optional[dict]:
        if not isinstance(node, dict):
            return None
        name = self._attr_value(node.get(self.name_attribute)) or node.get("display_label")
        if not name:
            return None
        host = ""
        if self.address_relationship:
            addr_node = self._rel_node(node.get(self.address_relationship))
            if addr_node:
                host = _strip_prefix_len(
                    self._attr_value(addr_node.get(self.address_attribute)) or ""
                )
        extra: dict[str, Any] = {}
        for spec in self.metadata_relationships:
            rel, attr = self._rel_spec(spec)
            rel_node = self._rel_node(node.get(rel))
            if rel_node is not None:
                extra[rel] = self._attr_value(rel_node.get(attr))
        item: dict[str, Any] = {
            "name": name,
            "host": host or name,
            "source": self.name,
            "tags": [],
            "extra": extra,
        }
        site = extra.get("site") or extra.get("location")
        if site:
            item["site"] = site
        return item

    def _records_from_data(self, data: dict) -> list[dict]:
        kind_data = data.get(self.device_kind, {}) if isinstance(data, dict) else {}
        edges = kind_data.get("edges", []) if isinstance(kind_data, dict) else []
        out: list[dict] = []
        for edge in edges:
            node = edge.get("node") if isinstance(edge, dict) else None
            norm = self._normalize(node)
            if norm:
                out.append(norm)
        return out

    # -- public API -----------------------------------------------------------

    async def query(self, filters: dict | None = None, limit: int = 100) -> list[dict]:
        try:
            data = await self._graphql(self._build_query(filters, limit, rich=True))
        except InventorySourceError:
            if not (self.metadata_relationships and self._allow_minimal_fallback):
                raise
            # The rich selection set may reference relationships absent from a
            # customized schema. The filters are unaffected, so retry with a
            # minimal selection set so device discovery still works. A genuinely
            # invalid filter fails again below and re-raises.
            logger.warning(
                "infrahub '%s': rich query failed, retrying with a minimal "
                "selection set (set options.metadata_relationships to match "
                "your schema).", self.name,
            )
            data = await self._graphql(self._build_query(filters, limit, rich=False))
        return self._records_from_data(data)

    async def get_device(self, identifier: str) -> Optional[dict]:
        # Try by name first.
        by_name = await self.query({"name": identifier}, limit=5)
        for d in by_name:
            if str(d["name"]).lower() == identifier.lower():
                return d
        if by_name:
            return by_name[0]
        # Then by management IP via the address relationship.
        if self.address_relationship:
            addr_filter = (
                f"{self.address_relationship}__{self.address_attribute}__value"
            )
            try:
                data = await self._graphql(
                    self._build_query({addr_filter: identifier}, 5, rich=True)
                )
            except InventorySourceError:
                return None
            for norm in self._records_from_data(data):
                if norm["host"] == identifier or norm["host"].startswith(f"{identifier}/"):
                    return norm
        return None

    async def health(self) -> dict:
        try:
            await self._graphql(self._build_query(None, 1, rich=False))
            return {"source": self.name, "type": self.type,
                    "reachable": True, "branch": self.branch}
        except InventorySourceError as exc:
            return {"source": self.name, "type": self.type,
                    "reachable": False, "error": str(exc)}


def build_source_client(cfg: SourceConfig) -> InventorySource:
    if cfg.type == "netbox":
        return NetBoxSource(cfg)
    if cfg.type == "nautobot":
        return NautobotSource(cfg)
    if cfg.type == "infrahub":
        return InfrahubSource(cfg)
    raise InventorySourceError(f"Unsupported source type: {cfg.type}")


# ─── HashiCorp Vault ─────────────────────────────────────────────────────────


class VaultClient:
    """Minimal async HashiCorp Vault client (KV v1/v2) for credential lookup."""

    def __init__(self, cfg: VaultConfig):
        self.cfg = cfg

    @property
    def configured(self) -> bool:
        return bool(self.cfg.enabled and self.cfg.url and self.cfg.token)

    def _secret_url(self, path: str) -> str:
        base = self.cfg.url.rstrip("/")
        mount = self.cfg.mount.strip("/")
        path = path.lstrip("/")
        if self.cfg.kv_version == 2:
            return f"{base}/v1/{mount}/data/{path}"
        return f"{base}/v1/{mount}/{path}"

    async def get_credentials(self, device_name: str) -> Optional[dict]:
        if not self.configured:
            return None
        path = self.cfg.path_template.format(device=device_name, name=device_name)
        url = self._secret_url(path)
        connector = aiohttp.TCPConnector(ssl=self.cfg.verify_ssl if self.cfg.verify_ssl else False)
        timeout = aiohttp.ClientTimeout(total=self.cfg.timeout)
        try:
            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                async with session.get(url, headers={"X-Vault-Token": self.cfg.token}) as resp:
                    if resp.status == 404:
                        return None
                    if resp.status >= 400:
                        text = await resp.text()
                        raise InventorySourceError(
                            f"Vault: HTTP {resp.status} reading {path} — {text[:200]}"
                        )
                    payload = await resp.json()
        except asyncio.TimeoutError as exc:
            raise InventorySourceError(f"Vault: timeout after {self.cfg.timeout}s reading {path}.") from exc
        except aiohttp.ClientError as exc:
            raise InventorySourceError(
                f"Vault: connection error to {self.cfg.url}: {type(exc).__name__} — {exc}"
            ) from exc

        data = payload.get("data", {})
        if self.cfg.kv_version == 2:
            data = data.get("data", {}) if isinstance(data, dict) else {}
        if not isinstance(data, dict):
            return None
        creds: dict[str, str] = {}
        mapping = {
            "username": self.cfg.username_field,
            "password": self.cfg.password_field,
            "ssh_username": self.cfg.ssh_username_field,
            "ssh_password": self.cfg.ssh_password_field,
        }
        for out_key, field_name in mapping.items():
            if field_name in data and data[field_name] not in (None, ""):
                creds[out_key] = data[field_name]
        return creds or None

    async def health(self) -> dict:
        if not self.cfg.enabled:
            return {"enabled": False}
        if not (self.cfg.url and self.cfg.token):
            return {"enabled": True, "reachable": False,
                    "error": "Vault URL/token missing (set VAULT_ADDR / VAULT_TOKEN)."}
        connector = aiohttp.TCPConnector(ssl=self.cfg.verify_ssl if self.cfg.verify_ssl else False)
        timeout = aiohttp.ClientTimeout(total=self.cfg.timeout)
        try:
            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                async with session.get(f"{self.cfg.url.rstrip('/')}/v1/sys/health",
                                       headers={"X-Vault-Token": self.cfg.token}) as resp:
                    return {"enabled": True, "reachable": resp.status < 500, "status": resp.status}
        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
            return {"enabled": True, "reachable": False, "error": str(exc)}


# ─── Inventory manager ───────────────────────────────────────────────────────


class InventoryManager:
    """Orchestrates local + external inventory sources and Vault credentials."""

    def __init__(self, inventory: Inventory):
        self.inventory = inventory
        self.vault = VaultClient(inventory.vault)
        self._clients: dict[str, InventorySource] = {}
        for name, cfg in inventory.sources.items():
            if cfg.type == LOCAL_SOURCE:
                continue
            try:
                self._clients[name] = build_source_client(cfg)
            except InventorySourceError as exc:
                logger.warning("⚠️  Inventory source '%s' disabled: %s", name, exc)

    # -- introspection --------------------------------------------------------

    def priority_index(self, source_name: str) -> int:
        order = self.inventory.source_order
        return order.index(source_name) if source_name in order else len(order)

    @property
    def has_external_sources(self) -> bool:
        return bool(self._clients)

    def list_sources(self) -> list[dict]:
        out = []
        for name in self.inventory.source_order:
            cfg = self.inventory.sources.get(name)
            if cfg is None:
                continue
            entry = {
                "name": name,
                "type": cfg.type,
                "priority": self.priority_index(name),
                "is_default": cfg.type == LOCAL_SOURCE,
            }
            if cfg.type != LOCAL_SOURCE:
                entry["url"] = cfg.url
                entry["has_token"] = cfg.has_token
                entry["token"] = _mask(cfg.token)
                entry["verify_ssl"] = cfg.verify_ssl
                entry["active"] = name in self._clients
            out.append(entry)
        return out

    async def sources_health(self) -> list[dict]:
        results = []
        for name in self.inventory.source_order:
            cfg = self.inventory.sources.get(name)
            if cfg is None:
                continue
            if cfg.type == LOCAL_SOURCE:
                results.append({"source": name, "type": LOCAL_SOURCE, "reachable": True})
            elif name in self._clients:
                results.append(await self._clients[name].health())
            else:
                results.append({"source": name, "type": cfg.type, "reachable": False,
                                "error": "source not initialized (missing URL/token)"})
        return results

    # -- queries --------------------------------------------------------------

    async def find_devices(self, filters: dict | None = None,
                           source: str | None = None,
                           local_devices: dict[str, DeviceConfig] | None = None,
                           limit: int = 100) -> dict:
        """Query the configured sources (priority order) and merge by name.

        Returns {"devices": [...], "errors": {...}, "queried_sources": [...]}.
        Higher-priority sources win when a name appears in several sources."""
        order = [source] if source else list(self.inventory.source_order)
        merged: dict[str, dict] = {}
        provenance: dict[str, int] = {}
        errors: dict[str, str] = {}
        queried: list[str] = []

        for src_name in order:
            cfg = self.inventory.sources.get(src_name)
            if cfg is None and src_name not in self._clients:
                errors[src_name] = "unknown source"
                continue
            prio = self.priority_index(src_name)
            queried.append(src_name)
            if cfg and cfg.type == LOCAL_SOURCE:
                for rec in self._filter_local(local_devices or {}, filters):
                    self._merge(merged, provenance, rec, prio)
                continue
            client = self._clients.get(src_name)
            if client is None:
                errors[src_name] = "source not initialized (missing URL/token)"
                continue
            try:
                for rec in await client.query(filters, limit=limit):
                    self._merge(merged, provenance, rec, prio)
            except InventorySourceError as exc:
                errors[src_name] = str(exc)

        return {
            "devices": list(merged.values()),
            "errors": errors,
            "queried_sources": queried,
        }

    async def resolve_device(self, identifier: str,
                             local_devices: dict[str, DeviceConfig] | None = None) -> Optional[dict]:
        """Resolve a single device (name or IP) honoring source priority."""
        best: Optional[dict] = None
        best_prio = None
        local_devices = local_devices or {}
        for src_name in self.inventory.source_order:
            cfg = self.inventory.sources.get(src_name)
            prio = self.priority_index(src_name)
            rec = None
            if cfg and cfg.type == LOCAL_SOURCE:
                rec = self._local_lookup(local_devices, identifier)
            elif src_name in self._clients:
                try:
                    rec = await self._clients[src_name].get_device(identifier)
                except InventorySourceError as exc:
                    logger.warning("resolve_device: %s", exc)
                    rec = None
            if rec and (best_prio is None or prio < best_prio):
                best, best_prio = rec, prio
        return best

    async def prefetch(self, local_devices: dict[str, DeviceConfig],
                       defaults: dict | None = None, limit: int = 500) -> dict:
        """Pull external devices and merge them into `local_devices` in place,
        honoring source priority. Returns a summary."""
        summary = {"added": [], "updated": [], "errors": {}, "sources": []}
        # provenance priority for devices already present (local).
        local_prio = self.priority_index(LOCAL_SOURCE)
        provenance = {name: local_prio for name in local_devices}

        for src_name in self.inventory.source_order:
            client = self._clients.get(src_name)
            if client is None:
                continue
            prio = self.priority_index(src_name)
            summary["sources"].append(src_name)
            try:
                records = await client.query(None, limit=limit)
            except InventorySourceError as exc:
                summary["errors"][src_name] = str(exc)
                continue
            for rec in records:
                name = rec["name"]
                current = provenance.get(name)
                if current is not None and current <= prio:
                    continue  # keep the higher- or equal-priority source
                dev = build_device_from_source(rec, src_name, defaults)
                if name in local_devices:
                    summary["updated"].append(name)
                else:
                    summary["added"].append(name)
                local_devices[name] = dev
                provenance[name] = prio
        return summary

    # -- credentials ----------------------------------------------------------

    async def resolve_credentials(self, dev: DeviceConfig) -> dict:
        """Return the credentials to use for `dev`, applying the priority:
        device-specific > Vault > env/defaults. Mutates nothing.

        Returns {username, password, ssh_username, ssh_password, source}."""
        result = {
            "username": dev.username,
            "password": dev.password,
            "ssh_username": dev.ssh_username,
            "ssh_password": dev.ssh_password,
            "source": "inventory/env",
        }
        use_vault = dev.vault or self.inventory.vault.enabled
        # Only consult Vault for fields that were not explicitly set on the device.
        if use_vault and self.vault.configured:
            try:
                vault_creds = await self.vault.get_credentials(dev.name)
            except InventorySourceError as exc:
                logger.warning("Vault lookup failed for %s: %s", dev.name, exc)
                vault_creds = None
            if vault_creds:
                result["source"] = "vault"
                if "username" not in dev.explicit and vault_creds.get("username"):
                    result["username"] = vault_creds["username"]
                if "password" not in dev.explicit and vault_creds.get("password"):
                    result["password"] = vault_creds["password"]
                if "ssh_username" not in dev.explicit and vault_creds.get("ssh_username"):
                    result["ssh_username"] = vault_creds["ssh_username"]
                elif "ssh_username" not in dev.explicit and vault_creds.get("username"):
                    result["ssh_username"] = vault_creds["username"]
                if "ssh_password" not in dev.explicit and vault_creds.get("ssh_password"):
                    result["ssh_password"] = vault_creds["ssh_password"]
                elif "ssh_password" not in dev.explicit and vault_creds.get("password"):
                    result["ssh_password"] = vault_creds["password"]
        return result

    # -- helpers --------------------------------------------------------------

    @staticmethod
    def _merge(merged: dict, provenance: dict, rec: dict, prio: int) -> None:
        name = rec.get("name")
        if not name:
            return
        current = provenance.get(name)
        if current is None or prio < current:
            merged[name] = rec
            provenance[name] = prio

    @staticmethod
    def _local_record(dev: DeviceConfig) -> dict:
        return {
            "name": dev.name,
            "host": dev.host,
            "source": dev.source or LOCAL_SOURCE,
            "tags": list(dev.tags),
            "site": dev.site,
            "extra": {
                "site": dev.site,
                "tags": list(dev.tags),
                "description": dev.description,
                **(dev.extra or {}),
            },
        }

    def _local_lookup(self, local_devices: dict[str, DeviceConfig], identifier: str) -> Optional[dict]:
        dev = local_devices.get(identifier)
        if dev is None:
            dev = next((d for d in local_devices.values() if d.host == identifier), None)
        return self._local_record(dev) if dev else None

    def _filter_local(self, local_devices: dict[str, DeviceConfig],
                      filters: dict | None) -> list[dict]:
        records = [self._local_record(d) for d in local_devices.values()]
        if not filters:
            return records
        out = []
        for rec in records:
            if self._matches(rec, filters):
                out.append(rec)
        return out

    @staticmethod
    def _matches(rec: dict, filters: dict) -> bool:
        extra = rec.get("extra", {})
        for key, value in filters.items():
            if value in (None, ""):
                continue
            lkey = key.lower()
            if lkey == "name":
                if str(value).lower() not in str(rec.get("name", "")).lower():
                    return False
            elif lkey == "tag":
                tags = [str(t).lower() for t in rec.get("tags", [])]
                if str(value).lower() not in tags:
                    return False
            elif lkey in ("site", "tenant", "location", "rack", "role", "status"):
                if str(extra.get(lkey, "")).lower() != str(value).lower():
                    return False
            else:
                # Custom field match against extra.custom_fields or extra.
                cf = extra.get("custom_fields", {}) or {}
                candidate = cf.get(key, extra.get(key))
                if str(candidate).lower() != str(value).lower():
                    return False
        return True
