"""
ArubaOS-CX REST API client (v10.x)
Handles session cookie authentication and all API requests.
"""

import asyncio
import base64
import calendar
import difflib
import ipaddress
import logging
import random
import re
import time
from urllib.parse import quote, unquote
from typing import Any, Optional

import aiohttp

logger = logging.getLogger(__name__)

DEFAULT_API_VERSION = "v10.18"
_API_VERSION_RE = re.compile(r"^v?\d+\.\d+$", re.IGNORECASE)


class ArubaAPIError(Exception):
    def __init__(self, message: str, status_code: int | None = None):
        super().__init__(message)
        self.status_code = status_code

    def __str__(self):
        if self.status_code:
            return f"[HTTP {self.status_code}] {super().__str__()}"
        return super().__str__()


# ══════════════════════════════════════════════════════════════════════
# Input compliance validators — fail fast with a clear, LLM-friendly message
# BEFORE any request reaches the switch. Values are returned as the strings/
# ints the firmware expects (we validate compliance, we do NOT change types).
# Bounds taken from openapi.json (ip_mtu 68-9198) and the relevant RFC/IEEE
# ranges (VLAN 1-4094, VNI 24-bit, 4-byte ASN).
# ══════════════════════════════════════════════════════════════════════

_MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
_VLAN_MIN, _VLAN_MAX = 1, 4094
_VNI_MIN, _VNI_MAX = 1, 16777215            # 24-bit VXLAN VNI
_ASN_MIN, _ASN_MAX = 1, 4294967295          # 4-byte AS number
_MTU_MIN, _MTU_MAX = 68, 9198               # openapi ip_mtu bounds


def _v_mac(value: Any, field: str = "mac") -> str:
    """Validate a MAC address. Returns it normalised to lower-case."""
    if not isinstance(value, str) or not _MAC_RE.match(value.strip()):
        raise ArubaAPIError(
            f"Invalid {field} '{value}'. Expected a MAC address in the form "
            "AA:BB:CC:DD:EE:FF (six colon-separated hex octets).", 400)
    return value.strip().lower()


def _v_ipv4_host(value: Any, field: str = "ip") -> str:
    """Validate a bare IPv4 host address (no prefix). Returns it unchanged."""
    s = str(value).strip()
    try:
        ip = ipaddress.ip_address(s)
    except ValueError:
        raise ArubaAPIError(
            f"Invalid {field} '{value}'. Expected an IPv4 address like "
            "10.0.0.1.", 400)
    if ip.version != 4:
        raise ArubaAPIError(
            f"Invalid {field} '{value}'. Expected an IPv4 address (got an "
            "IPv6 address).", 400)
    return s


def _v_ip_host(value: Any, field: str = "ip") -> str:
    """Validate a bare IPv4 OR IPv6 host address (no prefix). Unchanged."""
    s = str(value).strip().split("/")[0]
    try:
        ipaddress.ip_address(s)
    except ValueError:
        raise ArubaAPIError(
            f"Invalid {field} '{value}'. Expected an IPv4 or IPv6 address "
            "like 10.0.0.1 or 2001:db8::1.", 400)
    return str(value).strip()


def _v_ipv4_cidr(value: Any, field: str = "ip4_address") -> str:
    """Validate an IPv4 address with an explicit prefix length (e.g.
    10.0.0.1/31). Host bits are allowed (interface address). Unchanged."""
    s = str(value).strip()
    if "/" not in s:
        raise ArubaAPIError(
            f"Invalid {field} '{value}'. Expected an IPv4 address with a "
            "prefix length, e.g. 10.0.0.1/31.", 400)
    try:
        iface = ipaddress.ip_interface(s)
    except ValueError:
        raise ArubaAPIError(
            f"Invalid {field} '{value}'. Expected an IPv4 address with a "
            "prefix length, e.g. 10.0.0.1/31.", 400)
    if iface.version != 4:
        raise ArubaAPIError(
            f"Invalid {field} '{value}'. Expected an IPv4 (not IPv6) address "
            "with a prefix length.", 400)
    return s


def _v_int_range(value: Any, lo: int, hi: int, field: str) -> int:
    """Validate an integer (or digit string) within [lo, hi]. Returns int."""
    try:
        n = int(value)
    except (TypeError, ValueError):
        raise ArubaAPIError(
            f"Invalid {field} '{value}'. Expected an integer between {lo} "
            f"and {hi}.", 400)
    if not lo <= n <= hi:
        raise ArubaAPIError(
            f"Invalid {field} '{value}'. Out of range: must be between {lo} "
            f"and {hi}.", 400)
    return n


def _v_vlan(value: Any, field: str = "vlan") -> int:
    return _v_int_range(value, _VLAN_MIN, _VLAN_MAX, field)


def _v_vni(value: Any, field: str = "vni") -> int:
    return _v_int_range(value, _VNI_MIN, _VNI_MAX, field)


def _v_mtu(value: Any, field: str = "mtu") -> int:
    return _v_int_range(value, _MTU_MIN, _MTU_MAX, field)


def _v_asn(value: Any, field: str = "asn") -> int:
    """Validate an AS number. Accepts a plain integer (1-4294967295) or
    asdot notation 'X.Y'. Returns the plain 32-bit integer the firmware uses."""
    s = str(value).strip()
    if "." in s and ":" not in s and not s.replace(".", "").strip().startswith("/"):
        parts = s.split(".")
        if len(parts) == 2 and all(p.isdigit() for p in parts):
            hi, lo = int(parts[0]), int(parts[1])
            if 0 <= hi <= 65535 and 0 <= lo <= 65535:
                n = hi * 65536 + lo
                if _ASN_MIN <= n <= _ASN_MAX:
                    return n
        raise ArubaAPIError(
            f"Invalid {field} '{value}'. Expected an AS number 1-4294967295 "
            "or asdot notation X.Y.", 400)
    return _v_int_range(value, _ASN_MIN, _ASN_MAX, field)


def _v_route_target(value: Any, field: str = "route_target") -> str:
    """Validate a route-target / route-distinguisher string. Accepts
    'ASN:NN' (e.g. 65001:250) or 'IPv4:NN' (e.g. 10.0.0.1:250). Unchanged."""
    s = str(value).strip()
    if s.count(":") != 1:
        raise ArubaAPIError(
            f"Invalid {field} '{value}'. Expected 'ASN:NN' (e.g. 65001:250) "
            "or 'IPv4:NN' (e.g. 10.0.0.1:250).", 400)
    left, right = s.split(":")
    if not right.isdigit() or not 0 <= int(right) <= _ASN_MAX:
        raise ArubaAPIError(
            f"Invalid {field} '{value}'. The value after ':' must be an "
            f"integer 0-{_ASN_MAX}.", 400)
    left_ok = False
    if left.isdigit() and 0 <= int(left) <= _ASN_MAX:
        left_ok = True
    else:
        try:
            ipaddress.IPv4Address(left)
            left_ok = True
        except ValueError:
            left_ok = False
    if not left_ok:
        raise ArubaAPIError(
            f"Invalid {field} '{value}'. The value before ':' must be an AS "
            f"number (0-{_ASN_MAX}) or an IPv4 address.", 400)
    return s


def _v_ospf_area(value: Any, field: str = "area_id") -> str:
    """Validate an OSPF area id: a 32-bit integer (0-4294967295) or a dotted
    IPv4 form (e.g. 0.0.0.0). Returns the value as a string."""
    s = str(value).strip()
    if s.isdigit():
        if not 0 <= int(s) <= 4294967295:
            raise ArubaAPIError(
                f"Invalid {field} '{value}'. Numeric area id must be "
                "0-4294967295.", 400)
        return s
    try:
        ipaddress.IPv4Address(s)
    except ValueError:
        raise ArubaAPIError(
            f"Invalid {field} '{value}'. Expected a number (0-4294967295) or "
            "a dotted form like 0.0.0.0.", 400)
    return s


class ArubaOSCXClient:
    """Asynchronous client for the ArubaOS-CX REST API."""

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        api_version: str = DEFAULT_API_VERSION,
        verify_ssl: bool = True,
        timeout: int = 30,
    ):
        self.host = host.rstrip("/")
        self.username = username
        self.password = password
        self.api_version = self._normalize_api_version(api_version)
        self._requested_api_version = self.api_version
        self.verify_ssl = verify_ssl
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self._session: aiohttp.ClientSession | None = None
        self._rest_root = f"https://{self.host}/rest"
        self._base_url = self._versioned_base_url(self.api_version)
        # If False, the session is NOT closed when leaving the context manager
        # (pooled for the duration of a workflow; explicit logout afterwards).
        self._auto_logout = True
        self._connect_lock: asyncio.Lock | None = None
        # Incremented on every successful (re)login. Used to coalesce concurrent
        # 401 recovery so peers don't tear down a freshly re-established session.
        self._session_gen = 0
        # Inventory-driven write policy. True = allows POST/PUT/DELETE (except
        # login/logout always allowed). False = read-only mode.
        self._write_enabled = True

    @staticmethod
    def _normalize_api_version(value: str) -> str:
        raw = (value or DEFAULT_API_VERSION).strip()
        if not raw:
            raw = DEFAULT_API_VERSION
        if raw.lower() == "latest":
            return "latest"
        if not _API_VERSION_RE.match(raw):
            raise ArubaAPIError(
                f"Invalid API version '{value}'. Use 'latest' or a version like 'v10.13'."
            )
        if not raw.lower().startswith("v"):
            raw = f"v{raw}"
        return raw.lower()

    def _versioned_base_url(self, api_version: str) -> str:
        return f"{self._rest_root}/{api_version}"

    async def _resolve_latest_api_version(self) -> str:
        assert self._session is not None
        try:
            async with self._session.get(self._rest_root, headers={"Content-Type": "application/json"}) as resp:
                if resp.status != 200:
                    text = await resp.text()
                    raise ArubaAPIError(
                        f"Failed to discover latest API version on {self.host}: {text}",
                        resp.status,
                    )
                data = await resp.json()
        except asyncio.TimeoutError as exc:
            raise ArubaAPIError(
                f"Timeout after {self.timeout.total:g}s while discovering the latest API version on {self.host}.",
                504,
            ) from exc
        except aiohttp.ClientError as exc:
            raise ArubaAPIError(
                f"Connection error while discovering the latest API version on {self.host}: {type(exc).__name__} — {exc}",
                502,
            ) from exc

        latest = data.get("latest") if isinstance(data, dict) else None
        version = latest.get("version") if isinstance(latest, dict) else None
        resolved = self._normalize_api_version(str(version or "")) if version else None
        if resolved is None:
            raise ArubaAPIError(
                f"Invalid API discovery payload on {self.host}: missing latest.version.",
                502,
            )
        return resolved

    async def _resolve_api_version(self) -> None:
        if self._requested_api_version == "latest":
            self.api_version = await self._resolve_latest_api_version()
        else:
            self.api_version = self._requested_api_version
        self._base_url = self._versioned_base_url(self.api_version)

    def set_write_enabled(self, enabled: bool) -> None:
        self._write_enabled = bool(enabled)

    def _assert_write_allowed(self, method: str, path: str) -> None:
        if self._write_enabled:
            return
        if path in ("/login", "/logout"):
            return
        # Troubleshoot instances are volatile, non-persistent diagnostics — allowed on read-only devices.
        if path.startswith("/system/troubleshoots") or path.startswith("/system/tshoot_"):
            return
        raise ArubaAPIError(
            f"Write blocked on {self.host}: device access_mode is read-only "
            f"({method} {path}).",
            403,
        )

    def _api_version_tuple(self) -> tuple[int, int]:
        """Return the API version as (major, minor), e.g.: 'v10.18' -> (10, 18)."""
        try:
            digits = self.api_version.lstrip("vV")
            major, _, minor = digits.partition(".")
            return (int(major), int(minor or 0))
        except (ValueError, AttributeError):
            return (0, 0)

    @staticmethod
    def _collection_items(data: Any) -> list[tuple[str, Any]]:
        if isinstance(data, dict):
            return [(str(key), value) for key, value in data.items()]
        if isinstance(data, list):
            items: list[tuple[str, Any]] = []
            for index, value in enumerate(data):
                if isinstance(value, dict):
                    key = (
                        value.get("name")
                        or value.get("id")
                        or value.get("interface_name")
                        or value.get("ip_or_ifname_or_group_name")
                        or value.get("prefix")
                        or value.get("interface")
                        or value.get("peer")
                        or str(index)
                    )
                    items.append((str(key), value))
                else:
                    items.append((str(index), value))
            return items
        return []

    async def __aenter__(self):
        await self._connect()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        # In pooled mode (_auto_logout=False), the session is kept open
        # so it can be reused by the following steps of the workflow.
        if self._auto_logout:
            await self._disconnect()

    @property
    def is_connected(self) -> bool:
        return self._session is not None and not self._session.closed

    async def logout(self) -> bool:
        """Explicitly close the REST session (POST /logout). Idempotent.
        Return True if a session was open and has been closed."""
        was_open = self.is_connected
        await self._disconnect()
        return was_open

    async def _connect(self):
        # Idempotent connection: if a session is already open, reuse it
        # (pooling). A lock prevents concurrent double-logins.
        if self.is_connected:
            return
        if self._connect_lock is None:
            self._connect_lock = asyncio.Lock()
        async with self._connect_lock:
            if self.is_connected:
                return
            connector = aiohttp.TCPConnector(ssl=self.verify_ssl if self.verify_ssl else False)
            self._session = aiohttp.ClientSession(
                connector=connector,
                timeout=self.timeout,
                headers={"Accept": "application/json"},  # no global Content-Type: it varies per request
                cookie_jar=aiohttp.CookieJar(unsafe=True),  # required to keep the session on IP addresses
            )
            try:
                await self._resolve_api_version()
                await self._login()
                self._session_gen += 1
            except Exception:
                await self._session.close()
                self._session = None
                raise

    async def _disconnect(self):
        if self._session:
            try:
                await self._session.post(f"{self._base_url}/logout")
            except Exception:
                pass
            await self._session.close()
            self._session = None

    async def _reconnect(self, stale_gen: int | None = None):
        """Drop the current (possibly server-side expired) session and re-authenticate.
        Used to transparently recover from an HTTP 401 on a pooled session: the
        device may expire the REST session on its side (idle/absolute timeout or
        max-concurrent-session eviction) while our local session object still looks
        open.

        `stale_gen` is the session generation observed by the caller before the
        failing request. If another concurrent request has already refreshed the
        session in the meantime, this call becomes a no-op so we never tear down a
        fresh session out from under an in-flight retry."""
        if self._connect_lock is None:
            self._connect_lock = asyncio.Lock()
        async with self._connect_lock:
            if stale_gen is not None and self._session_gen != stale_gen:
                return  # a peer already re-authenticated
            if self._session:
                try:
                    await self._session.close()
                except Exception:
                    pass
                self._session = None
        await self._connect()

    async def _ensure_live(self):
        """Guarantee a usable session before issuing a request.

        A pooled session can be torn down between workflow steps — device-side
        eviction, the idle reaper, or an aiohttp connector closed while the
        ClientSession object still looks open. In those states a request would
        raise "'NoneType' object has no attribute 'get'" (session is None) or
        "Connector is closed". Re-establish the session transparently first; the
        residual connector-closed edge is caught and retried by each request
        wrapper."""
        if self._session is None or self._session.closed:
            await self._connect()

    @staticmethod
    def _is_dead_session_error(exc: BaseException) -> bool:
        """True if `exc` signals a torn-down aiohttp session/connector that a
        reconnect can recover from (vs. a genuine network failure)."""
        return "closed" in str(exc).lower()

    async def _login(self):
        url = f"{self._base_url}/login"
        # ArubaOS-CX expects application/x-www-form-urlencoded, not JSON
        try:
            async with self._session.post(url, data={"username": self.username, "password": self.password}) as resp:
                if resp.status != 200:
                    text = await resp.text()
                    raise ArubaAPIError(
                        f"Authentication failed on {self.host} ({self.username}): {text}",
                        resp.status,
                    )
        except asyncio.TimeoutError as exc:
            raise ArubaAPIError(
                f"Timeout after {self.timeout.total:g}s while connecting to {self.host}. "
                f"The device is reachable but does not respond fast enough (increase the timeout).",
                504,
            ) from exc
        except aiohttp.ClientError as exc:
            raise ArubaAPIError(
                f"Connection error to {self.host}: {type(exc).__name__} — {exc}",
                502,
            ) from exc
        logger.info("✅ Connected to %s", self.host)

    async def _get(self, path: str, params: dict | None = None, _retried: bool = False) -> Any:
        url = f"{self._base_url}{path}"
        await self._ensure_live()
        gen = self._session_gen
        expired = False
        result: Any = {}
        try:
            async with self._session.get(url, params=params, headers={"Content-Type": "application/json"}) as resp:
                if resp.status == 401 and not _retried:
                    expired = True  # re-login + retry once, after releasing the response
                elif resp.status == 401:
                    raise ArubaAPIError("Session expired or not authorized", 401)
                elif resp.status == 404:
                    raise ArubaAPIError(f"Resource not found: {path}", 404)
                elif resp.status not in (200, 204):
                    text = await resp.text()
                    raise ArubaAPIError(f"GET {path} error: {text}", resp.status)
                elif resp.status == 204:
                    result = {}
                else:
                    result = await resp.json()
        except asyncio.TimeoutError as exc:
            raise ArubaAPIError(
                f"Timeout after {self.timeout.total:g}s on GET {path}"
                + (f" (params={params})" if params else "")
                + f". The device {self.host} takes too long to respond — "
                f"reduce the request depth or increase the timeout.",
                504,
            ) from exc
        except (aiohttp.ClientError, RuntimeError) as exc:
            if not _retried and self._is_dead_session_error(exc):
                expired = True  # dead pooled session → reconnect + retry once
            else:
                raise ArubaAPIError(
                    f"Network error on GET {path} to {self.host}: {type(exc).__name__} — {exc}",
                    502,
                ) from exc
        if expired:
            await self._reconnect(gen)
            return await self._get(path, params, _retried=True)
        return result

    async def _post(self, path: str, body: dict | None = None, params: dict | None = None, _retried: bool = False) -> Any:
        url = f"{self._base_url}{path}"
        self._assert_write_allowed("POST", path)
        await self._ensure_live()
        gen = self._session_gen
        expired = False
        result: Any = {}
        try:
            async with self._session.post(url, json=body, params=params, headers={"Content-Type": "application/json"}) as resp:
                if resp.status == 401 and not _retried:
                    expired = True  # re-login + retry once, after releasing the response
                elif resp.status == 401:
                    raise ArubaAPIError("Session expired or not authorized", 401)
                elif resp.status not in (200, 201, 202, 204):
                    text = await resp.text()
                    raise ArubaAPIError(f"POST {path} error: {text}", resp.status)
                elif resp.status == 204:
                    result = {}
                else:
                    try:
                        result = await resp.json()
                    except Exception:
                        result = {"raw": await resp.text()}
        except asyncio.TimeoutError as exc:
            raise ArubaAPIError(
                f"Timeout after {self.timeout.total:g}s on POST {path}. "
                f"The device {self.host} takes too long to respond — increase the timeout.",
                504,
            ) from exc
        except aiohttp.ClientError as exc:
            if not _retried and self._is_dead_session_error(exc):
                expired = True  # dead pooled session → reconnect + retry once
            else:
                raise ArubaAPIError(
                    f"Network error on POST {path} to {self.host}: {type(exc).__name__} — {exc}",
                    502,
                ) from exc
        if expired:
            await self._reconnect(gen)
            return await self._post(path, body, params, _retried=True)
        return result

    async def _put(self, path: str, body: dict | None = None, params: dict | None = None, _retried: bool = False) -> Any:
        url = f"{self._base_url}{path}"
        self._assert_write_allowed("PUT", path)
        await self._ensure_live()
        gen = self._session_gen
        expired = False
        result: Any = {}
        try:
            async with self._session.put(url, json=body, params=params, headers={"Content-Type": "application/json"}) as resp:
                if resp.status == 401 and not _retried:
                    expired = True  # re-login + retry once, after releasing the response
                elif resp.status == 401:
                    raise ArubaAPIError("Session expired or not authorized", 401)
                elif resp.status not in (200, 201, 202, 204):
                    text = await resp.text()
                    raise ArubaAPIError(f"PUT {path} error: {text}", resp.status)
                elif resp.status == 204:
                    result = {}
                else:
                    try:
                        result = await resp.json()
                    except Exception:
                        result = {"raw": await resp.text()}
        except asyncio.TimeoutError as exc:
            raise ArubaAPIError(
                f"Timeout after {self.timeout.total:g}s on PUT {path}. "
                f"The device {self.host} takes too long to respond — increase the timeout.",
                504,
            ) from exc
        except aiohttp.ClientError as exc:
            if not _retried and self._is_dead_session_error(exc):
                expired = True  # dead pooled session → reconnect + retry once
            else:
                raise ArubaAPIError(
                    f"Network error on PUT {path} to {self.host}: {type(exc).__name__} — {exc}",
                    502,
                ) from exc
        if expired:
            await self._reconnect(gen)
            return await self._put(path, body, params, _retried=True)
        return result

    async def _delete(self, path: str, _retried: bool = False) -> Any:
        url = f"{self._base_url}{path}"
        self._assert_write_allowed("DELETE", path)
        await self._ensure_live()
        gen = self._session_gen
        expired = False
        result: Any = {}
        try:
            async with self._session.delete(url, headers={"Content-Type": "application/json"}) as resp:
                if resp.status == 401 and not _retried:
                    expired = True  # re-login + retry once, after releasing the response
                elif resp.status == 401:
                    raise ArubaAPIError("Session expired or not authorized", 401)
                elif resp.status not in (200, 201, 202, 204):
                    text = await resp.text()
                    raise ArubaAPIError(f"DELETE {path} error: {text}", resp.status)
                elif resp.status == 204:
                    result = {}
                else:
                    try:
                        result = await resp.json()
                    except Exception:
                        result = {"raw": await resp.text()}
        except asyncio.TimeoutError as exc:
            raise ArubaAPIError(
                f"Timeout after {self.timeout.total:g}s on DELETE {path}. "
                f"The device {self.host} takes too long to respond — increase the timeout.",
                504,
            ) from exc
        except aiohttp.ClientError as exc:
            if not _retried and self._is_dead_session_error(exc):
                expired = True  # dead pooled session → reconnect + retry once
            else:
                raise ArubaAPIError(
                    f"Network error on DELETE {path} to {self.host}: {type(exc).__name__} — {exc}",
                    502,
                ) from exc
        if expired:
            await self._reconnect(gen)
            return await self._delete(path, _retried=True)
        return result

    # ─── System ──────────────────────────────────────────────────────────────

    async def get_system_info(self) -> dict:
        # Anti-timeout optimization: we do NOT request /system?depth=2 (which inlines
        # all child collections — interfaces, vlans, vrfs, routes… — and may
        # exceed the timeout on a chassis like the Border). We filter only the
        # useful scalar attributes (depth=1), and retrieve hardware details via
        # get_hardware_health() which queries each subsystem separately.
        attrs = "hostname,platform_name,software_version,software_info,boot_time,mgmt_intf_status"
        # The two requests are independent → run them in parallel.
        data, hardware = await asyncio.gather(
            self._get("/system", params={"attributes": attrs, "depth": "1"}),
            self.get_hardware_health(),
        )
        if not isinstance(data, dict):
            raise ArubaAPIError(f"Unexpected response from /system: {type(data).__name__}")

        software_info = data.get("software_info") if isinstance(data.get("software_info"), dict) else {}
        mgmt_intf = data.get("mgmt_intf_status")

        # Uptime derived from boot_time (epoch, present at top-level on all platforms).
        boot_time = data.get("boot_time")
        uptime_seconds: Any = "N/A"
        try:
            if boot_time is not None:
                uptime_seconds = max(0, int(time.time()) - int(boot_time))
        except (TypeError, ValueError):
            uptime_seconds = "N/A"

        # The switch serial and the vendor come from the chassis (system_info=None on these firmwares).
        chassis = next((m for m in hardware["modules"] if m.get("type") == "chassis"), None)
        serial_number = "N/A"
        vendor = "Aruba"
        if isinstance(chassis, dict):
            if chassis.get("serial_number") not in (None, "", "N/A"):
                serial_number = chassis["serial_number"]
            if chassis.get("vendor") not in (None, "", "N/A"):
                vendor = chassis["vendor"]

        return {
            "hostname": data.get("hostname", "N/A"),
            "platform_name": data.get("platform_name", "N/A"),
            "software_version": data.get("software_version", "N/A"),
            "build_date": software_info.get("build_date", "N/A"),
            "build_id": software_info.get("build_id", "N/A"),
            "serial_number": serial_number,
            "vendor": vendor,
            "boot_time": boot_time if boot_time is not None else "N/A",
            "uptime_seconds": uptime_seconds,
            "mgmt_interface": mgmt_intf if isinstance(mgmt_intf, dict) else {},
            "management_modules": hardware["management_modules"],
            "modules": hardware["modules"],
            "fans": hardware["fans"],
            "temperature": hardware["temp_sensors"],
            "power_supplies": hardware["power_supplies"],
            "hardware_faults": hardware["faults"],
            "hardware_health": hardware["health_summary"],
        }

    async def get_capacities(self) -> dict:
        """System resource capacities (scale/hardware limits) and their current
        consumption, grouped together. Reads two `/system` attributes in a single
        GET:
          - `capacities`        : the maximum/limit for each resource.
          - `capacities_status` : the amount currently consumed (sampled).
        Equivalent to the CLI `show capacities` + `show capacities-status`.
        Returns a `utilization` view (one entry per tracked resource, most-used
        first) plus the two raw maps."""
        data = await self._get(
            "/system",
            params={"attributes": "capacities,capacities_status", "depth": "2"},
        )
        if not isinstance(data, dict):
            raise ArubaAPIError(
                f"Unexpected response from /system: {type(data).__name__}"
            )
        capacities = data.get("capacities") if isinstance(data.get("capacities"), dict) else {}
        status = data.get("capacities_status") if isinstance(data.get("capacities_status"), dict) else {}

        utilization: list[dict] = []
        for key, used in status.items():
            limit = capacities.get(key)
            pct = None
            if isinstance(limit, (int, float)) and limit > 0 and isinstance(used, (int, float)):
                pct = round(used / limit * 100, 2)
            utilization.append(
                {"resource": key, "used": used, "capacity": limit, "utilization_pct": pct}
            )
        # Most-consumed first; entries without a computable percentage sort last.
        utilization.sort(key=lambda e: (e["utilization_pct"] is None, -(e["utilization_pct"] or 0)))

        return {
            "summary": {
                "capacities_count": len(capacities),
                "status_count": len(status),
                "tracked": len(utilization),
            },
            "utilization": utilization,
            "capacities": capacities,
            "capacities_status": status,
        }

    # ─── Troubleshoot (AOS-CX 10.18+) ─────────────────────────────────────────

    _TSHOOT_CHOICES = ("basic-health", "config", "health", "operations", "detailed")

    @staticmethod
    def _str_bool(value: Any) -> bool:
        return str(value).strip().lower() in ("true", "1", "yes")

    async def _troubleshoot_catalog(self) -> tuple[bool, str, dict]:
        """Probe the Troubleshoot feature catalog. Returns (supported, reason, raw).
        supported=False (with an explanatory reason) when the resource is absent —
        i.e. the firmware is older than 10.18."""
        try:
            data = await self._get(
                "/system/troubleshoot_feature_components", params={"depth": "3"}
            )
        except ArubaAPIError as exc:
            code = exc.status_code
            if code in (404, 501) or (code == 400 and "not found" in str(exc).lower()):
                return (
                    False,
                    "The Troubleshoot API (/system/troubleshoot_feature_components) is not "
                    f"available on {self.host} — it requires AOS-CX 10.18 or later.",
                    {},
                )
            raise
        if not isinstance(data, dict):
            return False, "Unexpected response from the Troubleshoot feature catalog.", {}
        return True, "", data

    async def list_troubleshoot_features(self, feature_name: str | None = None) -> dict:
        """List the troubleshoot features and their components supported by the
        device (source: `/system/troubleshoot_feature_components`). Each component
        reports which check types it supports: basic health, config check,
        operations. Returns supported=False on firmware older than 10.18."""
        supported, reason, catalog = await self._troubleshoot_catalog()
        if not supported:
            return {"supported": False, "reason": reason, "features": []}

        features: list[dict] = []
        for fname, fobj in self._collection_items(catalog):
            fobj = fobj if isinstance(fobj, dict) else {}
            comps_raw = fobj.get("components") if isinstance(fobj.get("components"), dict) else {}
            components = []
            for cname, cobj in comps_raw.items():
                if not isinstance(cobj, dict):
                    continue
                components.append({
                    "component": cname,
                    "description": cobj.get("description", ""),
                    "basic_health": self._str_bool(cobj.get("basic")),
                    "config_check": self._str_bool(cobj.get("config_checker")),
                    "operations": self._str_bool(cobj.get("operations")),
                })
            components.sort(key=lambda c: c["component"])
            features.append({
                "feature_name": fobj.get("feature_name", fname),
                "feature_description": fobj.get("feature_description", ""),
                "components": components,
                "component_count": len(components),
            })
        features.sort(key=lambda f: f["feature_name"])

        if feature_name:
            match = [f for f in features if f["feature_name"] == feature_name]
            if not match:
                return {
                    "supported": True,
                    "feature_name": feature_name,
                    "error": f"Unknown troubleshoot feature '{feature_name}'.",
                    "available_features": [f["feature_name"] for f in features],
                    "features": [],
                }
            return {"supported": True, "count": len(match), "features": match}

        return {"supported": True, "count": len(features), "features": features}

    def _format_troubleshoot(
        self, data: dict, feature_name: str, cookie: int, choice: str, verbose: bool
    ) -> dict:
        data = data if isinstance(data, dict) else {}

        def _alerts(key: str) -> list[dict]:
            raw = data.get(key)
            items: list[dict] = []
            if isinstance(raw, dict):
                for aid, alert in raw.items():
                    if not isinstance(alert, dict):
                        continue
                    entry = {
                        "id": aid,
                        "severity": alert.get("severity"),
                        "component": alert.get("component"),
                        "message": alert.get("message"),
                        "root_cause": alert.get("root_cause"),
                        "recommendation": alert.get("recommendation"),
                        "resource": alert.get("resource"),
                        "interfaces": alert.get("interfaces"),
                        "ports": alert.get("ports"),
                        "error_id": alert.get("error_id"),
                        "timestamp": alert.get("timestamp"),
                    }
                    items.append({k: v for k, v in entry.items() if v not in (None, "")})
            return items

        basic_alerts = _alerts("basic_health_check_alerts")
        config_alerts = _alerts("config_alerts")
        advanced_alerts = _alerts("advanced_alerts")
        all_alerts = basic_alerts + config_alerts + advanced_alerts

        sev_counts: dict[str, int] = {}
        for alert in all_alerts:
            sev = alert.get("severity") or "unknown"
            sev_counts[sev] = sev_counts.get(sev, 0) + 1

        start = data.get("start_timestamp")
        end = data.get("end_timestamp")
        duration = None
        if isinstance(start, int) and isinstance(end, int) and end >= start > 0:
            duration = end - start

        out = {
            "supported": True,
            "feature_name": data.get("feature_name", feature_name),
            "cookie": data.get("cookie", cookie),
            "choice": data.get("choice", choice),
            "component_name": data.get("component_name"),
            "troubleshoot_type": data.get("troubleshoot_type"),
            "progress": data.get("progress"),
            "result": data.get("result"),
            "start_timestamp": start,
            "end_timestamp": end,
            "duration_seconds": duration,
            "basic_health_check_alerts": basic_alerts,
            "config_alerts": config_alerts,
            "advanced_alerts": advanced_alerts,
            "health_check_results": data.get("health_check_results") or {},
            "config_status": data.get("config_status") or {},
            "tshoot_results": data.get("tshoot_results") or {},
            "summary": {
                "result": data.get("result"),
                "total_alerts": len(all_alerts),
                "alerts_by_severity": sev_counts,
            },
        }
        if verbose:
            out["verbose_logs"] = data.get("verbose_logs") or {}
            out["health_check_error_reports"] = data.get("health_check_error_reports") or {}
        return out

    async def run_troubleshoot(
        self,
        feature_name: str,
        choice: str = "health",
        component_name: str | None = None,
        user_input: str | None = None,
        verbose: bool = False,
        timeout: float = 120.0,
        poll_interval: float = 2.0,
        cleanup: bool = True,
    ) -> dict:
        """Run an on-device automated troubleshoot/diagnostic (AOS-CX 10.18+).

        Launches a volatile troubleshoot request (POST /system/troubleshoots),
        polls the instance until completion (or `timeout` seconds), parses the
        alerts and text results, then deletes the volatile instance.
        `choice` selects the run depth (basic-health/config/health/operations/
        detailed). Returns supported=False on firmware older than 10.18."""
        choice = (choice or "health").lower()
        if choice not in self._TSHOOT_CHOICES:
            raise ArubaAPIError(
                f"Invalid troubleshoot choice '{choice}'. "
                f"Valid values: {', '.join(self._TSHOOT_CHOICES)}.",
                400,
            )

        supported, reason, catalog = await self._troubleshoot_catalog()
        if not supported:
            return {"supported": False, "reason": reason}

        feat_keys = {str(k) for k, _ in self._collection_items(catalog)}
        for _, fobj in self._collection_items(catalog):
            if isinstance(fobj, dict) and fobj.get("feature_name"):
                feat_keys.add(str(fobj["feature_name"]))
        if feature_name not in feat_keys:
            return {
                "supported": True,
                "status": "invalid_input",
                "error": f"Unknown troubleshoot feature '{feature_name}'.",
                "available_features": sorted(feat_keys),
            }

        cookie = random.randint(1, 4294967295)
        body: dict[str, Any] = {
            "feature_name": feature_name,
            "cookie": cookie,
            "choice": choice,
            "troubleshoot_type": "manual",
            "persistence": "volatile",
        }
        if component_name:
            body["component_name"] = component_name
        if user_input:
            body["user_input"] = user_input
        if verbose:
            body["verbose_mode"] = True

        await self._post("/system/troubleshoots", body=body)

        key = f"{quote(str(feature_name), safe='')},{cookie}"
        path = f"/system/troubleshoots/{key}"
        deadline = time.monotonic() + max(timeout, poll_interval)
        data: dict = {}
        timed_out = True
        while time.monotonic() < deadline:
            await asyncio.sleep(poll_interval)
            try:
                data = await self._get(path, params={"depth": "2"})
            except ArubaAPIError as exc:
                if exc.status_code == 404:
                    continue  # instance not visible yet
                raise
            if not isinstance(data, dict):
                continue
            end_ts = data.get("end_timestamp")
            if data.get("result") in ("pass", "fail") or (isinstance(end_ts, int) and end_ts > 0):
                timed_out = False
                break

        out = self._format_troubleshoot(data, feature_name, cookie, choice, verbose)
        out["timed_out"] = timed_out
        if cleanup:
            try:
                await self._delete(path)
                out["cleaned_up"] = True
            except ArubaAPIError:
                out["cleaned_up"] = False
        return out

    async def get_ssh_config(self) -> dict:
        """
        SSH server configuration: global settings + per-VRF activation
        and effective source-interface per VRF.

        - Global (/system object): port, algorithms, grace time, allow-list, etc.
        - Per VRF (/system/vrfs/{vrf}): ssh_enable, ssh_server_status,
          source_interface / source_ip / effective_source_ip.
        """
        system = await self._get("/system", params={"depth": "1"})
        if not isinstance(system, dict):
            system = {}

        global_cfg = {
            "server_port": system.get("ssh_server_port", "N/A"),
            "login_grace_time": system.get("ssh_login_grace_time", "N/A"),
            "max_auth_attempts": system.get("ssh_maximum_authentication_attempts", "N/A"),
            "publickey_auth_enable": system.get("ssh_publickeyauthentication_enable"),
            "password_auth_enable": system.get("ssh_passkeyauthentication_enable"),
            "two_factor_auth_enable": system.get("ssh_twofactorauthentication_enable"),
            "server_allowlist_enable": system.get("ssh_server_allowlist_enable"),
            "server_allowlist_ips": system.get("ssh_server_allowlist_ips", {}),
        }

        vrfs = await self._get("/system/vrfs", params={"depth": "1"})
        per_vrf: list[dict] = []
        enabled_vrfs: list[str] = []
        for vrf_name, _ in self._collection_items(vrfs):
            encoded = quote(str(vrf_name), safe="")
            try:
                vrf_data = await self._get(f"/system/vrfs/{encoded}", params={"depth": "2"})
            except ArubaAPIError:
                continue
            if not isinstance(vrf_data, dict):
                continue
            ssh_enable = vrf_data.get("ssh_enable")
            source_if = self._ref_name(vrf_data.get("source_interface")) if vrf_data.get("source_interface") else None
            source_ip = vrf_data.get("source_ip") if isinstance(vrf_data.get("source_ip"), dict) else {}
            eff_src = vrf_data.get("effective_source_ip") if isinstance(vrf_data.get("effective_source_ip"), dict) else {}
            entry = {
                "vrf": vrf_name,
                "ssh_enabled": bool(ssh_enable) if ssh_enable is not None else False,
                "ssh_server_status": vrf_data.get("ssh_server_status", "N/A"),
                "source_interface": source_if or "N/A",
                "source_ip": source_ip,
                "effective_source_ip": eff_src,
            }
            per_vrf.append(entry)
            if entry["ssh_enabled"]:
                enabled_vrfs.append(str(vrf_name))

        return {
            "global": global_cfg,
            "vrfs": per_vrf,
            "ssh_enabled_vrfs": enabled_vrfs,
            "count": len(per_vrf),
        }

    async def get_hardware_health(self) -> dict:
        """Detailed hardware state: modules (chassis, management modules, line cards,
        fan trays, fabric cards…), PSU, fans, temperature sensors and LEDs,
        plus a section dedicated to management modules (active/standby, last
        boot and uptime per module — useful on redundant chassis such as 6400).

        Anti-timeout optimization: instead of a single GET /system/subsystems?depth=4
        (huge and slow payload on a chassis), we list the subsystems at depth=1
        then retrieve EACH subsystem individually at depth=3, in parallel
        (bounded concurrency). Each response stays small and the total scales with the
        number of cards without exceeding the timeout."""
        listing = await self._get("/system/subsystems", params={"depth": "1"})
        keys = [str(key) for key, _ in self._collection_items(listing)]

        sem = asyncio.Semaphore(8)  # bounds the concurrency so as not to saturate the device

        async def _fetch(key: str) -> tuple[str, Any]:
            async with sem:
                encoded = quote(key, safe="")
                try:
                    sub = await self._get(f"/system/subsystems/{encoded}", params={"depth": "3"})
                except ArubaAPIError:
                    return key, None
                return key, sub

        fetched = await asyncio.gather(*[_fetch(k) for k in keys])
        items = [(k, sub) for k, sub in fetched if isinstance(sub, dict)]

        modules: list[dict] = []
        mgmt_modules: list[dict] = []
        all_fans: list[dict] = []
        all_psus: list[dict] = []
        all_temps: list[dict] = []
        faults: list[dict] = []

        for key, sub in items:
            if not isinstance(sub, dict):
                continue
            stype, sname = _parse_subsystem_key(str(key))
            label = f"{stype} {sname}"
            product = sub.get("product_info") if isinstance(sub.get("product_info"), dict) else {}

            fans  = _extract_fans_from_sub(sub)
            psus  = _extract_psus_from_sub(sub)
            temps = _extract_temps_from_sub(sub)
            leds  = _extract_leds_from_sub(sub)

            module = {
                "type": stype,
                "name": sname,
                "product_name": product.get("product_name", "N/A"),
                "part_number": product.get("part_number", "N/A"),
                "serial_number": product.get("serial_number", "N/A"),
                "device_version": product.get("device_version", "N/A"),
                "vendor": product.get("vendor", "N/A"),
                "base_mac_address": product.get("base_mac_address", "N/A"),
                "admin_state": sub.get("admin_state", "N/A"),
                "fans": fans,
                "power_supplies": psus,
                "temp_sensors": temps,
                "leds": leds,
            }

            ru = sub.get("resource_utilization")
            if isinstance(ru, dict) and ru:
                module["resource_utilization"] = {
                    "cpu_percent": ru.get("cpu", "N/A"),
                    "memory_percent": ru.get("memory", "N/A"),
                }
            if stype == "management_module":
                module["control_plane_state"] = sub.get("control_plane_target_state", "N/A")
                # Ignore empty slots (absent VSF stack members):
                # state='empty' without serial → it is not a real supervisor.
                state = str(sub.get("state", "")).lower()
                if state != "empty" and product.get("serial_number"):
                    mgmt_modules.append(_build_mgmt_module(sname, sub, product))

            failed_reason = product.get("failed_reason")
            if failed_reason:
                module["failed_reason"] = failed_reason
                faults.append({"component": label, "issue": failed_reason})

            modules.append(module)

            for fan in fans:
                all_fans.append({"module": label, **fan})
                if _is_fault(fan.get("status")):
                    faults.append({"component": f"fan {fan.get('name')} ({label})", "status": fan.get("status")})
            for psu in psus:
                all_psus.append({"module": label, **psu})
                if _is_fault(psu.get("status")):
                    faults.append({"component": f"psu {psu.get('name')} ({label})", "status": psu.get("status")})
            for temp in temps:
                all_temps.append({"module": label, **temp})
                if _is_fault(temp.get("status")):
                    faults.append({"component": f"temp {temp.get('name')} ({label})", "status": temp.get("status")})

        # Stable sort of management modules by name (1/1 before 1/2).
        mgmt_modules.sort(key=lambda m: m.get("name", ""))

        return {
            "modules": modules,
            "management_modules": mgmt_modules,
            "fans": all_fans,
            "power_supplies": all_psus,
            "temp_sensors": all_temps,
            "faults": faults,
            "health_summary": {
                "modules_total": len(modules),
                "management_modules_total": len(mgmt_modules),
                "management_modules_active": sum(1 for m in mgmt_modules if m.get("role") == "active"),
                "fans_total": len(all_fans),
                "power_supplies_total": len(all_psus),
                "temp_sensors_total": len(all_temps),
                "faults_detected": len(faults),
                "healthy": len(faults) == 0,
            },
        }

    async def get_boot_history(self) -> dict:
        """Reboot history, per subsystem that supports it.

        The firmware stores `boot_history` only on the `management_module`
        and `line_card` subsystems (cf. the Subsystem model of the REST API):
        management module / standby = last 4 reboots, line card = last 6.
        We retrieve these subsystems individually (depth=2, which already inlines
        boot_history and reboot_statistics) and in parallel, to stay fast even
        on a chassis. Each entry is sorted from the most recent reboot to the
        oldest, with derived epoch timestamp and cause counters (reboot_statistics)."""
        listing = await self._get("/system/subsystems", params={"depth": "1"})
        # Only these types carry a boot_history → avoid querying the rest.
        keys = [
            str(key) for key, _ in self._collection_items(listing)
            if str(key).startswith(("management_module", "line_card"))
        ]

        sem = asyncio.Semaphore(8)

        async def _fetch(key: str) -> tuple[str, Any]:
            async with sem:
                encoded = quote(key, safe="")
                try:
                    sub = await self._get(f"/system/subsystems/{encoded}", params={"depth": "2"})
                except ArubaAPIError:
                    return key, None
                return key, sub

        fetched = await asyncio.gather(*[_fetch(k) for k in keys])

        subsystems: list[dict] = []
        for key, sub in fetched:
            if not isinstance(sub, dict):
                continue
            history = sub.get("boot_history")
            if not isinstance(history, dict) or not history:
                continue  # empty slot or subsystem without history
            stype, sname = _parse_subsystem_key(str(key))
            entries = _format_boot_history(history)
            entry = {
                "type": stype,
                "name": sname,
                "state": sub.get("state", "N/A"),
                "boots": entries,
                "boot_count": len(entries),
                "last_boot": entries[0] if entries else {},
                "reboot_statistics": sub.get("reboot_statistics") if isinstance(sub.get("reboot_statistics"), dict) else {},
            }
            if stype == "management_module":
                cp_state = sub.get("control_plane_target_state")
                entry["role"] = "active" if cp_state == "running_active" else "standby"
            subsystems.append(entry)

        subsystems.sort(key=lambda s: (s["type"], s["name"]))
        return {
            "subsystems": subsystems,
            "count": len(subsystems),
        }

    async def get_transceivers(self, interface_name: Optional[str] = None) -> dict:
        """Transceiver state (pluggable modules) from the pm_info /
        pm_monitor attribute of the interfaces. Returns the connector type, vendor info and
        the digital optical diagnostics (DOM) with active alarms/warnings."""
        if interface_name:
            encoded = quote(interface_name, safe="")
            data = await self._get(f"/system/interfaces/{encoded}", params={"depth": "2"})
            return {"transceivers": [_format_transceiver(interface_name, data)], "count": 1}

        data = await self._get("/system/interfaces", params={"depth": "2"})
        transceivers = []
        for name, iface in self._collection_items(data):
            if not isinstance(iface, dict):
                continue
            pm = iface.get("pm_info")
            if not isinstance(pm, dict) or not pm:
                continue  # no pluggable module present on this interface
            transceivers.append(_format_transceiver(name, iface))
        faults = [t for t in transceivers if t["status"] != "ok"]
        return {
            "transceivers": transceivers,
            "count": len(transceivers),
            "with_alarms": len(faults),
        }

    async def get_poe_status(self, interface_name: Optional[str] = None) -> dict:
        """PoE (Power over Ethernet) status: per-port power draw (Watts/current/
        voltage), powering state, powered-device type/class, plus the
        chassis-wide PoE power budget (available/drawn/reserved/redundant/
        failover power supplied by the PSUs).

        Pass `interface_name` for a single port, otherwise every PoE-capable
        port is scanned in parallel (detected via the `poe_interface` reference
        on /system/interfaces)."""
        if interface_name:
            encoded = quote(interface_name, safe="")
            try:
                data = await self._get(f"/system/interfaces/{encoded}/poe_interface", params={"depth": "2"})
            except ArubaAPIError as exc:
                if exc.status_code == 404:
                    raise ArubaAPIError(
                        f"Interface '{interface_name}' not found or not PoE-capable.", 404)
                raise
            ports = [_format_poe_interface(interface_name, data)]
        else:
            ifaces_data = await self._get("/system/interfaces", params={"depth": "2"})
            poe_capable = [name for name, raw in self._collection_items(ifaces_data)
                           if isinstance(raw, dict) and raw.get("poe_interface")]

            sem = asyncio.Semaphore(8)

            async def _fetch(name: str) -> tuple[str, Any]:
                async with sem:
                    encoded = quote(name, safe="")
                    try:
                        data = await self._get(f"/system/interfaces/{encoded}/poe_interface", params={"depth": "2"})
                    except ArubaAPIError:
                        return name, None
                    return name, data

            fetched = await asyncio.gather(*[_fetch(n) for n in poe_capable])
            ports = [_format_poe_interface(n, d) for n, d in fetched if isinstance(d, dict)]

        powered = [p for p in ports if p["powering_status"] == "delivering"]
        total_drawn_w = round(
            sum(p["power_drawn_w"] for p in powered if isinstance(p["power_drawn_w"], (int, float))), 1)

        budget = await self._get_poe_chassis_budget()

        return {
            "ports": ports,
            "count": len(ports),
            "powered_count": len(powered),
            "total_drawn_w": total_drawn_w,
            "budget": budget,
        }

    async def _get_poe_chassis_budget(self) -> dict:
        """Chassis-wide PoE power budget, aggregated across every `chassis`
        subsystem (stacks/VSF have one per member). Source: Subsystem.poe_power
        (available/drawn/reserved/redundant/failover, in Watts) and
        Subsystem.poe_power_consumed_average."""
        listing = await self._get("/system/subsystems", params={"depth": "1"})
        chassis_keys = [str(key) for key, _ in self._collection_items(listing)
                        if _parse_subsystem_key(str(key))[0] == "chassis"]

        budgets: list[dict] = []
        for key in chassis_keys:
            encoded = quote(key, safe="")
            try:
                sub = await self._get(f"/system/subsystems/{encoded}", params={"depth": "1"})
            except ArubaAPIError:
                continue
            if not isinstance(sub, dict):
                continue
            poe_power = sub.get("poe_power") if isinstance(sub.get("poe_power"), dict) else {}
            consumed_avg = sub.get("poe_power_consumed_average")
            if not poe_power and consumed_avg is None:
                continue  # this chassis has no PoE capability
            _, sname = _parse_subsystem_key(key)
            budgets.append({
                "chassis": sname,
                "available_power_w": poe_power.get("available_power", "N/A"),
                "drawn_power_w": poe_power.get("drawn_power", "N/A"),
                "reserved_power_w": poe_power.get("reserved_power", "N/A"),
                "redundant_power_w": poe_power.get("redundant_power", "N/A"),
                "failover_power_w": poe_power.get("failover_power", "N/A"),
                "consumed_average_w": consumed_avg if consumed_avg is not None else "N/A",
            })

        return {"per_chassis": budgets, "supported": len(budgets) > 0}

    # ─── Interfaces ───────────────────────────────────────────────────────────

    async def get_interfaces(self, interface_name: Optional[str] = None) -> dict:
        if interface_name:
            encoded = quote(interface_name, safe="")
            try:
                data = await self._get(f"/system/interfaces/{encoded}", params={"depth": "2"})
                return _format_interface(interface_name, data)
            except ArubaAPIError as exc:
                if exc.status_code != 404:
                    raise
                # Fallback: the interface may have a different encoding, look it up in the list
                all_data = await self._get("/system/interfaces", params={"depth": "2"})
                items = self._collection_items(all_data)
                needle = interface_name.lower().replace("/", "").replace("-", "").replace("_", "")
                for name, iface in items:
                    if name.lower().replace("/", "").replace("-", "").replace("_", "") == needle or name == interface_name:
                        return _format_interface(name, iface)
                available = [n for n, _ in items]
                raise ArubaAPIError(
                    f"Interface '{interface_name}' not found. "
                    f"Available: {', '.join(available[:20])}"
                    + (" …" if len(available) > 20 else ""), 404)
        else:
            data = await self._get("/system/interfaces", params={"depth": "2"})
            items = self._collection_items(data)
            return {
                "interfaces": [_format_interface(name, iface) for name, iface in items],
                "count": len(items),
            }

    async def get_interface_counters(self, interface_name: Optional[str] = None) -> dict:
        """Traffic counters (statistics) of the interfaces: rx/tx bytes & packets,
        error counters (CRC, frame, runts, giants), drops and aggregate totals.

        Pulled from the AOS-CX Interface `statistics` object (depth=2). Pass
        `interface_name` for a single port, otherwise all interfaces are returned.
        Counters that the device does not report are omitted; `counters_available`
        is False when an interface exposes no statistics at all."""
        if interface_name:
            encoded = quote(interface_name, safe="")
            try:
                data = await self._get(f"/system/interfaces/{encoded}", params={"depth": "2"})
                return _format_interface_counters(interface_name, data)
            except ArubaAPIError as exc:
                if exc.status_code != 404:
                    raise
                all_data = await self._get("/system/interfaces", params={"depth": "2"})
                items = self._collection_items(all_data)
                needle = interface_name.lower().replace("/", "").replace("-", "").replace("_", "")
                for name, iface in items:
                    if name.lower().replace("/", "").replace("-", "").replace("_", "") == needle or name == interface_name:
                        return _format_interface_counters(name, iface)
                available = [n for n, _ in items]
                raise ArubaAPIError(
                    f"Interface '{interface_name}' not found. "
                    f"Available: {', '.join(available[:20])}"
                    + (" …" if len(available) > 20 else ""), 404)

        data = await self._get("/system/interfaces", params={"depth": "2"})
        items = self._collection_items(data)
        counters = [_format_interface_counters(name, iface) for name, iface in items]
        return {
            "interfaces": counters,
            "count": len(counters),
            "without_counters": sum(1 for c in counters if not c["counters_available"]),
        }

    async def get_supported_transceivers(self, search: Optional[str] = None) -> dict:
        """Catalog of transceivers (SFP/QSFP/DAC ...) supported by this device.

        Reads the device-wide `/system/supported_transceivers` collection — the
        REST equivalent of `show supported-transceivers`. Each entry has a
        product_number and a short description (e.g. '10G-DAC0.65'). `search`
        filters case-insensitively on the product number or description.
        """
        data = await self._get("/system/supported_transceivers", params={"depth": "2"})
        needle = search.lower().strip() if search else None
        transceivers: list[dict] = []
        for key, entry in self._collection_items(data):
            entry = entry if isinstance(entry, dict) else {}
            product = entry.get("product_number") or key
            description = entry.get("description", "")
            long_description = entry.get("long_description", "")
            if needle and needle not in str(product).lower() \
                    and needle not in str(description).lower() \
                    and needle not in str(long_description).lower():
                continue
            transceivers.append({
                "product_number": product,
                "description": description,
                "long_description": long_description,
            })
        transceivers.sort(key=lambda t: str(t["product_number"]))
        result = {
            "transceivers": transceivers,
            "count": len(transceivers),
        }
        if needle:
            result["search"] = search
        return result

    async def _filtered_interfaces(self, predicate) -> list[tuple[str, dict]]:
        """Fetch all interfaces (depth=2) and return the (name, raw) pairs that
        match `predicate(name, raw)`."""
        data = await self._get("/system/interfaces", params={"depth": "2"})
        items = self._collection_items(data)
        return [(name, iface) for name, iface in items
                if isinstance(iface, dict) and predicate(name, iface)]

    async def get_loopbacks(self) -> dict:
        """Loopback interfaces (type 'loopback'), e.g. loopback0/1 used as
        router-id / VTEP source."""
        matched = await self._filtered_interfaces(
            lambda name, raw: (raw.get("type") == "loopback")
            or str(name).lower().startswith("loopback")
        )
        return {
            "interfaces": [_format_interface(name, iface) for name, iface in matched],
            "count": len(matched),
        }

    async def get_routed_ports(self) -> dict:
        """Routed (L3) ports: physical/LAG/sub-interfaces with `routing` enabled
        (excludes switched L2 ports, VLAN SVIs, loopbacks and overlay types)."""
        excluded = {"vlan", "loopback", "vxlan", "internal", "mgmt", "management"}

        def is_routed(name: str, raw: dict) -> bool:
            if raw.get("routing") is not True:
                return False
            return str(raw.get("type") or "").lower() not in excluded

        matched = await self._filtered_interfaces(is_routed)
        return {
            "interfaces": [_format_interface(name, iface) for name, iface in matched],
            "count": len(matched),
        }

    async def get_vlan_interfaces(self) -> dict:
        """VLAN interfaces / SVIs (type 'vlan'), e.g. vlan100 — L3 gateways for a
        VLAN. Returns the SVI list with VRF and IP addresses."""
        matched = await self._filtered_interfaces(
            lambda name, raw: (raw.get("type") == "vlan")
            or str(name).lower().startswith("vlan")
        )
        return {
            "interfaces": [_format_interface(name, iface) for name, iface in matched],
            "count": len(matched),
        }

    # ─── LAG / LACP ──────────────────────────────────────────────────────────

    async def get_lag(self, lag_name: Optional[str] = None) -> dict:
        """Link Aggregation Groups (LAGs / port-channels) with their members.

        Covers BOTH static LAGs and LACP-negotiated LAGs. For each LAG returns
        the bond mode (static / lacp-active / lacp-passive), the aggregate speed
        and state, and per-member LACP actor/partner state parsed into flags so a
        degraded member (not synchronized / not collecting-distributing) stands
        out. A single depth=2 fetch of all interfaces is reused for the members,
        so no extra round-trips are made.

        `lag_name` optional (e.g. 'lag256' or '256') — omit for all LAGs.
        """
        data = await self._get("/system/interfaces", params={"depth": "2"})
        items = self._collection_items(data)
        by_name = {name: raw for name, raw in items if isinstance(raw, dict)}

        def _is_lag(name: str, raw: dict) -> bool:
            return str(raw.get("type")) == "lag" or str(name).lower().startswith("lag")

        lags = [(n, r) for n, r in items if isinstance(r, dict) and _is_lag(n, r)]

        if lag_name:
            needle = str(lag_name).lower().replace("lag", "").strip()
            selected = [
                (n, r) for n, r in lags
                if n.lower() == str(lag_name).lower()
                or n.lower().replace("lag", "") == needle
            ]
            if not selected:
                available = [n for n, _ in lags]
                raise ArubaAPIError(
                    f"LAG '{lag_name}' not found. "
                    f"Available: {', '.join(available) or 'none'}", 404)
            lags = selected

        formatted = [_format_lag(name, raw, by_name) for name, raw in lags]
        return {"lags": formatted, "count": len(formatted)}

    # ─── VLANs ───────────────────────────────────────────────────────────────

    async def get_vlans(self, vlan_id: Optional[int] = None) -> dict:
        if vlan_id:
            data = await self._get(f"/system/vlans/{vlan_id}", params={"depth": "2"})
            return _format_vlan(vlan_id, data)
        else:
            data = await self._get("/system/vlans", params={"depth": "2"})
            return {
                "vlans": [_format_vlan(vid, v) for vid, v in self._collection_items(data)],
                "count": len(self._collection_items(data)),
            }

    # ─── LLDP ────────────────────────────────────────────────────────────────

    @staticmethod
    def _split_csv(value: Any) -> list[str]:
        """Split an AOS-CX comma-separated list field (e.g. mgmt_ip_list,
        vlan_id_list) into a clean list. Returns [] for empty/missing values."""
        if not isinstance(value, str) or not value.strip():
            return []
        return [item.strip() for item in value.split(",") if item.strip()]

    def _format_lldp_neighbor(self, local_interface: str, lldp_data: dict) -> dict:
        """Normalize an LLDP_Neighbor resource.

        The neighbor's identity (system name, description, management IPs, remote
        port, VLANs, capabilities…) lives in the nested `neighbor_info` object;
        only chassis_id / port_id / mac_addr / selfseen sit at the top level.
        """
        info = lldp_data.get("neighbor_info") if isinstance(lldp_data.get("neighbor_info"), dict) else {}

        mgmt_ips = self._split_csv(info.get("mgmt_ip_list"))
        vlan_ids = self._split_csv(info.get("vlan_id_list"))
        vlan_names = self._split_csv(info.get("vlan_name_list"))

        return {
            "local_interface": local_interface,
            # Neighbor identity (from neighbor_info.chassis_*)
            "neighbor_system_name": info.get("chassis_name", "N/A"),
            "neighbor_system_description": info.get("chassis_description", "N/A"),
            "neighbor_chassis_id": info.get("chassis_id", lldp_data.get("chassis_id", "N/A")),
            "neighbor_chassis_id_subtype": info.get("chassis_id_subtype", "N/A"),
            "neighbor_mac_address": lldp_data.get("mac_addr", "N/A"),
            # Remote port (from neighbor_info.port_*)
            "neighbor_port_id": info.get("port_id", lldp_data.get("port_id", "N/A")),
            "neighbor_port_id_subtype": info.get("port_id_subtype", "N/A"),
            "neighbor_port_description": info.get("port_description", "N/A"),
            "neighbor_port_pvid": info.get("port_pvid", "N/A"),
            # Management & capabilities
            "neighbor_mgmt_addresses": mgmt_ips,
            "neighbor_mgmt_address": mgmt_ips[0] if mgmt_ips else "N/A",
            "neighbor_capabilities_available": info.get("chassis_capability_available", "N/A"),
            "neighbor_capabilities_enabled": info.get("chassis_capability_enabled", "N/A"),
            "neighbor_med_device_class": info.get("med_device_class", "N/A"),
            # VLANs advertised by the neighbor
            "neighbor_vlan_ids": vlan_ids,
            "neighbor_vlan_names": vlan_names,
            # Misc
            "neighbor_ttl": info.get("chassis_ttl", "N/A"),
            "self_loop": lldp_data.get("selfseen", False),
        }

    async def get_lldp_neighbors(self) -> dict:
        neighbors = []
        data = await self._get("/system/interfaces", params={"depth": "1"})
        for iface_name, _ in self._collection_items(data):
            encoded = quote(str(iface_name), safe="")
            try:
                lldp = await self._get(f"/system/interfaces/{encoded}/lldp_neighbors", params={"depth": "2"})
            except ArubaAPIError:
                continue
            for _, lldp_data in self._collection_items(lldp):
                if not isinstance(lldp_data, dict):
                    continue
                neighbors.append(self._format_lldp_neighbor(str(iface_name), lldp_data))
        return {"lldp_neighbors": neighbors, "count": len(neighbors)}

    # ─── Routing ─────────────────────────────────────────────────────────────

    async def get_routing_table(self, vrf: str = "default") -> dict:
        """
        Full routing table (equivalent to 'show ip route [vrf ...]').

        - vrf="default" (or a specific name): routes of that VRF.
        - vrf="all": routes of all VRFs, grouped by VRF.

        Each route exposes: prefix, origin protocol ('from': connected,
        local, static, ospf, bgp…), sub-type (e.g. ospf_intra_area, evpn),
        administrative distance, metric, 'selected' state, forwarding type and
        the list of resolved nexthops (ip + interface).

        Routes are also broken down by VRF and by protocol.
        """
        # Source: /system/vrfs/{vrf}/routes (depth=2 → 'from'/distance/metric/
        # sub_protocol_type present, nexthops as ID references).
        # Nexthops are global resources: we retrieve the table once
        # to resolve id → {ip_address, interface}.
        nexthop_map = await self._get_nexthop_map()

        if vrf == "all":
            vrfs_raw = await self._get("/system/vrfs", params={"depth": "1"})
            vrf_names = [name for name, _ in self._collection_items(vrfs_raw)]
        else:
            vrf_names = [vrf]

        all_routes: list[dict] = []
        by_vrf: dict[str, int] = {}
        by_protocol: dict[str, int] = {}
        by_vrf_protocol: dict[str, dict[str, int]] = {}

        for vrf_name in vrf_names:
            encoded = quote(str(vrf_name), safe="")
            try:
                data = await self._get(f"/system/vrfs/{encoded}/routes", params={"depth": "2"})
            except ArubaAPIError:
                continue
            for prefix, route in self._collection_items(data):
                if not isinstance(route, dict):
                    continue
                protocol = route.get("from", route.get("protocol", "N/A"))
                nexthops = self._resolve_nexthops(route.get("nexthops"), nexthop_map)
                route_entry = {
                    "prefix": prefix,
                    "vrf": vrf_name,
                    "protocol": protocol,
                    "sub_protocol_type": route.get("sub_protocol_type") or "",
                    "address_family": route.get("address_family", "ipv4"),
                    "distance": route.get("distance", "N/A"),
                    "metric": route.get("metric", "N/A"),
                    "type": route.get("type", "N/A"),
                    "selected": route.get("selected", None),
                    "nexthops": nexthops,
                    "next_hop": nexthops[0]["ip_address"] if nexthops else "N/A",
                    "via_interface": nexthops[0]["interface"] if nexthops else "N/A",
                }
                all_routes.append(route_entry)
                by_vrf[vrf_name] = by_vrf.get(vrf_name, 0) + 1
                by_protocol[protocol] = by_protocol.get(protocol, 0) + 1
                by_vrf_protocol.setdefault(vrf_name, {})
                by_vrf_protocol[vrf_name][protocol] = by_vrf_protocol[vrf_name].get(protocol, 0) + 1

        result: dict = {
            "routes": all_routes,
            "count": len(all_routes),
            "by_vrf": by_vrf,
            "by_protocol": by_protocol,
            "by_vrf_protocol": by_vrf_protocol,
        }
        # Compatibility: keep a 'vrf' field when a single VRF is requested.
        if vrf != "all":
            result["vrf"] = vrf
        return result

    async def _get_nexthop_map(self) -> dict[str, dict]:
        """Global nexthop table (id → {ip_address, interface}) to resolve
        the references carried by the routes."""
        try:
            data = await self._get("/system/nexthops", params={"depth": "2"})
        except ArubaAPIError:
            return {}
        nexthop_map: dict[str, dict] = {}
        for nh_id, nh in self._collection_items(data):
            if not isinstance(nh, dict):
                continue
            nexthop_map[str(nh_id)] = {
                "ip_address": nh.get("ip_address") or "",
                "interface": self._ref_name(nh.get("port")) or "N/A",
                "weight": nh.get("weight", 0),
            }
        return nexthop_map

    def _resolve_nexthops(self, nexthops: Any, nexthop_map: dict[str, dict]) -> list[dict]:
        """Resolve a route's nexthops (dict {id: ref} or list of refs) by
        relying on the global nexthop table."""
        resolved: list[dict] = []
        items = self._collection_items(nexthops) if nexthops else []
        for nh_key, nh_val in items:
            entry: Optional[dict] = None
            # nh_val may already be a dict (high depth) with ip_address/port
            if isinstance(nh_val, dict) and (nh_val.get("ip_address") or nh_val.get("port")):
                entry = {
                    "ip_address": nh_val.get("ip_address") or "",
                    "interface": self._ref_name(nh_val.get("port")) or "N/A",
                    "weight": nh_val.get("weight", 0),
                }
            else:
                # Otherwise, nh_key (or the end of the URI) is the id to resolve
                nh_id = nh_key
                if isinstance(nh_val, str) and nh_val:
                    nh_id = nh_val.rstrip("/").split("/")[-1]
                entry = nexthop_map.get(str(nh_id))
            if entry and (entry.get("ip_address") or entry.get("interface") not in (None, "N/A")):
                resolved.append(entry)
        return resolved


    # ─── MAC table ───────────────────────────────────────────────────────────

    async def get_mac_table(self, vlan_id: Optional[int] = None) -> dict:
        entries = []
        data = await self._get("/system/vlans", params={"depth": "1"})
        for vid, _ in self._collection_items(data):
            if vlan_id and int(vid) != vlan_id:
                continue
            try:
                macs = await self._get(f"/system/vlans/{vid}/macs", params={"depth": "2"})
            except ArubaAPIError:
                continue
            for mac, mac_data in self._collection_items(macs):
                if not isinstance(mac_data, dict):
                    continue
                entries.append({
                    "mac_address": mac_data.get("mac_address", mac),
                    "vlan": int(vid),
                    "port": mac_data.get("port", mac_data.get("interface", "N/A")),
                    "type": mac_data.get("mac_type", mac_data.get("type", "N/A")),
                })
        return {"mac_table": entries, "count": len(entries)}

    # ─── ARP table ───────────────────────────────────────────────────────────

    async def get_arp_table(self, vrf: str = "default") -> dict:
        data = await self._get(
            f"/system/vrfs/{vrf}/neighbors",
            params={"depth": "2"},
        )
        entries = []
        for key, neighbor in self._collection_items(data):
            if not isinstance(neighbor, dict):
                continue
            entries.append({
                "ip_address": neighbor.get("ip_address", neighbor.get("ip", key)),
                "mac_address": neighbor.get("mac_address", neighbor.get("mac", "N/A")),
                "port": _uri_tail(neighbor.get("port"), default="N/A"),
                "state": neighbor.get("state", neighbor.get("neighbor_state", "N/A")),
                "vrf": vrf,
            })
        return {"arp_table": entries, "count": len(entries)}

    # ─── Logs ────────────────────────────────────────────────────────────────

    async def get_logs(self, limit: int = 50, priority: Optional[str] = None) -> dict:
        params: dict = {"limit": min(limit, 1000)}
        if priority:
            params["priority"] = priority
        data = await self._get("/logs/event", params=params)
        logs = data if isinstance(data, list) else (data.get("result") or data.get("items") or []) if isinstance(data, dict) else []
        return {"logs": logs, "count": len(logs)}

    # ─── Spanning Tree ───────────────────────────────────────────────────────

    async def get_spanning_tree(self) -> dict:
        data = await self._get("/system/stp_instances", params={"depth": "3"})
        instances = []
        for name, stp in self._collection_items(data):
            if isinstance(stp, dict):
                instances.append({"name": name, **stp})
        return {"stp_instances": instances, "count": len(instances)}

    # ─── BGP ─────────────────────────────────────────────────────────────────

    async def get_bgp_neighbors(self, vrf: str = "default") -> dict:
        neighbors = []
        peer_groups = []
        data = await self._get(f"/system/vrfs/{vrf}/bgp_routers", params={"depth": "2"})

        # prefix_statistics is only populated starting with API v10.18. On
        # earlier versions, we count routes from bgp_routes.
        use_prefix_statistics = self._api_version_tuple() >= (10, 18)

        # Route count per peer from bgp_routes (used as a fallback when
        # prefix_statistics is not available / not populated by the firmware)
        routes_by_peer: dict[str, int] = {}
        if not use_prefix_statistics:
            try:
                bgp_routes_raw = await self._get(
                    f"/system/vrfs/{vrf}/bgp_routes", params={"depth": "2"}
                )
            except ArubaAPIError:
                bgp_routes_raw = {}
            if isinstance(bgp_routes_raw, dict):
                for _, route in self._collection_items(bgp_routes_raw):
                    if not isinstance(route, dict):
                        continue
                    peer = route.get("peer", "")
                    if peer and peer != "0.0.0.0":
                        routes_by_peer[peer] = routes_by_peer.get(peer, 0) + 1

        for asn, router in self._collection_items(data):
            if not isinstance(router, dict):
                continue
            try:
                peers = await self._get(
                    f"/system/vrfs/{vrf}/bgp_routers/{asn}/bgp_neighbors",
                    params={"depth": "2"},
                )
            except ArubaAPIError:
                peers = router.get("bgp_neighbors", {})
            for peer_name, peer in self._collection_items(peers):
                if not isinstance(peer, dict):
                    continue
                status = peer.get("status", {}) if isinstance(peer.get("status"), dict) else {}
                statistics = peer.get("statistics", {}) if isinstance(peer.get("statistics"), dict) else {}
                peer_ip = peer.get("ip_or_ifname_or_group_name", peer_name)

                # An entry can be a peer-group (is_peer_group=True) rather
                # than an individual neighbor. We classify it separately instead of ignoring it,
                # in order to expose the peer-group definition without loading the whole config.
                if peer.get("is_peer_group"):
                    peer_groups.append({
                        "name": peer_ip,
                        "remote_as": peer.get("remote_as", "N/A"),
                        "description": peer.get("description", ""),
                        "update_source": self._ref_name(peer.get("update_source")) if peer.get("update_source") else "N/A",
                        "members": [],   # filled in after the loop
                        "local_as": asn,
                        "vrf": vrf,
                    })
                    continue

                # Possible attachment to a peer-group (reference {name: uri})
                peer_group_name = self._ref_name(peer.get("bgp_peer_group")) if peer.get("bgp_peer_group") else None
                if use_prefix_statistics:
                    # API v10.18+: use prefix_statistics directly
                    prefixes_received = _sum_bgp_prefix_stat(peer, "received_prefixes")
                    prefixes_sent = _sum_bgp_prefix_stat(peer, "sent_prefixes")
                    prefixes_accepted = _sum_bgp_prefix_stat(peer, "accepted_prefixes")
                    prefixes_active = _sum_bgp_prefix_stat(peer, "active_prefixes")
                else:
                    # API < v10.18: count from bgp_routes
                    prefixes_received = routes_by_peer.get(peer_ip, 0)
                    prefixes_sent = _sum_bgp_prefix_stat(peer, "sent_prefixes")
                    prefixes_accepted = prefixes_received
                    prefixes_active = prefixes_received
                neighbors.append({
                    "peer_ip": peer_ip,
                    "remote_as": peer.get("remote_as", "N/A"),
                    "received_remote_as": peer.get("received_remote_as", "N/A"),
                    "peer_group": peer_group_name or "N/A",
                    "is_peer_group": False,
                    "state": status.get("bgp_peer_state", "N/A"),
                    "uptime": statistics.get("bgp_peer_uptime", "N/A"),
                    "prefixes_received": prefixes_received,
                    "prefixes_sent": prefixes_sent,
                    "prefixes_accepted": prefixes_accepted,
                    "prefixes_active": prefixes_active,
                    "peer_router_id": peer.get("peer_rtrid", "N/A"),
                    "description": peer.get("description", ""),
                    "origin": peer.get("origin", "N/A"),
                    "negotiated_holdtime": peer.get("negotiated_holdtime", "N/A"),
                    "negotiated_keepalive": peer.get("negotiated_keepalive", "N/A"),
                    "capabilities_received": peer.get("capabilites_recevied", peer.get("capabilities_received", [])),
                    "capabilities_sent": peer.get("capabilites_sent", peer.get("capabilities_sent", [])),
                    "last_error_received": {
                        "code": status.get("bgp_rcvd_err_code", "N/A"),
                        "sub_code": status.get("bgp_rcvd_err_sub_code", "N/A"),
                    },
                    "last_error_sent": {
                        "code": status.get("bgp_sent_err_code", "N/A"),
                        "sub_code": status.get("bgp_sent_err_sub_code", "N/A"),
                    },
                    "local_as": asn,
                    "vrf": vrf,
                })

        # Fill in the members of each peer-group from the attached neighbors.
        for pg in peer_groups:
            pg["members"] = sorted(
                n["peer_ip"] for n in neighbors if n["peer_group"] == pg["name"]
            )
            pg["member_count"] = len(pg["members"])

        return {
            "bgp_neighbors": neighbors,
            "count": len(neighbors),
            "peer_groups": peer_groups,
            "peer_groups_count": len(peer_groups),
        }

    async def get_bgp_config(self, vrf: str = "default") -> dict:
        """BGP configuration: ASN, router-id, address-families, redistribute."""
        data = await self._get(f"/system/vrfs/{vrf}/bgp_routers", params={"depth": "5"})
        routers = []
        for asn, router in self._collection_items(data):
            if not isinstance(router, dict):
                continue
            routers.append({
                "asn": router.get("asn", asn),
                "router_id": router.get("router_id", "N/A"),
                "selected_router_id": (router.get("status") or {}).get("bgp_selected_router_id", "N/A"),
                "cluster_id": router.get("cluster_id", "N/A"),
                "confederation_id": router.get("confederation_id", "N/A"),
                "confederation_peers": router.get("confederation_peers", []),
                "local_pref": router.get("local_pref", "N/A"),
                "timers": router.get("timers", {}),
                "update_group_enable": router.get("update_group_enable", False),
                "neighbor_count": len(router.get("bgp_neighbors", {})) if isinstance(router.get("bgp_neighbors"), dict) else 0,
                "redistribute": list((router.get("redistribute") or {}).keys()) if isinstance(router.get("redistribute"), dict) else list(router.get("redistribute", [])),
                "networks": list((router.get("networks") or {}).keys()) if isinstance(router.get("networks"), dict) else list(router.get("networks", [])),
                "aggregate_addresses": list((router.get("aggregate_addresses") or {}).keys()) if isinstance(router.get("aggregate_addresses"), dict) else list(router.get("aggregate_addresses", [])),
            })
        return {"vrf": vrf, "bgp_routers": routers, "count": len(routers)}

    async def get_bgp_routes(self, vrf: str = "default", address_family: str = "ipv4-unicast") -> dict:
        """BGP RIB routes per VRF and address-family."""
        data = await self._get(f"/system/vrfs/{vrf}/bgp_routes", params={"depth": "2"})
        af_map = {
            "ipv4-unicast": ("ipv4", "unicast"),
            "ipv6-unicast": ("ipv6", "unicast"),
            "l2vpn-evpn": ("l2vpn", "evpn"),
            "vpnv4": ("vpnv4", None),
        }
        address_family_name, sub_address_family = af_map.get(address_family, (address_family, None))
        routes = []
        for route_key, route_data in self._collection_items(data):
            if not isinstance(route_data, dict):
                continue
            if route_data.get("address_family") != address_family_name:
                continue
            if sub_address_family and route_data.get("sub_address_family") != sub_address_family:
                continue
            path_attributes = route_data.get("path_attributes", {}) if isinstance(route_data.get("path_attributes"), dict) else {}
            flags = route_data.get("flags") or []
            routes.append({
                "prefix": route_data.get("prefix", route_key),
                "next_hop": route_data.get("nexthop", "N/A"),
                "as_path": path_attributes.get("bgp_as_path", "N/A"),
                "local_pref": path_attributes.get("bgp_loc_pref", "N/A"),
                "med": route_data.get("metric", "N/A"),
                "origin": path_attributes.get("bgp_origin", "N/A"),
                "best": "SELECTED" in flags or "selected" in str(path_attributes.get("bgp_flags", "")).lower(),
                "peer": route_data.get("peer", "N/A"),
                "vni": route_data.get("vni", "N/A"),
                "path_id": route_data.get("path_id", "N/A"),
                "address_family": route_data.get("address_family", "N/A"),
                "sub_address_family": route_data.get("sub_address_family", "N/A"),
            })
        return {"vrf": vrf, "address_family": address_family, "routes": routes, "count": len(routes)}

    @staticmethod
    def _format_bgp_route_entry(route_key, route_data: dict) -> dict:
        """Normalize one BGP_Route record into advertised/received-friendly fields,
        surfacing the BGP path attributes (AS-path / origin / local-pref / flags)."""
        pa = route_data.get("path_attributes") if isinstance(route_data.get("path_attributes"), dict) else {}
        flags = route_data.get("flags") or []
        return {
            "prefix": route_data.get("prefix", route_key),
            "peer": route_data.get("peer") or "",
            "nexthop": route_data.get("nexthop") or route_data.get("nexthop_link_local") or "N/A",
            "path_attributes_available": bool(pa),
            "as_path": pa.get("bgp_as_path", "N/A"),
            "origin": pa.get("bgp_origin", "N/A"),
            "local_pref": pa.get("bgp_loc_pref", "N/A"),
            "med": route_data.get("metric", "N/A"),
            "distance": route_data.get("distance", "N/A"),
            "flags": flags,
            "best": "SELECTED" in flags,
            "valid": "VALID" in flags,
            "advertised": bool(route_data.get("prefix_advertised")),
            "accepted": bool(route_data.get("prefix_accepted")),
            "rejected": bool(route_data.get("prefix_rejected")),
            "ibgp": bool(route_data.get("protocol_iBGP")),
            "self_originated": bool(route_data.get("protocol_internal")),
            "community": route_data.get("community", ""),
            "ext_community": route_data.get("ecommunity", ""),
            "path_id": route_data.get("path_id", 0),
            "vni": route_data.get("vni", -1),
            "address_family": route_data.get("address_family", "N/A"),
            "sub_address_family": route_data.get("sub_address_family", "N/A"),
        }

    async def get_bgp_neighbor_routes(self, vrf: str = "default", neighbor: str = None,
                                      address_family: str = "ipv4-unicast",
                                      direction: str = "all") -> dict:
        """BGP advertised / received routes per neighbor, with path attributes.

        Source: GET /system/vrfs/{vrf}/bgp_routes (depth=2). Each BGP_Route record
        carries `peer` (origin neighbor), `prefix_advertised` (advertised to
        neighbors), `prefix_accepted` / `prefix_rejected` (received-route
        disposition) and `path_attributes` (AS-path, origin, local-pref, MED,
        flags). This single RIB collection backs the CLI views
        `show bgp <af> neighbors <ip> advertised-routes` and `... received-routes`.

        Args:
            vrf: routing VRF (default "default").
            neighbor: filter to a single peer IP; None = all peers.
            address_family: ipv4-unicast | ipv6-unicast | l2vpn-evpn | vpnv4.
            direction: advertised | received | all (default).
        """
        direction = (direction or "all").lower()
        if direction not in ("advertised", "received", "all"):
            raise ArubaAPIError(
                f"Invalid direction '{direction}' — use advertised | received | all.", 400)
        af_map = {
            "ipv4-unicast": ("ipv4", "unicast"),
            "ipv6-unicast": ("ipv6", "unicast"),
            "l2vpn-evpn": ("l2vpn", "evpn"),
            "vpnv4": ("vpnv4", None),
        }
        af_name, sub_af = af_map.get(address_family, (address_family, None))
        data = await self._get(f"/system/vrfs/{vrf}/bgp_routes", params={"depth": "2"})
        advertised: list[dict] = []
        received: list[dict] = []
        matched = 0
        with_path_attrs = 0
        for route_key, route_data in self._collection_items(data):
            if not isinstance(route_data, dict):
                continue
            if route_data.get("address_family") != af_name:
                continue
            if sub_af and route_data.get("sub_address_family") != sub_af:
                continue
            entry = self._format_bgp_route_entry(route_key, route_data)
            matched += 1
            if entry["path_attributes_available"]:
                with_path_attrs += 1
            peer = entry["peer"]
            if neighbor is not None and peer != neighbor:
                # advertised routes may be self-originated (empty peer): keep them
                # only when no specific neighbor is requested.
                if not (direction in ("advertised", "all") and entry["advertised"] and not peer):
                    continue
            if direction in ("advertised", "all") and entry["advertised"]:
                advertised.append(entry)
            if direction in ("received", "all") and peer:
                received.append(entry)
        result = {
            "vrf": vrf,
            "address_family": address_family,
            "neighbor": neighbor or "all",
            "direction": direction,
        }
        if direction in ("advertised", "all"):
            result["advertised"] = advertised
            result["advertised_count"] = len(advertised)
        if direction in ("received", "all"):
            result["received"] = received
            result["received_count"] = len(received)
            result["accepted_count"] = sum(1 for r in received if r["accepted"])
            result["rejected_count"] = sum(1 for r in received if r["rejected"])

        # Surface firmware limitations so the agent can relay them to the user:
        # on some AOS-CX versions (observed on v10.17) the bgp_routes collection
        # returns route identity (prefix/peer/nexthop) but leaves path_attributes
        # and the advertised/accepted/rejected dispositions empty. Without this
        # signal an empty as_path / advertised_count=0 looks like "no data"
        # instead of "not exposed by this firmware".
        warnings: list[str] = []
        if matched > 0 and with_path_attrs == 0:
            warnings.append(
                f"BGP path attributes (AS-path, origin, local-pref, flags) are not "
                f"available from this device (REST API {self.api_version}): "
                f"{matched} route(s) matched but path_attributes is empty for all of "
                f"them, so as_path/origin/local_pref are reported as 'N/A'. The "
                f"bgp_routes collection on this firmware/address-family does not "
                f"inline path attributes; use the device CLI "
                f"(show bgp <af> neighbors <ip> routes detail) if you need them.")
        if direction in ("advertised", "all") and matched > 0 and not advertised:
            warnings.append(
                "No route is flagged 'prefix_advertised' by this firmware; the "
                "advertised-routes view is not populated via REST here "
                "(advertised_count=0 does not necessarily mean nothing is "
                "advertised — query the device CLI to confirm).")
        if warnings:
            result["warnings"] = warnings
        return result

    async def get_evpn_routes(self, vrf: str = "default", route_type: int = None) -> dict:
        """EVPN routes from the BGP RIB l2vpn-evpn, decoded by Route Type."""
        data = await self._get(f"/system/vrfs/{vrf}/bgp_routes", params={"depth": "2"})
        routes: list[dict] = []
        for prefix, route_data in self._collection_items(data):
            if not isinstance(route_data, dict):
                continue
            if route_data.get("address_family") != "l2vpn" or route_data.get("sub_address_family") != "evpn":
                continue
            parsed = _parse_evpn_route(prefix, route_data)
            if route_type is not None and parsed.get("route_type") != route_type:
                continue
            routes.append(parsed)

        # Counters per type
        by_type: dict[int, int] = {}
        for r in routes:
            rt = r.get("route_type", 0)
            by_type[rt] = by_type.get(rt, 0) + 1

        return {
            "vrf": vrf,
            "routes": routes,
            "count": len(routes),
            "by_route_type": by_type,
        }

    # ─── OSPF ────────────────────────────────────────────────────────────────

    async def get_ospf_overview(self, vrf: str = "default") -> dict:
        """OSPF configuration: router-id, areas, interfaces, redistribute."""
        data = await self._get(f"/system/vrfs/{vrf}/ospf_routers", params={"depth": "5"})
        if not isinstance(data, dict):
            return {"vrf": vrf, "ospf_routers": [], "count": 0}
        routers = []
        for instance_id, router in self._collection_items(data):
            if not isinstance(router, dict):
                continue
            areas = []
            for area_id, area_data in self._collection_items(router.get("areas") or {}):
                if not isinstance(area_data, dict):
                    continue
                ifaces_raw = area_data.get("ospf_interfaces") or {}
                area_ifaces = [iface_name for iface_name, _ in self._collection_items(ifaces_raw)]
                areas.append({
                    "area_id": area_id,
                    "type": area_data.get("area_type", "normal"),
                    "interfaces": area_ifaces,
                    "interface_count": len(area_ifaces),
                })
            redistribute_raw = router.get("redistribute") or {}
            redistribute = list(redistribute_raw.keys()) if isinstance(redistribute_raw, dict) else list(redistribute_raw)
            routers.append({
                "instance": instance_id,
                "router_id": router.get("admin_router_id", router.get("active_router_id", "N/A")),
                "reference_bandwidth": router.get("auto_cost_ref_bw", "N/A"),
                "admin_state": "disabled" if router.get("protocol_disable") else "enabled",
                "passive_interface_default": router.get("passive_interface_default", False),
                "areas": areas,
                "redistribute": redistribute,
            })
        return {"vrf": vrf, "ospf_routers": routers, "count": len(routers)}

    async def get_ospf_neighbors(self, vrf: str = "default") -> dict:
        """OSPF neighbors and their state.

        Strategy:
          1. GET /ospf_routers depth=1 → instances
          2. GET .../areas depth=1 → areas
          3. GET .../ospf_interfaces depth=1 → list of interface names
          4. Parallel calls (asyncio.gather) to .../ospf_neighbors per interface
        """
        async def _fetch_neighbors(instance_id: str, area_id: str, iface_key: str) -> list[dict]:
            encoded_area = quote(str(area_id), safe="")
            encoded_iface = quote(str(iface_key), safe="")
            try:
                data = await asyncio.wait_for(
                    self._get(
                        f"/system/vrfs/{vrf}/ospf_routers/{instance_id}/areas/{encoded_area}"
                        f"/ospf_interfaces/{encoded_iface}/ospf_neighbors",
                        params={"depth": "2"},
                    ),
                    timeout=10,
                )
            except (ArubaAPIError, asyncio.TimeoutError):
                return []
            result = []
            for nbr_id, nbr in self._collection_items(data):
                if not isinstance(nbr, dict):
                    continue
                result.append({
                    "neighbor_id": nbr_id,
                    "address": nbr.get("nbr_if_addr", nbr.get("nbr_address", "N/A")),
                    "state": nbr.get("nfsm_state", "N/A"),
                    "dr": nbr.get("dr", "N/A"),
                    "bdr": nbr.get("bdr", "N/A"),
                    "interface": iface_key,
                    "area": area_id,
                    "dead_timer": (nbr.get("status") or {}).get("dead_timer_due", "N/A") if isinstance(nbr.get("status"), dict) else "N/A",
                    "instance": instance_id,
                    "neighbor_router_id": nbr.get("nbr_router_id", "N/A"),
                })
            return result

        # 1. Instances
        routers_data = await self._get(
            f"/system/vrfs/{vrf}/ospf_routers", params={"depth": "1"}
        )
        if not isinstance(routers_data, dict):
            return {"vrf": vrf, "ospf_neighbors": [], "count": 0}

        # Collect all (instance, area, interface) tuples
        tasks = []
        for instance_id, _ in self._collection_items(routers_data):
            areas_data = await self._get(
                f"/system/vrfs/{vrf}/ospf_routers/{instance_id}/areas",
                params={"depth": "1"},
            )
            if not isinstance(areas_data, dict):
                continue
            for area_id, _ in self._collection_items(areas_data):
                encoded_area = quote(str(area_id), safe="")
                ifaces_data = await self._get(
                    f"/system/vrfs/{vrf}/ospf_routers/{instance_id}/areas/{encoded_area}/ospf_interfaces",
                    params={"depth": "1"},
                )
                if not isinstance(ifaces_data, dict):
                    continue
                for iface_key, _ in self._collection_items(ifaces_data):
                    tasks.append(_fetch_neighbors(instance_id, area_id, iface_key))

        # 4. Parallel calls
        results = await asyncio.gather(*tasks)
        neighbors = [nbr for sublist in results for nbr in sublist]
        return {"vrf": vrf, "ospf_neighbors": neighbors, "count": len(neighbors)}

    async def get_ospf_interfaces(self, vrf: str = "default") -> dict:
        """OSPF interfaces with cost, timers, state.

        Strategy: list interfaces via depth=1, then parallel calls
        to each interface with depth=2 (includes ospf_neighbors as a collection).
        """
        async def _fetch_interface(instance_id: str, area_id: str, iface_key: str) -> dict | None:
            encoded_area = quote(str(area_id), safe="")
            encoded_iface = quote(str(iface_key), safe="")
            try:
                iface_obj = await asyncio.wait_for(
                    self._get(
                        f"/system/vrfs/{vrf}/ospf_routers/{instance_id}/areas/{encoded_area}"
                        f"/ospf_interfaces/{encoded_iface}",
                        params={"depth": "2"},
                    ),
                    timeout=10,
                )
            except (ArubaAPIError, asyncio.TimeoutError):
                return None
            if not isinstance(iface_obj, dict):
                return None
            nbr_raw = iface_obj.get("ospf_neighbors") or {}
            return {
                "interface": iface_key,
                "area": area_id,
                "instance": instance_id,
                "cost": iface_obj.get("calculated_output_cost", "N/A"),
                "hello_interval": iface_obj.get("hello_interval", "N/A"),
                "dead_interval": iface_obj.get("dead_interval", "N/A"),
                "network_type": iface_obj.get("network_type", "N/A"),
                "passive": iface_obj.get("passive", False),
                "state": iface_obj.get("ifsm_state", "N/A"),
                "dr_id": iface_obj.get("dr", "N/A"),
                "bdr_id": iface_obj.get("bdr", "N/A"),
                "neighbor_count": len(nbr_raw) if isinstance(nbr_raw, (dict, list)) else 0,
            }

        routers_data = await self._get(
            f"/system/vrfs/{vrf}/ospf_routers", params={"depth": "1"}
        )
        if not isinstance(routers_data, dict):
            return {"vrf": vrf, "ospf_interfaces": [], "count": 0}

        tasks = []
        for instance_id, _ in self._collection_items(routers_data):
            areas_data = await self._get(
                f"/system/vrfs/{vrf}/ospf_routers/{instance_id}/areas",
                params={"depth": "1"},
            )
            if not isinstance(areas_data, dict):
                continue
            for area_id, _ in self._collection_items(areas_data):
                encoded_area = quote(str(area_id), safe="")
                ifaces_data = await self._get(
                    f"/system/vrfs/{vrf}/ospf_routers/{instance_id}/areas/{encoded_area}/ospf_interfaces",
                    params={"depth": "1"},
                )
                if not isinstance(ifaces_data, dict):
                    continue
                for iface_key, _ in self._collection_items(ifaces_data):
                    tasks.append(_fetch_interface(instance_id, area_id, iface_key))

        results = await asyncio.gather(*tasks)
        interfaces = [r for r in results if r is not None]
        return {"vrf": vrf, "ospf_interfaces": interfaces, "count": len(interfaces)}

    # ─── CLI command ─────────────────────────────────────────────────────────

    async def get_cli_supported_commands(self) -> list[str]:
        """Try to list the commands via GET /cli (returns [] if not supported — 405)."""
        try:
            data = await self._get("/cli")
        except ArubaAPIError:
            return []
        if isinstance(data, list):
            return [str(c) for c in data]
        if isinstance(data, dict):
            for key in ("commands", "cli_cmds", "supported_commands"):
                if key in data and isinstance(data[key], list):
                    return [str(c) for c in data[key]]
        return []

    async def is_cli_command_supported(self, command: str) -> Optional[bool]:
        """
        Indicate whether a CLI command is supported according to GET /cli.
        Return True/False if the list is available, None if it is not
        (GET /cli not supported by the firmware — cannot be verified).
        """
        supported = await self.get_cli_supported_commands()
        if not supported:
            return None
        target = " ".join(command.strip().lower().split())
        normalized = [" ".join(c.strip().lower().split()) for c in supported]
        return any(target == c or target.startswith(c + " ") or c.startswith(target + " ")
                   for c in normalized)

    # Patterns returned by /cli when a command is not executable
    # (unrecognized, refused by an allow-list, or not permitted).
    _CLI_UNSUPPORTED_PATTERNS = (
        "invalid command",
        "not allowed",
        "not permitted",
        "not authorized",
        "permission denied",
        "command not found",
        "unknown command",
        "not supported",
        "incomplete command",
    )

    def _cli_unsupported_reason(self, status: int, text: str) -> Optional[str]:
        """Return a readable reason if the /cli response indicates that the command
        is not executable (to be treated as unsupported, not as a hard
        error), otherwise None. Covers 400 'Invalid command' and 403 'not allowed'."""
        lowered = text.lower()
        if status in (400, 403, 404, 405) and any(p in lowered for p in self._CLI_UNSUPPORTED_PATTERNS):
            return text.strip()
        return None

    # Mapping of CLI command 'show …' → equivalent REST tool to use
    # as a fallback when /cli refuses or does not support the command.
    _CLI_REST_FALLBACKS = (
        ("show system", "get_system_info"),
        ("show version", "get_system_info"),
        ("show environment", "get_hardware_health"),
        ("show module", "get_hardware_health"),
        ("show interface", "get_interfaces"),
        ("show ip interface", "get_interfaces"),
        ("show lacp", "get_lag"),
        ("show lacp interfaces", "get_lag"),
        ("show lacp aggregates", "get_lag"),
        ("show lacp configuration", "get_lag"),
        ("show interface lag", "get_lag"),
        ("show lag", "get_lag"),
        ("show vlan", "get_vlans"),
        ("show lldp neighbor", "get_lldp_neighbors"),
        ("show mac-address-table", "get_mac_table"),
        ("show arp", "get_arp_table"),
        ("show ip route", "get_routing_table"),
        ("show ip ospf neighbor", "get_ospf_neighbors"),
        ("show ip ospf interface", "get_ospf_interfaces"),
        ("show ip ospf", "get_ospf_overview"),
        ("show bgp", "get_bgp_neighbors"),
        ("show ip bgp", "get_bgp_routes"),
        ("show spanning-tree", "get_spanning_tree"),
        ("show vsx", "get_vsx_status"),
        ("show vsf", "get_vsf_status"),
        ("show running-config", "get_config"),
        ("show logging", "get_logs"),
        ("show evpn", "get_evpn_config"),
        ("show interface transceiver", "get_transceivers"),
    )

    def _cli_rest_fallback(self, command: str) -> Optional[str]:
        """Return the name of the equivalent REST tool for a given CLI
        command, to use as a fallback when /cli cannot execute it, or None
        if no known mapping exists."""
        normalized = " ".join(command.strip().lower().split())
        # Prefer the longest (most specific) match.
        best: Optional[str] = None
        best_len = -1
        for prefix, tool in self._CLI_REST_FALLBACKS:
            if (normalized == prefix or normalized.startswith(prefix + " ")) and len(prefix) > best_len:
                best, best_len = tool, len(prefix)
        return best

    async def run_cli_command(self, command: str, verify_supported: bool = True, _retried: bool = False) -> dict:
        """
        Execute a CLI command via POST /cli (text/plain response).

        verify_supported: if True, first verify via GET /cli that the command
        is supported. If the list is not available (firmware without GET /cli),
        the command is executed without any possible verification.

        If the command is not executable (negative GET /cli check, or
        POST response 400 'Invalid command' / 403 'not allowed'…), return
        supported=False WITHOUT raising an error (clean degradation, the raw error
        is not exposed to the user). Where applicable, `fallback_tool`
        indicates the equivalent REST tool to use instead.
        """
        verified: Optional[bool] = None
        if verify_supported:
            verified = await self.is_cli_command_supported(command)
            if verified is False:
                return {
                    "command": command,
                    "supported": False,
                    "output": None,
                    "support_verified": False,
                    "fallback_tool": self._cli_rest_fallback(command),
                    "error": f"Command '{command}' not supported according to GET /cli.",
                }
        url = f"{self._base_url}/cli"
        await self._ensure_live()
        gen = self._session_gen
        expired = False
        output = ""
        try:
            async with self._session.post(url, json={"cmd": command}, headers={"Content-Type": "application/json"}) as resp:
                text = await resp.text()
                if resp.status == 401 and not _retried:
                    expired = True  # re-login + retry once, after releasing the response
                elif resp.status not in (200, 201, 202):
                    # Command not executable (unrecognized, refused by an allow-list,
                    # not permitted…): we report it cleanly
                    # rather than raising a hard error exposed to the user.
                    reason = self._cli_unsupported_reason(resp.status, text)
                    if reason is not None:
                        return {
                            "command": command,
                            "supported": False,
                            "output": None,
                            "support_verified": verified,
                            "fallback_tool": self._cli_rest_fallback(command),
                            "error": (
                                f"Command not executable via /cli on this device "
                                f"(response: {reason})."
                            ),
                        }
                    raise ArubaAPIError(f"POST /cli error: {text}", resp.status)
                else:
                    output = text
        except asyncio.TimeoutError as exc:
            raise ArubaAPIError(
                f"Timeout after {self.timeout.total:g}s on CLI command '{command}' "
                f"({self.host}). The command takes too long to execute — increase the timeout.",
                504,
            ) from exc
        except aiohttp.ClientError as exc:
            raise ArubaAPIError(
                f"Network error on CLI command '{command}' to {self.host}: "
                f"{type(exc).__name__} — {exc}",
                502,
            ) from exc
        except RuntimeError as exc:
            if not _retried and self._is_dead_session_error(exc):
                expired = True  # dead pooled session → reconnect + retry once
            else:
                raise ArubaAPIError(f"Session error on CLI command '{command}' to {self.host}: {exc}", 502) from exc
        if expired:
            await self._reconnect(gen)
            return await self.run_cli_command(command, verify_supported=False, _retried=True)
        return {
            "command": command,
            "supported": True,
            "output": output,
            "support_verified": verified,
        }

    # ─── EVPN ────────────────────────────────────────────────────────────────

    async def get_evpn_config(self, vni_id: Optional[int] = None) -> dict:
        """
        Global EVPN configuration + L2 and L3 VNIs, with ARP/ND suppression details
        and redistribution.
        Sources:
          - /system/evpn              → global config
          - /system/evpn/evpn_vlans   → per-VLAN EVPN config (ARP/ND suppression, RTs)
          - /system/virtual_network_ids → VNI→VLAN/VRF mappings
          - /system/evpn_instances    → operational stats per VNI
        """
        # 1. Global EVPN config
        try:
            evpn_raw = await self._get("/system/evpn", params={"depth": "2"})
        except ArubaAPIError:
            evpn_raw = {}

        global_cfg = {
            "enabled": bool(evpn_raw) if isinstance(evpn_raw, dict) else False,
            "arp_suppression": evpn_raw.get("arp_suppression_enable", False) if isinstance(evpn_raw, dict) else False,
            "nd_suppression": evpn_raw.get("nd_suppression_enable", False) if isinstance(evpn_raw, dict) else False,
            "igmp_mld_proxy": evpn_raw.get("igmp_mld_proxy_enable", False) if isinstance(evpn_raw, dict) else False,
            "allow_imet_relay": evpn_raw.get("allow_imet_relay", False) if isinstance(evpn_raw, dict) else False,
            "oism_enable": evpn_raw.get("oism_enable", False) if isinstance(evpn_raw, dict) else False,
            "mac_move_count": evpn_raw.get("mac_move_count", "N/A") if isinstance(evpn_raw, dict) else "N/A",
            "mac_move_timer": evpn_raw.get("mac_move_timer", "N/A") if isinstance(evpn_raw, dict) else "N/A",
            "redistribute_local_mac": (evpn_raw.get("redistribute") or {}).get("local-mac", False) if isinstance(evpn_raw, dict) else False,
            "redistribute_local_svi": (evpn_raw.get("redistribute") or {}).get("local-svi", False) if isinstance(evpn_raw, dict) else False,
        }

        # 2. Per-VLAN EVPN config (ARP/ND suppression, RTs, host-route redistribution)
        try:
            evpn_vlans_raw = await self._get("/system/evpn/evpn_vlans", params={"depth": "3"})
            if not isinstance(evpn_vlans_raw, dict):
                evpn_vlans_raw = {}
        except ArubaAPIError:
            evpn_vlans_raw = {}

        # 3. VNI → VLAN/VRF mappings
        try:
            vni_map_raw = await self._get(
                "/system/virtual_network_ids",
                params={"depth": "2", "selector": "configuration"},
            )
            if not isinstance(vni_map_raw, dict):
                vni_map_raw = {}
        except ArubaAPIError:
            vni_map_raw = {}

        # 4. Operational stats from evpn_instances
        try:
            evpn_instances = await self._get("/system/evpn_instances", params={"depth": "2"})
            if not isinstance(evpn_instances, dict):
                evpn_instances = {}
        except ArubaAPIError:
            evpn_instances = {}

        # Build a vlan_id → evpn_vlan_config map
        vlan_evpn_cfg: dict[str, dict] = {}
        for vlan_key, vlan_evpn in self._collection_items(evpn_vlans_raw):
            if isinstance(vlan_evpn, dict):
                vlan_evpn_cfg[str(vlan_key)] = vlan_evpn

        # 5. Build L2 and L3 VNIs from virtual_network_ids
        l2_vnis: list[dict] = []
        l3_vnis: list[dict] = []

        for vni_key, vni_cfg in self._collection_items(vni_map_raw):
            if not isinstance(vni_cfg, dict):
                continue
            vni_num = vni_cfg.get("id")
            if vni_num is None:
                continue
            if vni_id is not None and vni_num != vni_id:
                continue

            # Operational stats
            evi = evpn_instances.get(str(vni_num), {}) if isinstance(evpn_instances, dict) else {}
            oper_status = evi.get("operational_status", "N/A") if isinstance(evi, dict) else "N/A"
            evi_stats = evi.get("statistics", {}) if isinstance(evi, dict) else {}
            rd_oper = evi.get("rd", "N/A") if isinstance(evi, dict) else "N/A"
            rt_import_oper = evi.get("import_route_targets", []) if isinstance(evi, dict) else []
            rt_export_oper = evi.get("export_route_targets", []) if isinstance(evi, dict) else []

            if vni_cfg.get("routing"):
                # L3 VNI
                vrf_refs = vni_cfg.get("vrf") or {}
                vrf_name = next(iter(vrf_refs.keys()), "N/A") if isinstance(vrf_refs, dict) else "N/A"
                l3_vnis.append({
                    "vni": vni_num,
                    "type": "L3",
                    "vrf": vrf_name,
                    "oper_status": oper_status,
                    "route_distinguisher": rd_oper,
                    "route_targets_import": rt_import_oper,
                    "route_targets_export": rt_export_oper,
                    "local_mac_count": evi_stats.get("local_mac_count", 0) if isinstance(evi_stats, dict) else 0,
                    "remote_mac_count": evi_stats.get("remote_mac_count", 0) if isinstance(evi_stats, dict) else 0,
                    "peer_vtep_count": evi_stats.get("peer_vtep_count", 0) if isinstance(evi_stats, dict) else 0,
                })
            else:
                # L2 VNI
                vlan_refs = vni_cfg.get("vlan") or {}
                vlan_id = next(iter(vlan_refs.keys()), "N/A") if isinstance(vlan_refs, dict) else "N/A"
                # VLAN-specific EVPN config
                vcfg = vlan_evpn_cfg.get(str(vlan_id), {})
                arp_sup_cfg = vcfg.get("arp_suppression_config") if isinstance(vcfg, dict) else None
                nd_sup_cfg = vcfg.get("nd_suppression_config") if isinstance(vcfg, dict) else None
                redistribute_vlan = vcfg.get("redistribute") if isinstance(vcfg, dict) else {}
                rd_cfg = vcfg.get("rd", "auto") if isinstance(vcfg, dict) else "auto"
                rt_import_cfg = vcfg.get("import_route_targets", []) if isinstance(vcfg, dict) else []
                rt_export_cfg = vcfg.get("export_route_targets", []) if isinstance(vcfg, dict) else []
                l2_vnis.append({
                    "vni": vni_num,
                    "type": "L2",
                    "vlan": vlan_id,
                    "oper_status": oper_status,
                    "route_distinguisher": rd_oper if rd_oper != "N/A" else rd_cfg,
                    "route_targets_import": rt_import_oper or rt_import_cfg,
                    "route_targets_export": rt_export_oper or rt_export_cfg,
                    # ARP/ND suppression: global by default, can be overridden per VLAN
                    "arp_suppression": global_cfg["arp_suppression"] if arp_sup_cfg is None else arp_sup_cfg,
                    "arp_suppression_extended": vcfg.get("arp_suppression_ip_exemption", []) if isinstance(vcfg, dict) else [],
                    "nd_suppression": global_cfg["nd_suppression"] if nd_sup_cfg is None else nd_sup_cfg,
                    "nd_suppression_extended": vcfg.get("nd_suppression_ip_exemption", []) if isinstance(vcfg, dict) else [],
                    "redistribute_host_route": (redistribute_vlan or {}).get("host-route", False) if isinstance(redistribute_vlan, dict) else False,
                    "local_mac_count": evi_stats.get("local_mac_count", 0) if isinstance(evi_stats, dict) else 0,
                    "remote_mac_count": evi_stats.get("remote_mac_count", 0) if isinstance(evi_stats, dict) else 0,
                    "peer_vtep_count": evi_stats.get("peer_vtep_count", 0) if isinstance(evi_stats, dict) else 0,
                    "remote_mac_per_vtep": evi.get("remote_mac_count_per_vtep_peer", {}) if isinstance(evi, dict) else {},
                })

        if l2_vnis or l3_vnis:
            global_cfg["enabled"] = True

        return {
            "global": global_cfg,
            "l2_vnis": sorted(l2_vnis, key=lambda x: x["vni"]),
            "l3_vnis": sorted(l3_vnis, key=lambda x: x["vni"]),
            "l2_count": len(l2_vnis),
            "l3_count": len(l3_vnis),
        }

    # ─── VXLAN ───────────────────────────────────────────────────────────────

    async def get_vxlan_config(self) -> dict:
        """
        VXLAN configuration: VTEP interfaces, VNI→VLAN/VRF mapping, source IP, peers.
        Source: /system/virtual_network_ids (selector=configuration) for the mappings
                /system/evpn_instances for operational stats and the RD (source IP).
        """
        # 1. VNI → VLAN/VRF mappings from virtual_network_ids
        try:
            vni_data = await self._get(
                "/system/virtual_network_ids",
                params={"depth": "2", "selector": "configuration"},
            )
        except ArubaAPIError:
            vni_data = {}

        if not isinstance(vni_data, dict) or not vni_data:
            return {"vtep_interfaces": [], "count": 0,
                    "message": "No VXLAN (VTEP) interface found."}

        # 2. Operational stats from evpn_instances
        try:
            evpn_instances = await self._get("/system/evpn_instances", params={"depth": "2"})
            if not isinstance(evpn_instances, dict):
                evpn_instances = {}
        except ArubaAPIError:
            evpn_instances = {}

        # 3. Derive the VTEP source IP from the RD of an EVPN instance
        source_ip = "N/A"
        for evi_key, evi_data in self._collection_items(evpn_instances):
            if isinstance(evi_data, dict):
                rd = evi_data.get("rd", "")
                if rd and isinstance(rd, str) and ":" in rd:
                    source_ip = rd.split(":")[0]
                    break

        # 4. Group by VTEP interface
        vtep_map: dict[str, dict] = {}  # iface_name → {l2_vnis, l3_vnis}
        for vni_key, vni_cfg in self._collection_items(vni_data):
            if not isinstance(vni_cfg, dict):
                continue
            vni_id = vni_cfg.get("id")
            if vni_id is None:
                continue
            # VTEP interface (normally vxlan1, vxlan2…)
            iface_refs = vni_cfg.get("interface") or {}
            iface_name = next(iter(iface_refs.keys()), "vxlan1") if isinstance(iface_refs, dict) else "vxlan1"

            if iface_name not in vtep_map:
                vtep_map[iface_name] = {"l2_vnis": [], "l3_vnis": []}

            # Operational stats of this EVI
            evi_stats = evpn_instances.get(str(vni_id), {}) if isinstance(evpn_instances, dict) else {}
            oper_status = evi_stats.get("operational_status", "N/A") if isinstance(evi_stats, dict) else "N/A"
            stats = evi_stats.get("statistics", {}) if isinstance(evi_stats, dict) else {}
            rd = evi_stats.get("rd", "N/A") if isinstance(evi_stats, dict) else "N/A"
            rt_import = evi_stats.get("import_route_targets", []) if isinstance(evi_stats, dict) else []
            rt_export = evi_stats.get("export_route_targets", []) if isinstance(evi_stats, dict) else []

            if vni_cfg.get("routing"):  # L3 VNI
                vrf_refs = vni_cfg.get("vrf") or {}
                vrf_name = next(iter(vrf_refs.keys()), "N/A") if isinstance(vrf_refs, dict) else "N/A"
                vtep_map[iface_name]["l3_vnis"].append({
                    "vni": vni_id,
                    "vrf": vrf_name,
                    "oper_status": oper_status,
                    "rd": rd,
                    "route_targets_import": rt_import,
                    "route_targets_export": rt_export,
                    "local_mac_count": stats.get("local_mac_count", 0) if isinstance(stats, dict) else 0,
                    "remote_mac_count": stats.get("remote_mac_count", 0) if isinstance(stats, dict) else 0,
                    "peer_vtep_count": stats.get("peer_vtep_count", 0) if isinstance(stats, dict) else 0,
                })
            else:  # L2 VNI
                vlan_refs = vni_cfg.get("vlan") or {}
                vlan_id = next(iter(vlan_refs.keys()), "N/A") if isinstance(vlan_refs, dict) else "N/A"
                vtep_map[iface_name]["l2_vnis"].append({
                    "vni": vni_id,
                    "vlan": vlan_id,
                    "oper_status": oper_status,
                    "rd": rd,
                    "route_targets_import": rt_import,
                    "route_targets_export": rt_export,
                    "local_mac_count": stats.get("local_mac_count", 0) if isinstance(stats, dict) else 0,
                    "remote_mac_count": stats.get("remote_mac_count", 0) if isinstance(stats, dict) else 0,
                    "peer_vtep_count": stats.get("peer_vtep_count", 0) if isinstance(stats, dict) else 0,
                })

        if not vtep_map:
            return {"vtep_interfaces": [], "count": 0,
                    "message": "No VXLAN (VTEP) interface found."}

        result = []
        for iface_name, vnis in vtep_map.items():
            l2 = sorted(vnis["l2_vnis"], key=lambda x: x["vni"])
            l3 = sorted(vnis["l3_vnis"], key=lambda x: x["vni"])
            result.append({
                "interface": iface_name,
                "source_ip": source_ip,
                "l2_vnis": l2,
                "l2_count": len(l2),
                "l3_vnis": l3,
                "l3_count": len(l3),
                "total_vni_count": len(l2) + len(l3),
            })

        return {"vtep_interfaces": result, "count": len(result)}

    async def get_vxlan_tunnels(self) -> dict:
        """
        Operational status of all VXLAN tunnels (EVPN + static).
        Source: GET /system/interfaces/{vxlan_iface}/tunnel_endpoints?selector=status
        Tunnel key: "{vrf},{origin},{destination}"
        Fields: destination, origin (evpn/static/hsc), state, mac, active VNIs, VRF.
        Traffic statistics (rx/tx packets/bytes) are included separately.
        """
        cfg = await self.get_vxlan_config()
        if not cfg.get("vtep_interfaces"):
            return {"vxlan_tunnels": [], "count": 0,
                    "message": "No VXLAN interface found."}

        tunnels = []
        for vtep in cfg["vtep_interfaces"]:
            iface_name = vtep["interface"]
            source_ip = vtep.get("source_ip", "N/A")
            encoded = quote(str(iface_name), safe="")

            # Status
            try:
                endpoints_status = await self._get(
                    f"/system/interfaces/{encoded}/tunnel_endpoints",
                    params={"depth": "2", "selector": "status"},
                )
            except ArubaAPIError:
                endpoints_status = {}

            # Statistics (separate so as not to slow down the status)
            try:
                endpoints_stats = await self._get(
                    f"/system/interfaces/{encoded}/tunnel_endpoints",
                    params={"depth": "2", "selector": "statistics"},
                )
            except ArubaAPIError:
                endpoints_stats = {}

            for ep_key, ep_data in self._collection_items(endpoints_status):
                if not isinstance(ep_data, dict):
                    continue
                # Extract the VNIs from network_id (dict vni_key → URI or object)
                net_ids = ep_data.get("network_id") or {}
                if isinstance(net_ids, dict):
                    vnis = [int(k.split(",")[-1]) for k in net_ids.keys() if "," in k]
                elif isinstance(net_ids, list):
                    vnis = [int(uri.rstrip("/").split(",")[-1]) for uri in net_ids if isinstance(uri, str)]
                else:
                    vnis = []

                # VRF
                vrf_refs = ep_data.get("vrf") or {}
                vrf_name = next(iter(vrf_refs.keys()), "default") if isinstance(vrf_refs, dict) else str(vrf_refs)

                # Stats
                ep_stats = (endpoints_stats or {}).get(ep_key, {}) if isinstance(endpoints_stats, dict) else {}
                stats_data = ep_stats.get("statistics", {}) if isinstance(ep_stats, dict) else {}

                tunnels.append({
                    "interface": iface_name,
                    "source_ip": source_ip,
                    "remote_vtep": ep_data.get("destination", ep_key.split(",")[-1] if "," in ep_key else ep_key),
                    "origin": ep_data.get("origin", "N/A"),
                    "state": ep_data.get("state", "N/A"),
                    "vrf": vrf_name,
                    "peer_mac": ep_data.get("mac", "N/A"),
                    "macs_invalid": ep_data.get("macs_invalid", False),
                    "vnis": sorted(vnis),
                    "vni_count": len(vnis),
                    "statistics": {
                        "rx_packets": stats_data.get("rx_packets", 0),
                        "rx_bytes": stats_data.get("rx_bytes", 0),
                        "rx_bum_packets": stats_data.get("rx_bum_packets", 0),
                        "tx_packets": stats_data.get("tx_packets", 0),
                        "tx_bytes": stats_data.get("tx_bytes", 0),
                        "tx_bum_packets": stats_data.get("tx_bum_packets", 0),
                    } if stats_data else {},
                })

        by_origin: dict[str, int] = {}
        for t in tunnels:
            o = t.get("origin", "unknown")
            by_origin[o] = by_origin.get(o, 0) + 1

        return {
            "vxlan_tunnels": tunnels,
            "count": len(tunnels),
            "by_origin": by_origin,
        }

    async def get_vxlan_static_peers(self) -> dict:
        """
        Statically configured VXLAN peers (origin=static).
        Returns the static-type tunnel endpoints with their VNIs and statistics.
        If no static peer is configured, returns an empty list.
        """
        cfg = await self.get_vxlan_config()
        if not cfg.get("vtep_interfaces"):
            return {"static_peers": [], "count": 0,
                    "message": "No VXLAN interface found."}

        static_peers = []
        for vtep in cfg["vtep_interfaces"]:
            iface_name = vtep["interface"]
            source_ip = vtep.get("source_ip", "N/A")
            encoded = quote(str(iface_name), safe="")

            try:
                endpoints = await self._get(
                    f"/system/interfaces/{encoded}/tunnel_endpoints",
                    params={"depth": "2", "selector": "status",
                            "filter": "origin:static"},
                )
            except ArubaAPIError:
                endpoints = {}

            for ep_key, ep_data in self._collection_items(endpoints):
                if not isinstance(ep_data, dict):
                    continue
                if ep_data.get("origin") != "static":
                    continue

                net_ids = ep_data.get("network_id") or {}
                if isinstance(net_ids, dict):
                    vnis = [int(k.split(",")[-1]) for k in net_ids.keys() if "," in k]
                elif isinstance(net_ids, list):
                    vnis = [int(uri.rstrip("/").split(",")[-1]) for uri in net_ids if isinstance(uri, str)]
                else:
                    vnis = []

                vrf_refs = ep_data.get("vrf") or {}
                vrf_name = next(iter(vrf_refs.keys()), "default") if isinstance(vrf_refs, dict) else str(vrf_refs)

                static_peers.append({
                    "interface": iface_name,
                    "source_ip": source_ip,
                    "remote_vtep": ep_data.get("destination", ep_key.split(",")[-1] if "," in ep_key else ep_key),
                    "vrf": vrf_name,
                    "state": ep_data.get("state", "N/A"),
                    "peer_mac": ep_data.get("mac", "N/A"),
                    "vnis": sorted(vnis),
                    "vni_count": len(vnis),
                })

        return {
            "static_peers": static_peers,
            "count": len(static_peers),
            "message": "No static VXLAN peer configured." if not static_peers else None,
        }

    async def get_evpn_vtep_neighbors(self, vrf: str = "default") -> dict:
        """
        VTEP neighbors learned via EVPN.
        Primary source: /system/vrfs/{vrf}/evpn_vtep_neighbors
        Secondary source: tunnel_endpoints filtered origin=evpn (if primary empty).
        """
        # Primary source
        try:
            raw = await self._get(
                f"/system/vrfs/{vrf}/evpn_vtep_neighbors",
                params={"depth": "3"},
            )
        except ArubaAPIError:
            raw = {}

        vtep_neighbors = []
        if isinstance(raw, dict) and raw:
            for ip_addr, nbr in self._collection_items(raw):
                if not isinstance(nbr, dict):
                    continue
                vtep_neighbors.append({
                    "ip_address": nbr.get("ip_address", ip_addr),
                    "origin": "evpn",
                    "vrf": vrf,
                    "state": nbr.get("state", "N/A"),
                    "mac": nbr.get("mac", "N/A"),
                    "vnis": list((nbr.get("vnis") or {}).keys()),
                })
        else:
            # Fallback: tunnel_endpoints origin=evpn on all VXLAN interfaces
            cfg = await self.get_vxlan_config()
            for vtep in cfg.get("vtep_interfaces", []):
                iface_name = vtep["interface"]
                encoded = quote(str(iface_name), safe="")
                try:
                    endpoints = await self._get(
                        f"/system/interfaces/{encoded}/tunnel_endpoints",
                        params={"depth": "2", "selector": "status"},
                    )
                except ArubaAPIError:
                    continue
                for ep_key, ep_data in self._collection_items(endpoints):
                    if not isinstance(ep_data, dict):
                        continue
                    if ep_data.get("origin") != "evpn":
                        continue
                    net_ids = ep_data.get("network_id") or {}
                    if isinstance(net_ids, dict):
                        vnis = sorted([int(k.split(",")[-1]) for k in net_ids.keys() if "," in k])
                    elif isinstance(net_ids, list):
                        vnis = sorted([int(uri.rstrip("/").split(",")[-1]) for uri in net_ids if isinstance(uri, str)])
                    else:
                        vnis = []
                    vrf_refs = ep_data.get("vrf") or {}
                    vrf_name = next(iter(vrf_refs.keys()), vrf) if isinstance(vrf_refs, dict) else vrf
                    vtep_neighbors.append({
                        "ip_address": ep_data.get("destination", ep_key.split(",")[-1] if "," in ep_key else ep_key),
                        "origin": "evpn",
                        "vrf": vrf_name,
                        "interface": iface_name,
                        "state": ep_data.get("state", "N/A"),
                        "mac": ep_data.get("mac", "N/A"),
                        "macs_invalid": ep_data.get("macs_invalid", False),
                        "vnis": vnis,
                        "vni_count": len(vnis),
                    })

        return {
            "evpn_vtep_neighbors": vtep_neighbors,
            "count": len(vtep_neighbors),
            "vrf": vrf,
        }

    # ─── EVPN Multihoming (Ethernet Segments) ────────────────────────────────

    async def get_evpn_multihoming(self) -> dict:
        """
        EVPN multihoming state (standards-based, RFC 7432 Ethernet Segments).

        Sources:
          - /system/evpn                     → global multihoming-system-id (LACP
                                               bridge identifier shared by all ES peers)
          - /system/evpn_ethernet_segments   → the configured Ethernet Segments with
                                               their ESI, mode, DF election state,
                                               operational status, RD/RT, ES port and
                                               peer VTEP members.

        If the Ethernet-Segment resource is absent (feature not supported or not
        configured), return configured=False (not an error).
        """
        # 1. Global multihoming system-id from the EVPN object.
        try:
            evpn_raw = await self._get("/system/evpn", params={"depth": "2"})
            if not isinstance(evpn_raw, dict):
                evpn_raw = {}
        except ArubaAPIError:
            evpn_raw = {}

        system_id = evpn_raw.get("multihoming_system_id", "N/A")

        # 2. Ethernet Segments.
        try:
            es_raw = await self._get(
                "/system/evpn_ethernet_segments", params={"depth": "3"}
            )
        except ArubaAPIError as exc:
            # The resource is absent when multihoming is unsupported/unconfigured.
            # Depending on firmware this surfaces as 404, or as 400 with a
            # "resource ... not found" message — treat both as "feature absent".
            _absent = exc.status_code == 404 or (
                exc.status_code == 400 and "not found" in str(exc).lower()
            )
            if _absent:
                return {
                    "configured": False,
                    "supported": False,
                    "multihoming_system_id": system_id,
                    "ethernet_segments": [],
                    "count": 0,
                    "message": (
                        "EVPN multihoming is not available on this device: the "
                        "resource /system/evpn_ethernet_segments is absent "
                        "(feature not supported or not configured)."
                    ),
                }
            raise

        segments: list[dict] = []
        for esi_key, es in self._collection_items(es_raw):
            if not isinstance(es, dict):
                continue
            # ES port reference → human-readable interface name.
            es_port = self._ref_name(es.get("es_port"))
            # The local VTEP that answered this query, derived from the RD
            # (admin field = local router-id / VTEP loopback, e.g. "10.0.0.1:0").
            rd = es.get("rd", "N/A")
            local_vtep = (
                rd.rsplit(":", 1)[0] if isinstance(rd, str) and ":" in rd else None
            )
            # ES peer members are references to Tunnel_Endpoint resources whose key
            # encodes the *peer* VTEP IP, e.g. "vxlan1,default,evpn,10.147.253.173".
            members_raw = es.get("es_members")
            member_keys: list[str] = []
            if isinstance(members_raw, dict):
                member_keys = [k for k in members_raw.keys() if k.upper() != "URI"]
            elif isinstance(members_raw, list):
                member_keys = [self._ref_name(ref) or str(ref) for ref in members_raw]
            peer_vteps = [k.split(",")[-1].strip() for k in member_keys if k]

            # Designated-forwarder election results. The API returns, per EVPN VLAN,
            # a boolean telling whether THIS device (local_vtep) is the elected DF
            # for that VLAN:  {"/rest/.../vlans/100": true|false}.
            # We resolve, per VLAN, the VTEP that is actually the Designated Forwarder.
            df_rules_raw = es.get("designated_forwarder_rules")
            df_election: list[dict] = []
            if isinstance(df_rules_raw, dict):
                for ref, is_local_df in df_rules_raw.items():
                    if ref.upper() == "URI":
                        continue
                    vlan_id = ref.rstrip("/").split("/")[-1]
                    if is_local_df:
                        df_vtep = local_vtep
                    elif len(peer_vteps) == 1:
                        # 2-member ES: if the local device is not the DF, the single
                        # peer necessarily is.
                        df_vtep = peer_vteps[0]
                    else:
                        df_vtep = None  # cannot disambiguate among >1 peers
                    df_election.append({
                        "vlan": vlan_id,
                        "local_is_df": bool(is_local_df),
                        "designated_forwarder_vtep": df_vtep or "unknown",
                    })

            segments.append({
                "esi": es.get("esi", esi_key),
                "multihoming_mode": es.get("multihoming_mode", "N/A"),
                "operational_status": es.get("operational_status", "N/A"),
                "es_port": es_port or "N/A",
                "es_port_state": es.get("es_port_state", "N/A"),
                "df_election_wait_time": es.get("df_election_wait_time"),
                "local_vtep": local_vtep or "N/A",
                "designated_forwarder": df_election,
                "rd": rd,
                "import_route_target": es.get("import_route_target", "N/A"),
                "es_members": peer_vteps,
                "es_member_count": len(peer_vteps),
            })

        configured = bool(segments) or (system_id not in ("N/A", "", None))
        return {
            "configured": configured,
            "supported": True,
            "multihoming_system_id": system_id,
            "ethernet_segments": segments,
            "count": len(segments),
        }

    # ─── VSX (Virtual Switching Extension) ───────────────────────────────────

    @staticmethod
    def _ref_name(ref: Any) -> Optional[str]:
        """
        Extract the name of a resource referenced by the API.
        Handles references as a dict {"<name>": {...}} or as a URI string
        (e.g. '/rest/v10.18/system/ports/1%2F1%2F1' → '1/1/1').
        """
        if isinstance(ref, dict):
            return next(iter(ref.keys()), None)
        if isinstance(ref, str) and ref:
            return unquote(ref.rstrip("/").split("/")[-1])
        return None

    @staticmethod
    def _vsx_unavailable() -> dict:
        """Normalized response when VSX is neither supported nor configured (not an error)."""
        return {
            "configured": False,
            "supported": False,
            "message": (
                "VSX is not available on this device: the resource "
                "/system/vsx is absent (feature not supported or not configured)."
            ),
        }

    async def _get_vsx_raw(self) -> Optional[dict]:
        """
        Retrieve the raw VSX object, or None if VSX is not supported/configured.
        A 404 on /system/vsx means the feature is not
        available on this device — it is not an error.
        """
        try:
            data = await self._get("/system/vsx", params={"depth": "2"})
        except ArubaAPIError as exc:
            if exc.status_code == 404:
                return None
            raise
        if not isinstance(data, dict) or not data:
            return None
        return data

    async def get_vsx_status(self) -> dict:
        """
        Operational state of VSX and details about the members (local and peer).
        Equivalent to 'show vsx status' / 'show vsx brief'.
        If VSX is not supported/configured, return configured=False (not an error).
        """
        data = await self._get_vsx_raw()
        if data is None:
            return self._vsx_unavailable()
        oper = data.get("oper_status") or {}
        keepalive_status = data.get("keepalive_status") or {}
        keepalive_peer = data.get("keepalive_peer_status") or {}
        peer = data.get("peer_status") or {}

        local_role = oper.get("device_role") or data.get("device_role", "N/A")

        return {
            "configured": True,
            "overall_state": oper.get("overall_state", "N/A"),
            "device_role": local_role,
            "configured_role": data.get("device_role", "N/A"),
            "system_mac": data.get("system_mac", "N/A"),
            "oper_system_id": oper.get("oper_system_id", "N/A"),
            "isl_protocol_state": oper.get("islp_device_state", "N/A"),
            "isl_link_state": oper.get("islp_link_state", "N/A"),
            "isl_mgmt_state": oper.get("isl_mgmt_state", "N/A"),
            "config_sync_state": oper.get("config_sync_state", "N/A"),
            "keepalive_state": keepalive_status.get("state", "N/A"),
            "isl_last_established": data.get("isl_last_established"),
            "isl_last_disconnect": data.get("isl_last_disconnect"),
            "keepalive_last_established": data.get("keepalive_last_established"),
            "keepalive_last_failed": data.get("keepalive_last_failed"),
            "members": {
                "local": {
                    "role": local_role,
                    "system_mac": data.get("system_mac", "N/A"),
                    "system_id": oper.get("oper_system_id", "N/A"),
                    "isl_port": self._ref_name(data.get("isl_port")) or "N/A",
                    "software_version": data.get("software_version", "N/A"),
                },
                "peer": {
                    "role": peer.get("peer_device_role", "N/A"),
                    "system_mac": peer.get("peer_system_mac", "N/A"),
                    "system_id": peer.get("peer_system_id", "N/A"),
                    "isl_port": peer.get("peer_isl_port", "N/A"),
                    "ready": peer.get("peer_ready"),
                    "islp_state": keepalive_peer.get("peer_islp_state", "N/A"),
                    "software_version": data.get("peer_sw_version", "N/A"),
                    "platform": data.get("remote_platform_name", "N/A"),
                    "last_reboot_time": peer.get("last_reboot_time"),
                },
            },
        }

    async def get_vsx_config(self) -> dict:
        """
        VSX configuration detail: role, system-mac, ISL and keepalive ports,
        timers and options. Equivalent to 'show vsx configuration'.
        If VSX is not supported/configured, return configured=False (not an error).
        """
        data = await self._get_vsx_raw()
        if data is None:
            return self._vsx_unavailable()
        isl_timers = data.get("isl_timers") or {}
        keepalive_timers = data.get("keepalive_timers") or {}
        features = data.get("config_sync_features") or []

        return {
            "configured": True,
            "device_role": data.get("device_role", "N/A"),
            "system_mac": data.get("system_mac", "N/A"),
            "linkup_delay_timer": data.get("linkup_delay_timer"),
            "split_recovery_disable": data.get("split_recovery_disable", False),
            "isl": {
                "port": self._ref_name(data.get("isl_port")) or "N/A",
                "hello_interval": isl_timers.get("hello_interval"),
                "timeout": isl_timers.get("timeout"),
                "hold_time": isl_timers.get("hold_time"),
                "peer_detect_interval": isl_timers.get("peer_detect_interval"),
            },
            "keepalive": {
                "port": self._ref_name(data.get("keepalive_port")) or "N/A",
                "src_ip": data.get("keepalive_src_ip", "N/A"),
                "peer_ip": data.get("keepalive_peer_ip", "N/A"),
                "vrf": self._ref_name(data.get("keepalive_vrf")) or "default",
                "udp_port": data.get("keepalive_udp_port"),
                "hello_interval": keepalive_timers.get("hello_interval"),
                "dead_interval": keepalive_timers.get("dead_interval"),
            },
            "config_sync": {
                "enabled": not data.get("config_sync_disable", False),
                "synced_feature_count": len(features),
            },
        }

    async def get_vsx_sync(self) -> dict:
        """
        Elements synchronized between the VSX cluster members ('vsx-sync').
        Lists the features marked for synchronization and the sync state.
        If VSX is not supported/configured, return configured=False (not an error).
        """
        data = await self._get_vsx_raw()
        if data is None:
            return self._vsx_unavailable()
        features = data.get("config_sync_features") or []
        oper = data.get("oper_status") or {}

        return {
            "configured": True,
            "config_sync_enabled": not data.get("config_sync_disable", False),
            "config_sync_state": oper.get("config_sync_state", "N/A"),
            "last_sync_timestamp": data.get("last_sync_timestamp"),
            "synced_features": sorted(features),
            "synced_feature_count": len(features),
        }

    # ─── Maintenance Mode ────────────────────────────────────────────────────

    # The lifecycle statuses of a 'unit' (feature-set) that signal it is
    # actively entering / sitting in maintenance.
    #
    # IMPORTANT: `initiated` is NOT active — it is the RESTING/default state of
    # the built-in feature-sets (default-bgp, default-ospfv2, ...). They always
    # report `initiated` even when Maintenance Mode is Inactive (verified live:
    # CLI 'show maintenance-mode' = Inactive while the built-ins read
    # `initiated`). Only `processing` (transitioning in) and `in-maintenance-mode`
    # (actually in maintenance) count as active; `completed` means exited.
    _MM_ACTIVE_STATUSES = ("processing", "in-maintenance-mode")

    async def _get_maintenance_collection(self, path: str) -> Optional[list[tuple[str, Any]]]:
        """Retrieve a Maintenance Mode-related collection, or None if the resource
        does not exist on the platform. Depending on the AOS-CX version, an absent
        resource returns either a 404 or a 400 'resource or attribute … not found':
        in both cases, we consider the feature as not supported."""
        try:
            data = await self._get(path, params={"depth": "2"})
        except ArubaAPIError as exc:
            if exc.status_code == 404:
                return None
            if exc.status_code == 400 and "not found" in str(exc).lower():
                return None
            raise
        return self._collection_items(data)

    async def get_maintenance_mode(self) -> dict:
        """Maintenance Mode state.

        Indicates whether maintenance mode is configured (profiles and/or units), whether it
        is active, and where applicable which profile is applied and which units are
        currently in maintenance.

        - profiles: /system/maintenance_mode_profiles (key `activated`)
        - units (feature-sets): /system/feature_set_bgps and /system/feature_set_ospfs
          (key `maintenance_status`: initiated/processing/in-maintenance-mode/completed)

        An absent resource (404) means the platform does not support this
        part of the feature — it is not an error."""
        profiles_items = await self._get_maintenance_collection("/system/maintenance_mode_profiles")
        bgp_items = await self._get_maintenance_collection("/system/feature_set_bgps")
        ospf_items = await self._get_maintenance_collection("/system/feature_set_ospfs")

        supported = not (profiles_items is None and bgp_items is None and ospf_items is None)

        profiles = []
        active_profiles = []
        for name, prof in (profiles_items or []):
            if not isinstance(prof, dict):
                continue
            activated = bool(prof.get("activated", False))
            stages = prof.get("stages") if isinstance(prof.get("stages"), dict) else {}
            entry = {
                "name": prof.get("name", name),
                "activated": activated,
                "origin": prof.get("origin", "N/A"),
                "description": prof.get("description", ""),
                "stage_ids": sorted(stages.keys()),
                "stage_count": len(stages),
            }
            profiles.append(entry)
            if activated:
                active_profiles.append(entry["name"])

        units = []
        active_units = []
        for unit_type, items in (("bgp", bgp_items), ("ospf", ospf_items)):
            for name, unit in (items or []):
                if not isinstance(unit, dict):
                    continue
                status = unit.get("maintenance_status")
                in_maintenance = status in self._MM_ACTIVE_STATUSES
                entry = {
                    "name": unit.get("name", name),
                    "type": unit_type,
                    "maintenance_status": status or "N/A",
                    "in_maintenance": in_maintenance,
                    "origin": unit.get("origin", "N/A"),
                    "all_instances": unit.get("all_instances", False),
                    "shutdown_delay_timer": unit.get("shutdown_delay_timer", "N/A"),
                    "description": unit.get("description", ""),
                }
                if unit_type == "bgp":
                    entry["bgp_shutdown_coordination"] = unit.get("bgp_shutdown_coordination", "N/A")
                    peers = unit.get("bgp_peer_vrfs") if isinstance(unit.get("bgp_peer_vrfs"), dict) else {}
                    entry["bgp_peers"] = sorted(peers.keys())
                units.append(entry)
                if in_maintenance:
                    active_units.append(entry)

        configured = bool(profiles) or bool(units)
        active = bool(active_profiles) or bool(active_units)

        if not supported:
            message = (
                "Maintenance Mode is not available on this device: "
                "the resources /system/maintenance_mode_profiles and /system/feature_set_* "
                "are absent (feature not supported)."
            )
        elif not configured:
            message = "Maintenance Mode is supported but no profile or unit is configured."
        elif active:
            message = (
                f"Maintenance Mode is ACTIVE — applied profile(s): "
                f"{', '.join(active_profiles) or 'none'} ; "
                f"unit(s) in maintenance: {len(active_units)}."
            )
        else:
            message = "Maintenance Mode is configured but inactive (no profile applied, no unit in maintenance)."

        return {
            "supported": supported,
            "configured": configured,
            "active": active,
            "active_profiles": active_profiles,
            "active_units": active_units,
            "profiles": profiles,
            "units": units,
            "summary": {
                "profiles_total": len(profiles),
                "profiles_activated": len(active_profiles),
                "units_total": len(units),
                "units_in_maintenance": len(active_units),
            },
            "message": message,
        }

    # ─── VSF (Virtual Switching Framework / stacking) ────────────────────────
    # This platform (openapi.json spec) does not expose a /system/vsf resource.
    # The members of a stack are represented as subsystems of type
    # `chassis` under /system/subsystems. We therefore derive the VSF state from
    # that documented resource.

    async def _get_subsystems(self, types: Optional[tuple[str, ...]] = None) -> list[tuple[str, dict]]:
        """
        List the subsystems (GET /system/subsystems, depth=2), optionally
        filtered by type (e.g. 'chassis'). Return tuples (key, data).
        """
        data = await self._get("/system/subsystems", params={"depth": "2"})
        items: list[tuple[str, dict]] = []
        for key, value in self._collection_items(data):
            if not isinstance(value, dict):
                continue
            stype = value.get("type") or str(key).split(",")[0]
            if types and stype not in types:
                continue
            items.append((str(key), value))
        return items

    def _format_vsf_member(self, key: str, member: dict) -> dict:
        """Normalize a `chassis` subsystem into a VSF stack member."""
        if not isinstance(member, dict):
            member = {}
        # The key of a subsystem has the form "chassis,1" → member 1.
        member_id = key.split(",", 1)[1] if "," in key else key
        product = member.get("product_info") or {}
        res = member.get("resource_utilization") or {}
        phys_mem = res.get("physical_memory")
        used_mem = res.get("used_memory")
        mem_pct = None
        if isinstance(phys_mem, int) and phys_mem > 0 and isinstance(used_mem, int):
            mem_pct = round(used_mem / phys_mem * 100, 1)
        return {
            "member_id": member_id,
            "type": member.get("type", "N/A"),
            "product_name": product.get("product_name", "N/A"),
            "part_number": product.get("part_number", "N/A"),
            "serial_number": product.get("serial_number", "N/A"),
            "device_version": product.get("device_version", "N/A"),
            "mac_address": product.get("base_mac_address", "N/A"),
            "vendor": product.get("vendor", "N/A"),
            "power_granted": member.get("power_granted"),
            "cpu_utilization_pct": res.get("cpu"),
            "cpu_avg_1_min_pct": res.get("cpu_avg_1_min"),
            "cpu_avg_5_min_pct": res.get("cpu_avg_5_min"),
            "memory_utilization_pct": mem_pct,
        }

    async def _get_vsf_members(self) -> list[dict]:
        """
        VSF stack members = subsystems of type `chassis`.
        Return [] if the resource /system/subsystems is not available.
        """
        try:
            chassis = await self._get_subsystems(types=("chassis",))
        except ArubaAPIError as exc:
            if exc.status_code == 404:
                return []
            raise
        members = [self._format_vsf_member(key, value) for key, value in chassis]
        members.sort(key=lambda m: str(m["member_id"]))
        return members

    # --- Dedicated VSF API (openapi_vsf.json) ----------------------------------
    # These resources expose the topology, stack links and split
    # detection, unlike the derivation via /system/subsystems.

    async def _get_vsf_collection(
        self, path: str, depth: str = "2"
    ) -> Optional[list[tuple[str, Any]]]:
        """Retrieve a VSF collection, or None if the resource is absent or not
        exposed on this platform. Depending on the AOS-CX version / platform, an
        unsupported VSF resource can surface as a 404, or as a 400 whose body
        says the resource is 'not found', 'private' (e.g. "resource VSF_Member is
        private") or 'not supported'. All of these mean: VSF API not available."""
        try:
            data = await self._get(path, params={"depth": depth})
        except ArubaAPIError as exc:
            if exc.status_code == 404:
                return None
            if exc.status_code in (400, 405) and any(
                token in str(exc).lower()
                for token in ("not found", "is private", "not supported", "private")
            ):
                return None
            raise
        return self._collection_items(data)

    async def _get_system_vsf_info(self) -> dict:
        """System-level VSF fields: vsf_status, vsf_config and split-detection
        counters (GET /system, depth=2)."""
        try:
            data = await self._get("/system", params={"depth": "2"})
        except ArubaAPIError:
            return {}
        if not isinstance(data, dict):
            return {}
        return {
            "vsf_status": data.get("vsf_status") or {},
            "vsf_config": data.get("vsf_config") or {},
            "vsf_split_detection_counters": data.get("vsf_split_detection_counters") or {},
            "system_mac": data.get("system_mac") or data.get("base_mac_address", "N/A"),
        }

    def _format_vsf_link(self, link: dict) -> dict:
        """Normalize a VSF_Link resource."""
        if not isinstance(link, dict):
            link = {}
        interfaces = [
            self._ref_name(ref) or ref for ref in (link.get("interfaces") or [])
        ]
        return {
            "link_id": link.get("id"),
            "oper_status": link.get("oper_status", "N/A"),
            "peer_member_id": link.get("peer_member_id"),
            "peer_link_id": link.get("peer_link_id"),
            "interfaces": interfaces,
            "description": link.get("description", ""),
        }

    async def _resolve_member_links(self, member_id: Any, links_field: Any) -> list[dict]:
        """Resolve a member's links: use the already-expanded objects
        (high depth), otherwise query /system/vsf_members/{id}/links."""
        if isinstance(links_field, dict) and links_field:
            expanded = [v for v in links_field.values() if isinstance(v, dict)]
            if expanded:
                links = [self._format_vsf_link(v) for v in expanded]
                links.sort(key=lambda l: (l["link_id"] is None, l["link_id"]))
                return links
        coll = await self._get_vsf_collection(
            f"/system/vsf_members/{member_id}/links", depth="2"
        )
        links = [self._format_vsf_link(v) for _, v in (coll or []) if isinstance(v, dict)]
        links.sort(key=lambda l: (l["link_id"] is None, l["link_id"]))
        return links

    async def _format_vsf_member_api(self, key: str, member: dict) -> dict:
        """Normalize a VSF_Member resource (role, status, memory, links).

        At depth>=3 the member's `subsystems` are inlined; the `chassis`
        subsystem carries the member's hardware identity (serial number,
        part number, product name, base MAC...) which the VSF_Member resource
        does not expose directly. We surface it here.
        """
        if not isinstance(member, dict):
            member = {}
        member_id = member.get("id", key)
        mem = member.get("memory_utilization") or {}
        current = mem.get("current_usage")
        total = mem.get("total_memory")
        mem_pct = None
        if isinstance(current, int) and isinstance(total, int) and total > 0:
            mem_pct = round(current / total * 100, 1)
        links = await self._resolve_member_links(member_id, member.get("links"))
        hardware = self._vsf_member_hardware(member.get("subsystems"))
        return {
            "member_id": member_id,
            "role": member.get("role", "N/A"),
            "status": member.get("status", "N/A"),
            "product_name": hardware["product_name"],
            "product_description": hardware["product_description"],
            "part_number": hardware["part_number"],
            "serial_number": hardware["serial_number"],
            "device_version": hardware["device_version"],
            "mac_address": hardware["mac_address"],
            "vendor": hardware["vendor"],
            "memory_current_usage": current,
            "memory_total": total,
            "memory_utilization_pct": mem_pct,
            "link_count": len(links),
            "links": links,
        }

    @staticmethod
    def _vsf_member_hardware(subsystems: Any) -> dict:
        """Extract a VSF member's hardware identity from its `subsystems`.

        At depth>=3 `subsystems` is a dict keyed by subsystem reference
        (e.g. "chassis,1", "line_card,1/1"). The `chassis` subsystem holds the
        member's real serial number / part number / product name and base MAC.
        Returns a dict with N/A defaults when the data is unavailable (e.g. when
        the resource was fetched at a lower depth and `subsystems` is only a list
        of URIs).
        """
        default = {
            "product_name": "N/A",
            "product_description": "N/A",
            "part_number": "N/A",
            "serial_number": "N/A",
            "device_version": "N/A",
            "mac_address": "N/A",
            "vendor": "N/A",
        }
        if not isinstance(subsystems, dict):
            return default
        chassis = None
        for sub_key, sub_val in subsystems.items():
            if isinstance(sub_val, dict) and str(sub_key).split(",", 1)[0] == "chassis":
                chassis = sub_val
                break
        if not isinstance(chassis, dict):
            return default
        product = chassis.get("product_info") or {}
        if not isinstance(product, dict):
            return default
        return {
            "product_name": product.get("product_name") or "N/A",
            "product_description": product.get("product_description") or "N/A",
            "part_number": product.get("part_number") or "N/A",
            "serial_number": product.get("serial_number") or "N/A",
            "device_version": product.get("device_version") or "N/A",
            "mac_address": product.get("base_mac_address") or "N/A",
            "vendor": product.get("vendor") or "N/A",
        }


    def _format_vsf_topology(self, key: str, topo: dict) -> dict:
        """Normalize a VSF_Topology resource."""
        if not isinstance(topo, dict):
            topo = {}
        return {
            "topology_id": topo.get("id", key),
            "type": topo.get("type", "N/A"),
            "active": topo.get("active"),
            "valid": topo.get("valid"),
        }

    def _build_split_detection(self, sysinfo: dict) -> dict:
        """Build the split-detection block from vsf_status / vsf_config."""
        status = sysinfo.get("vsf_status") or {}
        config = sysinfo.get("vsf_config") or {}
        counters = sysinfo.get("vsf_split_detection_counters") or {}
        return {
            "method": config.get("split_detection_method", "none"),
            "operational_status": status.get("split_detection_operational_status", "N/A"),
            "down_reason": status.get("split_detection_status_down_reason", ""),
            "stack_split_state": status.get("stack_split_state", "N/A"),
            "domain_id": status.get("domain_id", "N/A"),
            "secondary_member": config.get("secondary_member"),
            "traps_enable": config.get("traps_enable"),
            "counters": {
                "rx": counters.get("rx"),
                "rx_drop": counters.get("rx_drop"),
                "tx": counters.get("tx"),
            },
        }

    async def _get_vsf_via_api(self) -> Optional[dict]:
        """Retrieve the full VSF state via the dedicated API, or None if the resource
        /system/vsf_members does not exist on the platform."""
        members_raw = await self._get_vsf_collection("/system/vsf_members", depth="3")
        if members_raw is None:
            return None

        members = [
            await self._format_vsf_member_api(key, value)
            for key, value in members_raw
            if isinstance(value, dict)
        ]
        members.sort(key=lambda m: (m["member_id"] is None, m["member_id"]))

        topo_raw = await self._get_vsf_collection("/system/vsf_topologies", depth="2")
        topologies = [
            self._format_vsf_topology(key, value)
            for key, value in (topo_raw or [])
            if isinstance(value, dict)
        ]
        topologies.sort(key=lambda t: (t["topology_id"] is None, t["topology_id"]))

        sysinfo = await self._get_system_vsf_info()
        vsf_status = sysinfo.get("vsf_status") or {}
        topology_type = vsf_status.get("topology_type", "N/A")

        return {
            "members": members,
            "topologies": topologies,
            "topology_type": topology_type,
            "split_detection": self._build_split_detection(sysinfo),
            "system_mac": sysinfo.get("system_mac", "N/A"),
        }

    async def get_vsf_status(self) -> dict:
        """
        VSF stack state: members (role, status, memory), stack links,
        topology and split detection. Relies on the dedicated VSF API
        (/system/vsf_members, /system/vsf_topologies, vsf_status/vsf_config fields
        of /system). Falls back to /system/subsystems if the VSF API is absent.

        A single member = standalone device, outside a VSF stack.
        """
        api = await self._get_vsf_via_api()
        if api is not None and api["members"]:
            members = api["members"]
            standalone = len(members) == 1
            return {
                "vsf": not standalone,
                "stacked": not standalone,
                "standalone": standalone,
                "source": "/system/vsf_members",
                "system_mac": api["system_mac"],
                "member_count": len(members),
                "members": members,
                "topology_type": api["topology_type"],
                "topologies": api["topologies"],
                "split_detection": api["split_detection"],
                "message": (
                    "Standalone device: a single VSF member."
                    if standalone else
                    f"VSF stack of {len(members)} members."
                ),
            }

        # Fallback: derivation from /system/subsystems (type chassis).
        members = await self._get_vsf_members()
        if not members:
            return {
                "vsf": False,
                "stacked": False,
                "standalone": False,
                "member_count": 0,
                "members": [],
                "message": (
                    "No VSF member found: VSF not available on this device."
                ),
            }

        if len(members) == 1:
            return {
                "vsf": False,
                "stacked": False,
                "standalone": True,
                "source": "/system/subsystems (type=chassis)",
                "member_count": 1,
                "members": members,
                "message": (
                    "Standalone device: a single chassis configured, "
                    "it is not part of a VSF stack."
                ),
            }

        # System (base) MAC from /system if available.
        system_mac = "N/A"
        try:
            system = await self._get("/system", params={"depth": "1"})
            if isinstance(system, dict):
                system_mac = system.get("system_mac") or system.get("base_mac_address", "N/A")
        except ArubaAPIError:
            pass

        return {
            "vsf": True,
            "stacked": True,
            "standalone": False,
            "source": "/system/subsystems (type=chassis)",
            "system_mac": system_mac,
            "member_count": len(members),
            "members": members,
        }

    async def get_vsf_config(self) -> dict:
        """
        VSF configuration: hardware inventory of the members, topology, stack
        links and split-detection configuration. Relies on the dedicated VSF
        API, with a fallback to /system/subsystems if it is absent.
        """
        api = await self._get_vsf_via_api()
        if api is not None and api["members"]:
            members = api["members"]
            standalone = len(members) == 1
            return {
                "vsf": not standalone,
                "stacked": not standalone,
                "standalone": standalone,
                "source": "/system/vsf_members",
                "system_mac": api["system_mac"],
                "member_count": len(members),
                "members": [
                    {
                        "member_id": m["member_id"],
                        "role": m["role"],
                        "status": m["status"],
                        "links": m["links"],
                    }
                    for m in members
                ],
                "topology_type": api["topology_type"],
                "topologies": api["topologies"],
                "split_detection": api["split_detection"],
            }

        # Fallback: derivation from /system/subsystems (type chassis).
        members = await self._get_vsf_members()
        if not members:
            return {
                "vsf": False,
                "stacked": False,
                "standalone": False,
                "member_count": 0,
                "members": [],
                "message": (
                    "No VSF member found: VSF not available on this device."
                ),
            }
        standalone = len(members) == 1
        return {
            "vsf": not standalone,
            "stacked": not standalone,
            "standalone": standalone,
            "source": "/system/subsystems (type=chassis)",
            "member_count": len(members),
            "members": [
                {
                    "member_id": m["member_id"],
                    "product_name": m["product_name"],
                    "part_number": m["part_number"],
                    "serial_number": m["serial_number"],
                    "device_version": m["device_version"],
                    "mac_address": m["mac_address"],
                }
                for m in members
            ],
            "note": (
                "Standalone device: a single chassis, outside a VSF stack."
                if standalone else
                "Topology, VSF links and split-detection not available: the dedicated VSF "
                "API (/system/vsf_members) is absent on this platform."
            ),
        }

    # ─── Containers (on-switch application containers) ────────────────────────

    async def get_containers(self, name: Optional[str] = None) -> dict:
        """
        On-switch application containers (the AOS-CX container hosting feature).

        Source: /system/containers (depth=3 to inline networks/mounts). When a
        `name` is given, only that container is returned.

        If the container feature is absent (resource not present on the
        platform/firmware), return supported=False (not an error). Depending on
        firmware this surfaces as HTTP 404 or HTTP 400 "resource ... not found".
        """
        try:
            raw = await self._get("/system/containers", params={"depth": "3"})
        except ArubaAPIError as exc:
            _absent = exc.status_code == 404 or (
                exc.status_code == 400 and "not found" in str(exc).lower()
            )
            if _absent:
                return {
                    "supported": False,
                    "containers": [],
                    "count": 0,
                    "message": (
                        "On-switch containers are not available on this device: "
                        "the resource /system/containers is absent (feature not "
                        "supported or not configured)."
                    ),
                }
            raise

        containers: list[dict] = []
        for cname, c in self._collection_items(raw):
            if not isinstance(c, dict):
                continue
            if name and c.get("name", cname) != name:
                continue
            # Networks: {vrf_name: {...}} or list of refs.
            nets_raw = c.get("container_networks")
            networks: list[dict] = []
            if isinstance(nets_raw, dict):
                for vrf_key, net in nets_raw.items():
                    entry = {"vrf": self._ref_name(net.get("vrf")) if isinstance(net, dict) else vrf_key}
                    if isinstance(net, dict) and net.get("port_mapping"):
                        entry["port_mapping"] = net["port_mapping"]
                    networks.append(entry)
            constraints = c.get("runtime_constraints") or {}
            containers.append({
                "name": c.get("name", cname),
                "enabled": c.get("enable", False),
                "status": c.get("status", "N/A"),
                "image_status": c.get("image_status", "N/A"),
                "image_version": c.get("image_version", "N/A"),
                "image_location": c.get("image_location", "N/A"),
                "manifest_status": c.get("manifest_status", "N/A"),
                "allow_unsigned_image": c.get("allow_unsigned_image", False),
                "cpu_limit_percent": constraints.get("cpu"),
                "memory_limit_mb": constraints.get("memory"),
                "image_download_vrf": self._ref_name(c.get("image_download_vrf")),
                "networks": networks,
                "error_message": c.get("error_message") or "",
            })

        return {
            "supported": True,
            "containers": containers,
            "count": len(containers),
        }

    # ─── Licensing (feature pack) ─────────────────────────────────────────────

    async def get_feature_pack(self) -> dict:
        """
        Licensing / feature-pack (subscription) state.

        Source: /system/feature_pack. Reports the installed feature pack name,
        type, management mode, validity state, expiration, the designated
        platform/serials, and the per-feature enforcement mode/state.

        If the feature-pack resource is absent (older firmware / unlicensed
        platform), return supported=False (not an error). Depending on firmware
        this surfaces as HTTP 404 or HTTP 400 "resource ... not found".
        """
        try:
            fp = await self._get("/system/feature_pack", params={"depth": "3"})
            if not isinstance(fp, dict):
                fp = {}
        except ArubaAPIError as exc:
            _absent = exc.status_code == 404 or (
                exc.status_code == 400 and "not found" in str(exc).lower()
            )
            if _absent:
                return {
                    "supported": False,
                    "installed": False,
                    "features": [],
                    "feature_count": 0,
                    "message": (
                        "Feature-pack (licensing) is not available on this device: "
                        "the resource /system/feature_pack is absent (feature not "
                        "supported on this platform/firmware)."
                    ),
                }
            raise

        # Per-feature activation (features) + operational state (feature_state).
        feat_cfg = fp.get("features") or {}
        feat_state = fp.get("feature_state") or {}
        features: list[dict] = []
        if isinstance(feat_cfg, dict):
            for fname, fdata in feat_cfg.items():
                fdata = fdata if isinstance(fdata, dict) else {}
                state_obj = feat_state.get(fname) if isinstance(feat_state, dict) else None
                features.append({
                    "feature": fname,
                    "description": fdata.get("description", ""),
                    "mode": fdata.get("mode", "N/A"),
                    "enforcement_method": fdata.get("enforcement_method", "N/A"),
                    "state": (state_obj or {}).get("state", "N/A") if isinstance(state_obj, dict) else "N/A",
                })

        serials = fp.get("device_serial_number")
        if isinstance(serials, str):
            serials = [serials]
        elif not isinstance(serials, list):
            serials = []

        state = fp.get("state", "undetermined")
        installed = bool(fp) and state not in ("undetermined", "removed")

        return {
            "supported": True,
            "installed": installed,
            "name": fp.get("name", "N/A"),
            "state": state,
            "feature_pack_type": fp.get("feature_pack_type", "N/A"),
            "management_mode": fp.get("management_mode", "N/A"),
            "platform": fp.get("platform", "N/A"),
            "expiration_date": fp.get("expiration_date", "N/A"),
            "error_reason": fp.get("error_reason", "none"),
            "device_hostname": fp.get("device_hostname", "N/A"),
            "device_mac_address": fp.get("device_mac_address", "N/A"),
            "device_serial_numbers": serials,
            "features": features,
            "feature_count": len(features),
        }

    # ─── Aruba Central (HPE ANW Central) cloud management ─────────────────────

    async def get_aruba_central(self) -> dict:
        """
        HPE ANW Central (formerly Aruba Central) cloud-management connection state.

        Source: /system/hpe_anw_central. Reports whether the switch is connected
        to Central, the instantiation (public / on-premise), how it learned the
        configuration (cli / activate / dhcp), the connected location, the VRF and
        source IP used, plus the operational status (connection state, last
        disconnection reason, Activate connectivity).

        If the Central resource is absent (older firmware / unsupported platform),
        return supported=False (not an error). Depending on firmware this surfaces
        as HTTP 404 or HTTP 400 "resource ... not found".
        """
        try:
            data = await self._get("/system/hpe_anw_central", params={"depth": "2"})
            if not isinstance(data, dict):
                data = {}
        except ArubaAPIError as exc:
            _absent = exc.status_code == 404 or (
                exc.status_code == 400 and "not found" in str(exc).lower()
            )
            if _absent:
                return {
                    "supported": False,
                    "enabled": False,
                    "connected": False,
                    "message": (
                        "HPE ANW Central (Aruba Central) is not available on this "
                        "device: the resource /system/hpe_anw_central is absent "
                        "(feature not supported on this platform/firmware)."
                    ),
                }
            raise

        status = data.get("status") or {}
        central_connection = status.get("central_connection", "N/A")
        instantiation = data.get("central_instantiation", "none")
        source = data.get("central_source", "none")

        return {
            "supported": True,
            "enabled": not data.get("disable", False) and source != "none",
            "connected": central_connection == "connected",
            "instantiation": instantiation,
            "central_source": source,
            "central_source_alternative": data.get("central_source_alternative", "none"),
            "location": data.get("location", "N/A"),
            "location_alternative": data.get("location_alternative", "N/A"),
            "location_connected": status.get("location_connected", "N/A"),
            "activate_server": data.get("activate_server", "N/A"),
            "vrf": self._ref_name(data.get("vrf")) or "N/A",
            "source_ip": data.get("source_ip", "N/A"),
            "connection_status": central_connection,
            "disconnection_reason": status.get("central_disconnection_reason", ""),
            "activate_connection_status": status.get("centralsource_connection", "N/A"),
            "activate_last_connection_time": status.get("centralsource_last_connection_time"),
            "time_synced_with_activate": status.get("time_sync_with_activate"),
        }

    # ─── NAE (Network Analytics Engine) ──────────────────────────────────────

    @staticmethod
    def _decode_nae_script(encoded: Optional[str]) -> Optional[str]:
        """Decode the Base64 content of a NAE script."""
        if not encoded:
            return None
        try:
            return base64.b64decode(encoded).decode("utf-8", errors="replace")
        except Exception:
            return None

    async def _list_nae_scripts_raw(self) -> list[tuple[str, dict]]:
        """Raw list of NAE scripts (depth=2)."""
        data = await self._get("/system/nae_scripts", params={"depth": "2"})
        return [(name, val) for name, val in self._collection_items(data) if isinstance(val, dict)]

    def _format_nae_script(
        self, name: Any, script: dict, detailed: bool = False, include_script: bool = False
    ) -> dict:
        """Normalize a NAE script (status, agents, errors)."""
        if not isinstance(script, dict):
            script = {}
        status = script.get("status") or {}
        agent_names = [n for n, _ in self._collection_items(script.get("nae_agents") or {})]
        result = {
            "name": script.get("name", str(name)),
            "origin": script.get("origin", "N/A"),
            "version": script.get("version", "N/A"),
            "author": script.get("author", "N/A"),
            "description": script.get("description", ""),
            "state": status.get("state", "N/A"),
            "error_description": status.get("error_description"),
            "error_at": status.get("error_at"),
            "agent_count": len(agent_names),
            "agents": agent_names,
        }
        if detailed:
            result["script_checksum"] = status.get("script_checksum")
            result["required_nae_api_version"] = script.get("required_nae_api_version")
            result["tags"] = script.get("tags", [])
            result["aoscx_version_min"] = script.get("aoscx_version_min")
            result["aoscx_version_max"] = script.get("aoscx_version_max")
            # The script content is only returned on explicit request.
            if include_script:
                result["script"] = self._decode_nae_script(script.get("script"))
        return result

    def _format_nae_agent(
        self, script_name: str, agent_name: Any, agent: dict, detailed: bool = False
    ) -> dict:
        """Normalize a NAE agent (state, alert level, errors)."""
        if not isinstance(agent, dict):
            agent = {}
        status = agent.get("status") or {}
        alert_info = agent.get("alert_info") or {}
        result = {
            "name": agent.get("name", str(agent_name)),
            "script": script_name,
            "disabled": agent.get("disabled", False),
            "state": status.get("state", "N/A"),
            "alert_level": status.get("alert_level") or alert_info.get("alert_level"),
            "alert_description": alert_info.get("alert_description"),
            "alert_level_updated_at": status.get("alert_level_updated_at")
            or alert_info.get("alert_level_updated_at"),
            "alerts_count": agent.get("nae_alerts_count", 0),
            "error_description": status.get("error_description"),
            "error_at": status.get("error_at"),
            "executed_at": status.get("executed_at"),
            "last_activity_at": status.get("last_activity_at"),
            "rules_count": agent.get("nae_rules_count", 0),
            "time_series_count": agent.get("nae_time_series_count", 0),
        }
        if detailed:
            result["origin"] = agent.get("origin", "N/A")
            result["statistics"] = agent.get("statistics") or {}
            result["parameters_values"] = agent.get("parameters_values") or {}
            result["local_storage"] = agent.get("local_storage") or {}
            result["monitors"] = [n for n, _ in self._collection_items(agent.get("nae_monitors") or {})]
            result["rules"] = [n for n, _ in self._collection_items(agent.get("nae_rules") or {})]
            result["graphs"] = [n for n, _ in self._collection_items(agent.get("nae_graphs") or {})]
            result["baselines"] = [n for n, _ in self._collection_items(agent.get("nae_baselines") or {})]
            result["watches"] = [n for n, _ in self._collection_items(agent.get("nae_watches") or {})]
        return result

    async def _list_nae_agents_for_script(self, script_name: str) -> list[dict]:
        """Detail of the agents of a given NAE script."""
        encoded = quote(script_name, safe="")
        try:
            listing = await self._get(
                f"/system/nae_scripts/{encoded}/nae_agents", params={"depth": "3"}
            )
        except ArubaAPIError:
            return []

        agents: list[dict] = []
        for agent_name, agent in self._collection_items(listing):
            member = agent if isinstance(agent, dict) and len(agent) > 1 else None
            if member is None:
                try:
                    member = await self._get(
                        f"/system/nae_scripts/{encoded}/nae_agents/{quote(str(agent_name), safe='')}",
                        params={"depth": "2"},
                    )
                except ArubaAPIError:
                    member = agent if isinstance(agent, dict) else {}
            agents.append(self._format_nae_agent(script_name, agent_name, member))
        return agents

    async def get_nae_scripts(self) -> dict:
        """List of installed NAE scripts with their status and number of agents."""
        scripts = await self._list_nae_scripts_raw()
        formatted = [self._format_nae_script(name, script) for name, script in scripts]
        errored = [s for s in formatted if s.get("state") == "ERROR"]
        return {
            "nae_scripts": formatted,
            "count": len(formatted),
            "error_count": len(errored),
        }

    async def get_nae_script(self, name: str, include_script: bool = False) -> dict:
        """
        Detail of a NAE script and validation status.
        include_script: if True, includes the decoded content of the script (disabled by default).
        """
        encoded = quote(name, safe="")
        try:
            data = await self._get(f"/system/nae_scripts/{encoded}", params={"depth": "2"})
        except ArubaAPIError as exc:
            if exc.status_code == 404:
                raise ArubaAPIError(f"NAE script '{name}' not found.", 404) from exc
            raise
        return self._format_nae_script(name, data, detailed=True, include_script=include_script)

    async def get_nae_agents(self, script: Optional[str] = None) -> dict:
        """
        List of NAE agents (policies) with state, alert level and errors.
        If 'script' is provided, limits to the agents of that script.
        """
        if script:
            script_names = [script]
        else:
            script_names = [name for name, _ in await self._list_nae_scripts_raw()]

        all_agents: list[dict] = []
        for sname in script_names:
            all_agents.extend(await self._list_nae_agents_for_script(sname))

        alerting = [a for a in all_agents if a.get("alert_level")]
        errored = [a for a in all_agents if a.get("error_description")]
        disabled = [a for a in all_agents if a.get("disabled")]
        return {
            "nae_agents": all_agents,
            "count": len(all_agents),
            "alerting_count": len(alerting),
            "error_count": len(errored),
            "disabled_count": len(disabled),
        }

    async def get_nae_agent(self, script: str, agent: str) -> dict:
        """Full detail of a NAE agent: status, alerts, errors, statistics, monitors, rules."""
        s_enc = quote(script, safe="")
        a_enc = quote(agent, safe="")
        try:
            data = await self._get(
                f"/system/nae_scripts/{s_enc}/nae_agents/{a_enc}", params={"depth": "2"}
            )
        except ArubaAPIError as exc:
            if exc.status_code == 404:
                raise ArubaAPIError(
                    f"NAE agent '{agent}' not found for script '{script}'.", 404
                ) from exc
            raise
        return self._format_nae_agent(script, agent, data, detailed=True)

    # ─── Configs / Checkpoints ───────────────────────────────────────────────

    async def _get_text(self, path: str, params: dict | None = None, _retried: bool = False) -> str:
        """GET that returns the raw body (text) without JSON parsing."""
        url = f"{self._base_url}{path}"
        await self._ensure_live()
        gen = self._session_gen
        expired = False
        result = ""
        try:
            async with self._session.get(url, params=params, headers={"Content-Type": "application/json"}) as resp:
                if resp.status == 401 and not _retried:
                    expired = True  # re-login + retry once, after releasing the response
                elif resp.status == 401:
                    raise ArubaAPIError("Session expired or not authorized", 401)
                elif resp.status == 404:
                    raise ArubaAPIError(f"Resource not found: {path}", 404)
                elif resp.status not in (200, 204):
                    text = await resp.text()
                    raise ArubaAPIError(f"GET {path} error: {text}", resp.status)
                else:
                    result = await resp.text()
        except RuntimeError as exc:
            if not _retried and self._is_dead_session_error(exc):
                expired = True  # dead pooled session → reconnect + retry once
            else:
                raise ArubaAPIError(f"Session error on GET {path} to {self.host}: {exc}", 502) from exc
        if expired:
            await self._reconnect(gen)
            return await self._get_text(path, params, _retried=True)
        return result

    async def list_configs(self) -> dict:
        """List the available configurations (running-config, startup-config, checkpoints)."""
        checkpoints: list[dict] = []
        try:
            data = await self._get("/configs", params={"details": "true"})
            if isinstance(data, list):
                checkpoints = [c if isinstance(c, dict) else {"name": str(c)} for c in data]
            elif isinstance(data, dict):
                for key, val in data.items():
                    entry = {"name": key}
                    if isinstance(val, dict):
                        entry.update(val)
                    checkpoints.append(entry)
        except ArubaAPIError:
            pass
        checkpoint_names = [c.get("name", "") for c in checkpoints if c.get("name")]
        return {
            "standard": ["running-config", "startup-config"],
            "checkpoints": checkpoints,
            "checkpoint_names": checkpoint_names,
            "checkpoint_count": len(checkpoints),
            "available": ["running-config", "startup-config"] + checkpoint_names,
            "note": (
                "Use get_config(name=...) to retrieve a config, "
                "or compare_configs(config_a=..., config_b=...) to compare two configs."
            ),
        }

    async def list_checkpoints(self) -> dict:
        """
        List only the checkpoints (excludes running-config / startup-config),
        sorted from the most recent to the oldest, with their detailed metadata:
        date, age, author (writer), software version, schema and fingerprint (cli_hash).
        """
        entries: list[dict] = []
        try:
            data = await self._get("/configs", params={"details": "true"})
            if isinstance(data, list):
                entries = [e for e in data if isinstance(e, dict)]
            elif isinstance(data, dict):
                for key, val in data.items():
                    entry = {"name": key}
                    if isinstance(val, dict):
                        entry.update(val)
                    entries.append(entry)
        except ArubaAPIError:
            pass

        now = time.time()
        checkpoints: list[dict] = []
        for e in entries:
            if str(e.get("type", "")).lower() != "checkpoint":
                continue
            unix_date = e.get("unix_date")
            age_seconds = None
            age_human = None
            if isinstance(unix_date, (int, float)) and unix_date > 0:
                age_seconds = int(now - unix_date)
                age_human = self._format_duration(age_seconds)
            checkpoints.append({
                "name": e.get("name", ""),
                "date": e.get("date"),
                "unix_date": unix_date,
                "age_seconds": age_seconds,
                "age": age_human,
                "writer": e.get("writer"),
                "version": e.get("version"),
                "schema_version": e.get("schema_version"),
                "cli_hash": e.get("cli_hash"),
            })

        checkpoints.sort(
            key=lambda c: c.get("unix_date") or 0,
            reverse=True,
        )

        return {
            "checkpoints": checkpoints,
            "count": len(checkpoints),
            "checkpoint_names": [c["name"] for c in checkpoints if c.get("name")],
            "note": (
                "List sorted from the most recent to the oldest. "
                "Use get_config(name=...) for the content, "
                "compare_configs(config_a=..., config_b=...) to compare, "
                "or manage_config(action='restore_checkpoint', name=...) to restore."
            ),
        }

    @staticmethod
    def _format_duration(seconds: int) -> str:
        """Format a duration in seconds into a readable string (days/hours/min)."""
        seconds = int(seconds)
        if seconds < 0:
            seconds = 0
        days, rem = divmod(seconds, 86400)
        hours, rem = divmod(rem, 3600)
        minutes, _ = divmod(rem, 60)
        parts: list[str] = []
        if days:
            parts.append(f"{days}j")
        if hours:
            parts.append(f"{hours}h")
        if minutes and not days:
            parts.append(f"{minutes}min")
        if not parts:
            return "just now"
        return " ".join(parts)

    async def compare_configs(
        self,
        config_a: str = "running-config",
        config_b: str = "startup-config",
        color: bool = True,
        context_lines: int = 3,
    ) -> dict:
        """
        Compare two configurations (running/startup/checkpoint) and produce a
        readable unified diff. color=True: adds ANSI colors to the diff.
        """
        content_a = await self._get_text(f"/configs/{quote(config_a, safe='')}")
        content_b = await self._get_text(f"/configs/{quote(config_b, safe='')}")

        lines_a = content_a.splitlines()
        lines_b = content_b.splitlines()

        if content_a == content_b:
            return {
                "config_a": config_a,
                "config_b": config_b,
                "identical": True,
                "added_count": 0,
                "removed_count": 0,
                "diff": f"Configurations '{config_a}' and '{config_b}' are identical.",
            }

        raw_diff = list(
            difflib.unified_diff(
                lines_a,
                lines_b,
                fromfile=config_a,
                tofile=config_b,
                lineterm="",
                n=context_lines,
            )
        )

        # ANSI colours
        GREEN, RED, CYAN, BOLD, RESET = (
            "\033[32m", "\033[31m", "\033[36m", "\033[1m", "\033[0m"
        )

        added = removed = 0
        plain_lines: list[str] = []
        colored_lines: list[str] = []
        for line in raw_diff:
            if line.startswith("+++") or line.startswith("---"):
                col = f"{BOLD}{line}{RESET}"
            elif line.startswith("@@"):
                col = f"{CYAN}{line}{RESET}"
            elif line.startswith("+"):
                added += 1
                col = f"{GREEN}{line}{RESET}"
            elif line.startswith("-"):
                removed += 1
                col = f"{RED}{line}{RESET}"
            else:
                col = line
            plain_lines.append(line)
            colored_lines.append(col)

        diff_text = "\n".join(colored_lines if color else plain_lines)

        return {
            "config_a": config_a,
            "config_b": config_b,
            "identical": False,
            "added_count": added,
            "removed_count": removed,
            "colored": color,
            "summary": (
                f"{added} line(s) added in '{config_b}', "
                f"{removed} line(s) removed compared to '{config_a}'."
            ),
            "diff": diff_text,
        }

    async def get_config(self, name: str = "running-config", diff: Optional[str] = None, mode: Optional[str] = None) -> dict:
        """Retrieve a CLI configuration (text). diff: compare with another config."""
        params: dict = {}
        if diff:
            params["diff"] = diff
        if mode:
            params["mode"] = mode
        content = await self._get_text(f"/configs/{name}", params=params or None)
        result: dict = {"name": name, "format": "cli-text", "content": content}
        if diff:
            result["diff_with"] = diff
            result["diff_mode"] = mode or "default"
        return result

    async def get_full_config(self, name: str = "running-config") -> dict:
        """Retrieve the full configuration in JSON (REST format)."""
        data = await self._get(f"/fullconfigs/{name}")
        return {"name": name, "format": "json", "config": data}

    # ─── Configuration management: copy / checkpoint / write memory ───────

    # Reserved names that cannot be used as a checkpoint name.
    _RESERVED_CONFIG_NAMES = ("running-config", "startup-config")

    async def _config_names(self) -> dict:
        """Return the existing checkpoint names + the raw metadata."""
        listing = await self.list_configs()
        return {
            "checkpoint_names": listing.get("checkpoint_names", []),
            "checkpoints": listing.get("checkpoints", []),
        }

    async def copy_config(self, from_config: str, to_config: str) -> dict:
        """Copy a configuration to another on the device.

        Endpoint: PUT /configs/{to}?from=/rest/{ver}/configs/{from} (without body).
        `from`/`to` ∈ {running-config, startup-config, <checkpoint name>}.
        Firmware constraints: source ≠ destination; to create a checkpoint,
        the destination must be a NON-existing name."""
        if from_config == to_config:
            raise ArubaAPIError(
                f"Source and destination identical ('{from_config}'): operation refused by the firmware.",
                400,
            )
        from_uri = self._uri(f"/configs/{quote(from_config, safe='')}")
        await self._put(
            f"/configs/{quote(to_config, safe='')}",
            params={"from": from_uri},
        )
        return {
            "status": "ok",
            "from": from_config,
            "to": to_config,
            "note": f"Configuration '{from_config}' copied to '{to_config}'.",
        }

    async def save_config(self) -> dict:
        """'write memory': copy the running-config to the startup-config so that the
        configuration persists across reboots."""
        result = await self.copy_config("running-config", "startup-config")
        result["note"] = "running-config saved to startup-config (write memory)."
        return result

    async def create_checkpoint(self, name: str, source: str = "running-config") -> dict:
        """Create a checkpoint (snapshot) from the running- or startup-config.

        `name` must be a NON-existing name (the firmware refuses to overwrite a
        checkpoint). `source` in {running-config, startup-config}."""
        if name in self._RESERVED_CONFIG_NAMES:
            raise ArubaAPIError(
                f"'{name}' is a reserved name: choose a different checkpoint name.",
                400,
            )
        if source not in self._RESERVED_CONFIG_NAMES:
            raise ArubaAPIError(
                f"source must be 'running-config' or 'startup-config' (received: '{source}').",
                400,
            )
        existing = (await self._config_names())["checkpoint_names"]
        if name in existing:
            raise ArubaAPIError(
                f"Checkpoint '{name}' already exists (the firmware does not allow overwriting). "
                f"Delete it first or use a different name.",
                409,
            )
        result = await self.copy_config(source, name)
        result["checkpoint"] = name
        result["source"] = source
        result["note"] = f"Checkpoint '{name}' created from '{source}'."
        return result

    async def restore_checkpoint(self, name: str, target: str = "running-config") -> dict:
        """Restore a checkpoint to the running- or startup-config.

        `target` in {running-config, startup-config}. Restoring to running-config
        applies the configuration immediately."""
        if target not in self._RESERVED_CONFIG_NAMES:
            raise ArubaAPIError(
                f"target must be 'running-config' or 'startup-config' (received: '{target}').",
                400,
            )
        result = await self.copy_config(name, target)
        result["checkpoint"] = name
        result["target"] = target
        result["note"] = f"Checkpoint '{name}' restored to '{target}'."
        return result

    async def set_auto_checkpoint(self, minutes: int = 10) -> dict:
        """Start an automatic checkpoint (confirmed commit): create a temporary
        checkpoint and arm a timer; if confirm_auto_checkpoint() is not called
        before the deadline, the firmware restores the previous configuration
        (safety net against losing access after a risky change).

        Endpoint: POST /configs/autocheckpoint {minutes} (1 to 60, default 10)."""
        if not isinstance(minutes, int) or not (1 <= minutes <= 60):
            raise ArubaAPIError("minutes must be an integer between 1 and 60.", 400)
        await self._post("/configs/autocheckpoint", body={"minutes": minutes})
        return {
            "status": "armed",
            "minutes": minutes,
            "note": (
                f"Automatic checkpoint armed for {minutes} minute(s). "
                f"Call confirm_auto_checkpoint() before the deadline to validate, "
                f"otherwise the previous configuration will be restored automatically."
            ),
        }

    async def confirm_auto_checkpoint(self) -> dict:
        """Confirm (acknowledge) the pending automatic checkpoint: stop the timer
        and make the change permanent.

        Endpoint: PUT /configs/autocheckpoint (no body)."""
        await self._put("/configs/autocheckpoint")
        return {
            "status": "confirmed",
            "note": "Automatic checkpoint confirmed: the timer is stopped and the configuration is kept.",
        }

    # ─── API brute (debug) ───────────────────────────────────────────────────

    async def get_raw_api(self, path: str, depth: int = 2) -> Any:
        """Raw request to any ArubaOS-CX REST endpoint."""
        if not path.startswith("/"):
            path = "/" + path
        return await self._get(path, params={"depth": str(depth)})

    # ─── Port-Access (802.1X / MAC-Auth) ─────────────────────────────────────

    async def get_port_access_clients(
        self,
        interface: Optional[str] = None,
        auth_method: Optional[str] = None,
        status: Optional[str] = None,
    ) -> dict:
        """
        Status of authenticated clients (equivalent to 'show port-access clients').
        OpenAPI endpoint: GET /system/interfaces/{Interface.name}/port_access_clients
        """
        clients = []
        if interface:
            interface_names = [interface]
        else:
            interfaces = await self._get("/system/interfaces", params={"depth": "1"})
            interface_names = [name for name, _ in self._collection_items(interfaces)]

        for iface_name in interface_names:
            encoded = quote(str(iface_name), safe="")
            try:
                data = await self._get(f"/system/interfaces/{encoded}/port_access_clients", params={"depth": "4"})
            except ArubaAPIError:
                continue

            for entry_name, entry in self._collection_items(data):
                if not isinstance(entry, dict):
                    continue
                port = self._ref_name(entry.get("port")) or iface_name
                # The client's authentication state is carried by 'client_state'.
                state = entry.get("client_state", "N/A")
                # The authentication method is NOT a direct field of the client:
                # it is carried by the child resource auth_attributes (key =
                # authentication_method: dot1x / mac-auth / web-auth…). We keep
                # the effectively authenticated methods, otherwise all those present.
                auth_attrs = entry.get("auth_attributes")
                if not isinstance(auth_attrs, dict):
                    auth_attrs = {}
                methods_authok: list[str] = []
                methods_all: list[str] = []
                username = "N/A"
                eap_method = "N/A"
                for m_key, attr in self._collection_items(auth_attrs):
                    if not isinstance(attr, dict):
                        continue
                    m_name = attr.get("authentication_method", m_key)
                    methods_all.append(m_name)
                    a_state = str(attr.get("auth_state", "")).lower()
                    if a_state == "authenticated":
                        methods_authok.append(m_name)
                    if attr.get("username"):
                        username = attr.get("username")
                    if attr.get("dot1x_eap_method"):
                        eap_method = attr.get("dot1x_eap_method")
                if methods_authok:
                    method = ", ".join(dict.fromkeys(methods_authok))
                elif methods_all:
                    method = ", ".join(dict.fromkeys(methods_all))
                else:
                    method = "N/A"

                if auth_method and auth_method.lower() not in method.lower():
                    continue
                if status and str(state).lower() != status.lower():
                    continue

                mac_raw = entry.get("mac")
                mac_val = self._ref_name(mac_raw) if isinstance(mac_raw, (dict, str)) and mac_raw else entry_name

                clients.append({
                    "mac_address": mac_val,
                    "interface": port,
                    "auth_method": method,
                    "auth_state": state,
                    "vlan_assigned": self._ref_name(entry.get("access_vlan")) if entry.get("access_vlan") else "N/A",
                    "role": self._ref_name(entry.get("applied_role")) if entry.get("applied_role") else "N/A",
                    "role_type": entry.get("applied_role_type", "N/A"),
                    "onboarded_method": entry.get("onboarded_method", "N/A"),
                    "username": username,
                    "eap_method": eap_method,
                    "server_used": self._ref_name(entry.get("authenticating_radius_server")) if entry.get("authenticating_radius_server") else "N/A",
                    "auth_methods_configured": methods_all,
                })

        # Statistics per method
        stats: dict[str, int] = {}
        for c in clients:
            m = c["auth_method"]
            stats[m] = stats.get(m, 0) + 1

        return {
            "clients": clients,
            "count": len(clients),
            "by_method": stats,
            "filters_applied": {
                k: v for k, v in {
                    "interface": interface,
                    "auth_method": auth_method,
                    "status": status,
                }.items() if v
            },
        }

    async def get_port_access_auth_config(self, interface: Optional[str] = None) -> dict:
        """
        Per-port authentication configuration (equivalent to 'show port-access
        ... interface'). Indicates, for each interface, the configured
        authentication methods (802.1X / MAC-Auth / Web-Auth) and whether
        they are enabled.
        OpenAPI endpoint: GET /system/interfaces/{Interface.name}/port_access_auth_configurations
        """
        if interface:
            interface_names = [interface]
        else:
            interfaces = await self._get("/system/interfaces", params={"depth": "1"})
            interface_names = [name for name, _ in self._collection_items(interfaces)]

        ports: list[dict] = []
        for iface_name in interface_names:
            encoded = quote(str(iface_name), safe="")
            try:
                data = await self._get(
                    f"/system/interfaces/{encoded}/port_access_auth_configurations",
                    params={"depth": "2"},
                )
            except ArubaAPIError:
                continue
            methods: list[dict] = []
            for m_key, cfg in self._collection_items(data):
                if not isinstance(cfg, dict):
                    continue
                methods.append({
                    "method": cfg.get("authentication_method", m_key),
                    "enabled": bool(cfg.get("auth_enable", False)),
                    "reauth_enabled": bool(cfg.get("reauth_enable", False)),
                    "reauth_period": cfg.get("reauth_period", "N/A"),
                    "cached_reauth_enabled": bool(cfg.get("cached_reauth_enable", False)),
                    "max_retries": cfg.get("max_retries", "N/A"),
                    "quiet_period": cfg.get("quiet_period", "N/A"),
                    "radius_server_group": self._ref_name(cfg.get("radius_server_group")) if cfg.get("radius_server_group") else "N/A",
                })
            if not methods:
                continue
            enabled_methods = [m["method"] for m in methods if m["enabled"]]
            ports.append({
                "interface": iface_name,
                "methods": methods,
                "enabled_methods": enabled_methods,
            })

        return {
            "ports": ports,
            "count": len(ports),
            "filters_applied": {"interface": interface} if interface else {},
        }

    async def get_port_access_summary(self) -> dict:
        """
        Global summary of the port-access state:
        counters per method, per state and per assigned VLAN.
        """
        full = await self.get_port_access_clients()
        clients = full["clients"]

        by_state: dict[str, int] = {}
        by_vlan:  dict[str, int] = {}
        by_iface: dict[str, int] = {}

        for c in clients:
            s = c["auth_state"]
            v = str(c["vlan_assigned"])
            i = c["interface"]
            by_state[s] = by_state.get(s, 0) + 1
            by_vlan[v]  = by_vlan.get(v, 0) + 1
            by_iface[i] = by_iface.get(i, 0) + 1

        return {
            "total_clients": len(clients),
            "by_auth_method": full["by_method"],
            "by_auth_state": by_state,
            "by_assigned_vlan": by_vlan,
            "top_interfaces": dict(
                sorted(by_iface.items(), key=lambda x: x[1], reverse=True)[:10]
            ),
        }

    async def get_port_access_client_detail(self, interface: str, mac: str) -> dict:
        """
        Full detail of an authenticated client: VLAN, role, history,
        received RADIUS attributes, failure reason, 802.1X statistics.
        """
        enc_iface = quote(interface, safe="")
        enc_mac   = quote(mac, safe="")
        base_url  = f"/system/interfaces/{enc_iface}/port_access_clients/{enc_mac}"

        client = await self._get(base_url, params={"depth": "3"})
        if not isinstance(client, dict):
            raise ArubaAPIError(f"Client '{mac}' not found on {interface}", 404)

        # Auth attributes — one entry per method (dot1x, mac-auth, web-auth…)
        auth_details: list[dict] = []
        try:
            attrs_data = await self._get(f"{base_url}/auth_attributes", params={"depth": "3"})
            for method_key, attr in self._collection_items(attrs_data):
                if not isinstance(attr, dict):
                    continue
                radius_raw = attr.get("radius_attributes")
                auth_details.append({
                    "method": attr.get("authentication_method", method_key),
                    "state": attr.get("auth_state", "N/A"),
                    "failure_reason": attr.get("auth_failure_reason", "N/A"),
                    "username": attr.get("username", "N/A"),
                    "dot1x_eap_method": attr.get("dot1x_eap_method", "N/A"),
                    "radius_attributes": radius_raw if isinstance(radius_raw, dict) else {},
                    "authenticator_statistics": attr.get("authenticator_statistics") if isinstance(attr.get("authenticator_statistics"), dict) else {},
                    "dot1x_authenticator_statistics": attr.get("dot1x_authenticator_statistics") if isinstance(attr.get("dot1x_authenticator_statistics"), dict) else {},
                })
        except ArubaAPIError:
            pass

        return {
            "mac": mac,
            "interface": interface,
            "access_vlan": client.get("access_vlan", "N/A"),
            "applied_role": _uri_tail(client.get("applied_role")) if client.get("applied_role") else "N/A",
            "applied_role_type": client.get("applied_role_type", "N/A"),
            "accounting_session_id": client.get("accounting_session_id", "N/A"),
            "accounting_session_start": client.get("accounting_session_start_time", "N/A"),
            "abp_in_status": client.get("abp_in_status", "N/A"),
            "auth_history": client.get("auth_history", []),
            "auth_details": auth_details,
        }

    # ─── RADIUS ──────────────────────────────────────────────────────────────

    async def get_radius_servers(self, vrf: str = None) -> dict:
        """RADIUS servers: config, reachability, auth/accounting statistics.

        By default (vrf=None) ALL VRFs are searched and the results aggregated:
        RADIUS servers are very often bound to the mgmt VRF, so restricting to the
        'default' VRF alone would miss them and report 0 server. Pass an explicit
        `vrf` only to restrict the lookup to a single VRF."""
        if vrf is None:
            vrfs_raw = await self._get("/system/vrfs", params={"depth": "1"})
            vrf_names = [str(name) for name, _ in self._collection_items(vrfs_raw)]
        else:
            vrf_names = [vrf]
        servers = []
        for vrf_name in vrf_names:
            encoded = quote(str(vrf_name), safe="")
            try:
                data = await self._get(f"/system/vrfs/{encoded}/radius_servers", params={"depth": "2"})
            except ArubaAPIError:
                continue
            for key, srv in self._collection_items(data):
                if not isinstance(srv, dict):
                    continue
                auth_stats  = srv.get("auth_statistics")
                acct_stats  = srv.get("accounting_statistics")
                track_stats = srv.get("tracking_statistics")
                servers.append({
                    "address": srv.get("address", str(key).split(",")[0]),
                    "port": srv.get("port", "N/A"),
                    "port_type": srv.get("port_type", "N/A"),
                    "vrf": vrf_name,
                    "reachability_status": srv.get("reachability_status", "N/A"),
                    "auth_type": srv.get("auth_type", "N/A"),
                    "timeout": srv.get("timeout", "N/A"),
                    "retries": srv.get("retries", "N/A"),
                    "server_group": _uri_tail(srv.get("server_group")) if srv.get("server_group") else "N/A",
                    "clearpass": srv.get("clearpass", False),
                    "port_access": srv.get("port_access", False),
                    "tracking_enable": srv.get("tracking_enable", False),
                    "tracking_mode": srv.get("tracking_mode", "N/A"),
                    "tracking_method": srv.get("tracking_method", "N/A"),
                    "last_tracking_attempted": srv.get("last_tracking_attempted_time", "N/A"),
                    "last_status_changed": srv.get("last_tracking_status_changed_time", "N/A"),
                    "auth_statistics": {
                        "requests":   auth_stats.get("requests",   0) if isinstance(auth_stats, dict) else 0,
                        "responses":  auth_stats.get("responses",  0) if isinstance(auth_stats, dict) else 0,
                        "timeouts":   auth_stats.get("timeouts",   0) if isinstance(auth_stats, dict) else 0,
                        "retries":    auth_stats.get("retries",    0) if isinstance(auth_stats, dict) else 0,
                        "failures":   auth_stats.get("failures",   0) if isinstance(auth_stats, dict) else 0,
                    },
                    "accounting_statistics": {
                        "requests":  acct_stats.get("requests",  0) if isinstance(acct_stats, dict) else 0,
                        "responses": acct_stats.get("responses", 0) if isinstance(acct_stats, dict) else 0,
                        "timeouts":  acct_stats.get("timeouts",  0) if isinstance(acct_stats, dict) else 0,
                    },
                    "tracking_statistics": track_stats if isinstance(track_stats, dict) else {},
                })
        return {"vrf": vrf or "all", "radius_servers": servers, "count": len(servers)}

    # ─── TACACS+ ─────────────────────────────────────────────────────────────

    async def get_tacacs_servers(self, vrf: str = None) -> dict:
        """TACACS+ servers: config, reachability, statistics.

        By default (vrf=None) ALL VRFs are searched and the results aggregated:
        TACACS+ servers are very often bound to the mgmt VRF, so restricting to the
        'default' VRF alone would miss them. Pass an explicit `vrf` only to restrict
        the lookup to a single VRF."""
        if vrf is None:
            vrfs_raw = await self._get("/system/vrfs", params={"depth": "1"})
            vrf_names = [str(name) for name, _ in self._collection_items(vrfs_raw)]
        else:
            vrf_names = [vrf]
        servers = []
        for vrf_name in vrf_names:
            encoded = quote(str(vrf_name), safe="")
            try:
                data = await self._get(f"/system/vrfs/{encoded}/tacacs_servers", params={"depth": "2"})
            except ArubaAPIError:
                continue
            for key, srv in self._collection_items(data):
                if not isinstance(srv, dict):
                    continue
                auth_stats  = srv.get("auth_statistics")
                track_stats = srv.get("tracking_statistics")
                servers.append({
                    "address": srv.get("address", str(key).split(",")[0]),
                    "tcp_port": srv.get("tcp_port", "N/A"),
                    "vrf": vrf_name,
                    "reachability_status": srv.get("reachability_status", "N/A"),
                    "auth_type": srv.get("auth_type", "N/A"),
                    "timeout": srv.get("timeout", "N/A"),
                    "group": _uri_tail(srv.get("group")) if srv.get("group") else "N/A",
                    "default_group_priority": srv.get("default_group_priority", "N/A"),
                    "user_group_priority": srv.get("user_group_priority", "N/A"),
                    "tracking_enable": srv.get("tracking_enable", False),
                    "last_tracking_attempted": srv.get("last_tracking_attempted_time", "N/A"),
                    "last_status_changed": srv.get("last_tracking_status_changed_time", "N/A"),
                    "auth_statistics": {
                        "requests":  auth_stats.get("requests",  0) if isinstance(auth_stats, dict) else 0,
                        "responses": auth_stats.get("responses", 0) if isinstance(auth_stats, dict) else 0,
                        "timeouts":  auth_stats.get("timeouts",  0) if isinstance(auth_stats, dict) else 0,
                        "failures":  auth_stats.get("failures",  0) if isinstance(auth_stats, dict) else 0,
                    },
                    "tracking_statistics": track_stats if isinstance(track_stats, dict) else {},
                })
        return {"vrf": vrf or "all", "tacacs_servers": servers, "count": len(servers)}

    # ─── AAA ─────────────────────────────────────────────────────────────────

    async def get_aaa_authentication(self) -> dict:
        """
        AAA configuration: server groups, authentication order
        (per session type: 802.1x, MAC-auth, mgmt, etc.).
        """
        # Priorities: order in which the groups are consulted
        prios_raw  = await self._get("/system/aaa_server_group_prios", params={"depth": "2"})
        prio_list  = []
        for key, prio in self._collection_items(prios_raw):
            if not isinstance(prio, dict):
                continue
            prio_list.append({
                "session_type":             prio.get("session_type", key),
                "authentication_order":     _extract_group_prios(prio.get("authentication_group_prios")),
                "authorization_order":      _extract_group_prios(prio.get("authorization_group_prios")),
                "accounting_order":         _extract_group_prios(prio.get("accounting_group_prios")),
                "radius_authorize_only_order": _extract_group_prios(prio.get("radius_authorize_only_group_prios")),
            })

        # Defined server groups
        groups_raw = await self._get("/system/aaa_server_groups", params={"depth": "2"})
        groups = []
        for key, grp in self._collection_items(groups_raw):
            if not isinstance(grp, dict):
                continue
            groups.append({
                "name":   grp.get("group_name", key),
                "type":   grp.get("group_type", "N/A"),
                "origin": grp.get("origin", "N/A"),
            })

        return {
            "server_groups":           groups,
            "server_group_count":      len(groups),
            "session_type_priorities": prio_list,
        }

    async def get_aaa_accounting(self, with_logs: bool = False, limit: int = 50) -> dict:
        """
        AAA accounting configuration per session type.
        with_logs=True: also includes the entries of the accounting log.
        """
        attrs_raw = await self._get("/system/aaa_accounting_attributes", params={"depth": "2"})
        configs   = []
        for key, attr in self._collection_items(attrs_raw):
            if not isinstance(attr, dict):
                continue
            configs.append({
                "session_type":                  attr.get("session_type", key),
                "accounting_mode":               attr.get("accounting_mode", "N/A"),
                "interim_update_enable":         attr.get("interim_update_enable", False),
                "interim_update_interval":       attr.get("interim_update_interval", "N/A"),
                "interim_update_onreauth_enable": attr.get("interim_update_onreauth_enable", False),
            })

        result: dict = {"accounting_configs": configs, "config_count": len(configs)}

        if with_logs:
            try:
                logs = await self._get("/logs/accounting", params={"limit": limit})
                result["accounting_logs"]  = logs if isinstance(logs, list) else []
                result["accounting_log_count"] = len(result["accounting_logs"])
            except ArubaAPIError:
                result["accounting_logs"]  = []
                result["accounting_log_count"] = 0

        return result

    # ─── Port-Access Policies / Roles ────────────────────────────────────────

    async def get_port_access_policies(self, policy_name: Optional[str] = None) -> dict:
        """
        Port Access Policies: rules applied to clients (QoS, ACL, redirect…).
        policy_name: if provided, return the detail with the entries.
        """
        if policy_name:
            encoded = quote(policy_name, safe="")
            data = await self._get(f"/system/port_access_policies/{encoded}", params={"depth": "3"})
            return _format_port_access_policy(policy_name, data)
        data = await self._get("/system/port_access_policies", params={"depth": "2"})
        policies = [
            _format_port_access_policy(name, p)
            for name, p in self._collection_items(data)
            if isinstance(p, dict)
        ]
        return {"policies": policies, "count": len(policies)}

    async def get_port_access_roles(self, role_name: Optional[str] = None) -> dict:
        """
        Port Access Roles: profile applied to a client (VLAN, QoS, reauth, policies).
        role_name: if provided, return the full detail.
        """
        if role_name:
            encoded = quote(role_name, safe="")
            data = await self._get(f"/system/port_access_roles/{encoded}", params={"depth": "3"})
            return _format_port_access_role(role_name, data)
        data = await self._get("/system/port_access_roles", params={"depth": "2"})
        roles = [
            _format_port_access_role(name, r)
            for name, r in self._collection_items(data)
            if isinstance(r, dict)
        ]
        return {"roles": roles, "count": len(roles)}

    # ── GBP (Group-Based Policies) ────────────────────────────────────────────

    async def get_port_access_gbps(self, gbp_name: Optional[str] = None) -> dict:
        """
        Group-Based Policies: policy applied between client groups.
        gbp_name: if provided, return the full detail with the entries and actions.
        """
        try:
            if gbp_name:
                encoded = quote(gbp_name, safe="")
                data = await self._get(f"/system/port_access_gbps/{encoded}", params={"depth": "2"})
                entries = await self._fetch_gbp_entries(encoded)
                return _format_port_access_gbp(gbp_name, data, entries)
            data = await self._get("/system/port_access_gbps", params={"depth": "2"})
            result = []
            for name, g in self._collection_items(data):
                if not isinstance(g, dict):
                    continue
                result.append(_format_port_access_gbp(name, g, None))
            return {"gbps": result, "count": len(result)}
        except ArubaAPIError as exc:
            if exc.status_code == 404:
                return {"supported": False, "reason": "GBP not available on this firmware/platform (endpoint /system/port_access_gbps not found)"}
            raise

    async def _fetch_gbp_entries(self, encoded_name: str) -> list[dict]:
        """Retrieve the entries of a GBP with their action sets."""
        entries: list[dict] = []
        try:
            raw = await self._get(
                f"/system/port_access_gbps/{encoded_name}/cfg_entries",
                params={"depth": "2"},
            )
            for seq, entry in self._collection_items(raw):
                if not isinstance(entry, dict):
                    continue
                action_set = entry.get("gbp_action_set")
                if isinstance(action_set, str):
                    try:
                        enc_seq = quote(str(seq), safe="")
                        action_set = await self._get(
                            f"/system/port_access_gbps/{encoded_name}/cfg_entries/{enc_seq}/gbp_action_set",
                            params={"depth": "2"},
                        )
                    except ArubaAPIError:
                        action_set = {}
                entries.append({
                    "sequence": seq,
                    "class": _uri_tail(entry.get("class")) if entry.get("class") else "N/A",
                    "comment": entry.get("comment", ""),
                    "origin": entry.get("origin", "N/A"),
                    "action_set": _format_gbp_action_set(action_set),
                })
        except ArubaAPIError:
            pass
        return entries

    async def get_gbp_role_maps(self) -> dict:
        """
        GBP role name ↔ role-id mapping: useful to interpret the SGT/GBP tags
        assigned to authenticated clients.
        """
        try:
            data = await self._get("/system/gbp_role_name_id_maps", params={"depth": "2"})
        except ArubaAPIError as exc:
            if exc.status_code == 404:
                return {"supported": False, "reason": "GBP role maps not available on this firmware/platform"}
            raise
        maps = []
        for name, m in self._collection_items(data):
            if not isinstance(m, dict):
                maps.append({"role_name": name})
                continue
            maps.append({
                "role_name": m.get("gbp_role_name", name),
                "role_id": m.get("gbp_role_id", "N/A"),
                "origin": m.get("origin", "N/A"),
            })
        return {"role_maps": maps, "count": len(maps)}

    # ── ABP (Application-Based Policies) ─────────────────────────────────────

    async def get_port_access_abps(self, abp_name: Optional[str] = None) -> dict:
        """
        Application-Based Policies: policy based on application recognition (ARC).
        abp_name: if provided, return the full detail with the entries and statistics.
        """
        try:
            if abp_name:
                encoded = quote(abp_name, safe="")
                data = await self._get(f"/system/port_access_abps/{encoded}", params={"depth": "2"})
                entries = await self._fetch_abp_entries(encoded)
                return _format_port_access_abp(abp_name, data, entries)
            data = await self._get("/system/port_access_abps", params={"depth": "2"})
            result = []
            for name, a in self._collection_items(data):
                if not isinstance(a, dict):
                    continue
                result.append(_format_port_access_abp(name, a, None))
            return {"abps": result, "count": len(result)}
        except ArubaAPIError as exc:
            if exc.status_code == 404:
                return {"supported": False, "reason": "ABP not available on this firmware/platform (endpoint /system/port_access_abps not found). ARC must be enabled and supported."}
            raise

    async def _fetch_abp_entries(self, encoded_name: str) -> list[dict]:
        """Retrieve the entries of an ABP with their action sets."""
        entries: list[dict] = []
        try:
            raw = await self._get(
                f"/system/port_access_abps/{encoded_name}/cfg_entries",
                params={"depth": "2"},
            )
            for seq, entry in self._collection_items(raw):
                if not isinstance(entry, dict):
                    continue
                action_set = entry.get("abp_action_set")
                if isinstance(action_set, str):
                    try:
                        enc_seq = quote(str(seq), safe="")
                        action_set = await self._get(
                            f"/system/port_access_abps/{encoded_name}/cfg_entries/{enc_seq}/abp_action_set",
                            params={"depth": "2"},
                        )
                    except ArubaAPIError:
                        action_set = {}
                entries.append({
                    "sequence": seq,
                    "class": _uri_tail(entry.get("class")) if entry.get("class") else "N/A",
                    "comment": entry.get("comment", ""),
                    "origin": entry.get("origin", "N/A"),
                    "action_set": _format_abp_action_set(action_set),
                })
        except ArubaAPIError:
            pass
        return entries

    # ── App Recognition (ARC) ─────────────────────────────────────────────────

    async def get_app_recognition(self, include_apps: bool = False) -> dict:
        """
        Application Recognition and Control (ARC): status, mode, possible failure.
        include_apps=True: also includes the list of ARC applications and categories.

        Support (supported) is determined by the presence of the
        /system/app_recognition resource in the /system object: if the reference
        exists, the platform/firmware supports ARC. An HTTP 404 on the resource
        itself means that ARC is supported but NOT configured/enabled — it
        is not a lack of support.
        """
        # 1) Is the feature supported? -> presence of the reference in /system
        supported = False
        try:
            system = await self._get("/system", params={"depth": "1"})
            if isinstance(system, dict) and "app_recognition" in system:
                supported = True
        except ArubaAPIError:
            pass

        # 2) Retrieve the ARC config/state
        try:
            arc_cfg = await self._get("/system/app_recognition", params={"depth": "2"})
        except ArubaAPIError as exc:
            # 404: resource not instantiated but referenced => supported, not configured.
            # 400 '... not found': some platforms (e.g. 8360) do not expose
            # the ARC resource at all => not supported (and not 'not configured').
            not_found_400 = exc.status_code == 400 and "not found" in str(exc).lower()
            if exc.status_code == 404 or not_found_400:
                resource_supported = supported and not not_found_400
                return {
                    "supported": resource_supported,
                    "enabled": False,
                    "configured": False,
                    "status": "not_supported" if not resource_supported else "not_configured",
                    "reason": (
                        "Application Recognition (ARC) is not supported on this "
                        "platform (the /system/app_recognition resource is not exposed)."
                        if not resource_supported else
                        "Application Recognition (ARC) is supported by this platform "
                        "(the /system/app_recognition resource is exposed by the API) but "
                        "is not enabled/configured on this device. Enable ARC then "
                        "reference it in the port-access roles/policies for application visibility."
                    ),
                }
            raise

        result: dict = {
            "supported": True,
            "configured": True,
            "enabled": arc_cfg.get("enable", False) if isinstance(arc_cfg, dict) else False,
            "oper_status_enabled": arc_cfg.get("oper_status_enabled", False) if isinstance(arc_cfg, dict) else False,
            "mode": arc_cfg.get("mode", "N/A") if isinstance(arc_cfg, dict) else "N/A",
            "arc_failure_reason": arc_cfg.get("arc_failure_reason", "") if isinstance(arc_cfg, dict) else "",
            "abp_session_limit_exceed_action": arc_cfg.get("abp_session_limit_exceed_action", "N/A") if isinstance(arc_cfg, dict) else "N/A",
        }
        if include_apps:
            try:
                cats_raw = await self._get("/system/arc_app_categories", params={"depth": "2"})
                categories = []
                for cname, cat in self._collection_items(cats_raw):
                    if isinstance(cat, dict):
                        categories.append({"name": cat.get("name", cname), "description": cat.get("description", "")})
                    else:
                        categories.append({"name": cname})
                result["categories"] = categories
                result["categories_count"] = len(categories)
            except ArubaAPIError:
                result["categories"] = []
            try:
                apps_raw = await self._get("/system/arc_apps", params={"depth": "2"})
                apps = []
                for aname, app in self._collection_items(apps_raw):
                    if isinstance(app, dict):
                        apps.append({
                            "name": app.get("name", aname),
                            "id": app.get("id", "N/A"),
                            "description": app.get("description", ""),
                            "category": _uri_tail(app.get("category")) if app.get("category") else "N/A",
                        })
                    else:
                        apps.append({"name": aname})
                result["apps"] = apps
                result["apps_count"] = len(apps)
            except ArubaAPIError:
                result["apps"] = []
        return result

    # ── Application visibility (Traffic Insight + ARC) ───────────────────────

    @staticmethod
    def _flow_bytes(flow: Any) -> tuple[int, int, int]:
        """Retourne (total, tx, rx) octets d'un flux applicatif (flow_statistics)."""
        stats = flow.get("flow_statistics") if isinstance(flow, dict) else None
        if not isinstance(stats, dict):
            return (0, 0, 0)
        tx = _safe_int(stats.get("bytes_tx"))
        rx = _safe_int(stats.get("bytes_rx"))
        return (tx + rx, tx, rx)

    @staticmethod
    def _flow_packets(flow: Any) -> int:
        stats = flow.get("flow_statistics") if isinstance(flow, dict) else None
        if not isinstance(stats, dict):
            return 0
        return _safe_int(stats.get("packets_tx")) + _safe_int(stats.get("packets_rx"))

    @staticmethod
    def _aggregate_app_flows(flows: list[dict], top_n: int) -> dict:
        """Aggregate application flows into top talkers (client / destination /
        application / category) and produce the detailed list of the largest flows."""
        by_client: dict[str, dict] = {}
        by_dest: dict[str, dict] = {}
        by_app: dict[str, dict] = {}
        by_cat: dict[str, dict] = {}
        detailed: list[dict] = []

        for flow in flows:
            total, tx, rx = ArubaOSCXClient._flow_bytes(flow)
            pkts = ArubaOSCXClient._flow_packets(flow)
            client = flow.get("client_ip") or "N/A"
            dest = flow.get("destination_ip") or "N/A"
            app = flow.get("application_name") or "N/A"
            cat = flow.get("application_category") or "N/A"
            for bucket, key in ((by_client, client), (by_dest, dest), (by_app, app), (by_cat, cat)):
                entry = bucket.setdefault(key, {"bytes": 0, "bytes_tx": 0, "bytes_rx": 0, "packets": 0, "flows": 0})
                entry["bytes"] += total
                entry["bytes_tx"] += tx
                entry["bytes_rx"] += rx
                entry["packets"] += pkts
                entry["flows"] += 1
            detailed.append({
                "client_ip": client,
                "client_role": flow.get("client_role", "N/A"),
                "destination_ip": dest,
                "destination_l4_port": flow.get("destination_l4_port"),
                "protocol": flow.get("protocol"),
                "application_name": app,
                "application_category": cat,
                "application_url": flow.get("application_url") or flow.get("application_description") or "",
                "session_count": flow.get("session_count"),
                "policy_action": flow.get("policy_action", "N/A"),
                "forwarding_status": flow.get("forwarding_status", "N/A"),
                "vrf": _uri_tail(flow.get("vrf")),
                "source_vlan": _uri_tail(flow.get("source_vlan")),
                "bytes": total,
                "bytes_tx": tx,
                "bytes_rx": rx,
                "bytes_human": _human_bytes(total),
                "packets": pkts,
            })

        def _top(bucket: dict[str, dict], label: str) -> list[dict]:
            rows = [
                {label: key, **vals, "bytes_human": _human_bytes(vals["bytes"])}
                for key, vals in bucket.items()
            ]
            rows.sort(key=lambda r: r["bytes"], reverse=True)
            return rows[:top_n]

        detailed.sort(key=lambda f: f["bytes"], reverse=True)
        return {
            "flows_analyzed": len(flows),
            "top_talkers_by_client": _top(by_client, "client_ip"),
            "top_destinations": _top(by_dest, "destination_ip"),
            "top_applications": _top(by_app, "application"),
            "top_application_categories": _top(by_cat, "category"),
            "top_flows": detailed[:top_n],
        }

    @staticmethod
    def _flatten_monitor_reports(matched: Any) -> list[dict]:
        """Flatten the matched_flows structure {statistics_type: {rank: report}} of a
        TopN monitor into a list of reports sorted by type then rank."""
        reports: list[dict] = []
        if not isinstance(matched, dict):
            return reports
        for stat_type, ranks in matched.items():
            if not isinstance(ranks, dict):
                continue
            for rank, rep in ranks.items():
                if not isinstance(rep, dict):
                    continue
                stats = rep.get("statistics") if isinstance(rep.get("statistics"), dict) else {}
                reports.append({
                    "statistics_type": stat_type,
                    "rank": rank,
                    "group_value": rep.get("group_value"),
                    "src_ip": rep.get("src_ip"),
                    "dst_ip": rep.get("dst_ip"),
                    "src_port": rep.get("src_port"),
                    "dst_port": rep.get("dst_port"),
                    "protocol": rep.get("protocol"),
                    "application_name": rep.get("application_name"),
                    "application_category": rep.get("application_category"),
                    "egress_interface": rep.get("egress_interface"),
                    "egress_queue": rep.get("egress_queue"),
                    "statistics": stats,
                })

        def _rank_key(r: dict) -> tuple[str, int]:
            try:
                return (r["statistics_type"], int(r["rank"]))
            except (TypeError, ValueError):
                return (r["statistics_type"], 9999)

        reports.sort(key=_rank_key)
        return reports

    async def get_app_visibility(
        self,
        top_n: int = 10,
        include_flows: bool = True,
        include_monitors: bool = True,
        max_flows: int = 1000,
    ) -> dict:
        """
        Application visibility collector based 100% on the REST APIs (no SSH).

        Steps:
        1. Check the prerequisites:
           - App Recognition (ARC) supported, enabled and operational.
           - Traffic Insight supported and at least one instance enabled.
           - ARC applied on interfaces (`app_recognition_enable`) and/or via
             user-roles (`port_access_app_recognition_enable` on the ports, or
             `app_recognition_enable` on the Port_Access_Role).
        2. If no blocking prerequisite, collect the Traffic Insight application flows
           and return the top talkers (by client, destination, application, category)
           as well as the TopN reports from the Traffic Insight monitors.

        The `blockers` field lists, where applicable, what prevents the collection.
        """
        # ── 1) Prerequisite: App Recognition (ARC) ────────────────────────────
        arc = await self.get_app_recognition(include_apps=False)
        arc_summary = {
            "supported": arc.get("supported", False),
            "enabled": arc.get("enabled", False),
            "oper_status_enabled": arc.get("oper_status_enabled", False),
            "mode": arc.get("mode", "N/A"),
            "arc_failure_reason": arc.get("arc_failure_reason", ""),
            "status": arc.get("status", "configured" if arc.get("configured") else "n/a"),
        }

        # ── 2) Prerequisite: Traffic Insight ──────────────────────────────────
        ti: dict = {"supported": False, "enabled": False, "instances": []}
        try:
            ti_raw = await self._get("/system/traffic_insights", params={"depth": "2"})
            ti["supported"] = True
            for name, inst in self._collection_items(ti_raw):
                if not isinstance(inst, dict):
                    continue
                enabled = bool(inst.get("enable"))
                ti["instances"].append({
                    "name": inst.get("name", name),
                    "enabled": enabled,
                    "origin": inst.get("origin", "N/A"),
                    "source": inst.get("source", []),
                })
                if enabled:
                    ti["enabled"] = True
        except ArubaAPIError as exc:
            if exc.status_code != 404:
                raise
            # 404 => resource absent: Traffic Insight not supported/not configured.

        # ── 3) Prerequisite: ARC applied on interfaces ──────────────────────────
        arc_ifaces: dict = {"enabled_count": 0, "interfaces": []}
        try:
            ifaces_raw = await self._get(
                "/system/interfaces",
                params={
                    "depth": "2",
                    "attributes": "name,type,app_recognition_enable,port_access_app_recognition_enable",
                },
            )
            for name, iface in self._collection_items(ifaces_raw):
                if not isinstance(iface, dict):
                    continue
                direct = bool(iface.get("app_recognition_enable"))
                via_role = bool(iface.get("port_access_app_recognition_enable"))
                if direct or via_role:
                    arc_ifaces["interfaces"].append({
                        "interface": iface.get("name", name),
                        "type": iface.get("type", "N/A"),
                        "app_recognition_enable": direct,
                        "port_access_app_recognition_enable": via_role,
                        "source": "interface" if direct else "user-role",
                    })
            arc_ifaces["enabled_count"] = len(arc_ifaces["interfaces"])
        except ArubaAPIError as exc:
            arc_ifaces["error"] = str(exc)

        # ── 4) Prerequisite: ARC applied in user-roles ─────────────────
        arc_roles: dict = {"supported": False, "enabled_count": 0, "roles": []}
        try:
            roles_raw = await self._get(
                "/system/port_access_roles",
                params={"depth": "2", "attributes": "name,origin,app_recognition_enable"},
            )
            arc_roles["supported"] = True
            for name, role in self._collection_items(roles_raw):
                if not isinstance(role, dict):
                    continue
                if bool(role.get("app_recognition_enable")):
                    arc_roles["roles"].append({
                        "name": role.get("name", name),
                        "origin": role.get("origin", "N/A"),
                    })
            arc_roles["enabled_count"] = len(arc_roles["roles"])
        except ArubaAPIError as exc:
            if exc.status_code != 404:
                arc_roles["error"] = str(exc)

        # ── 5) Readiness evaluation ───────────────────
        blockers: list[str] = []
        if not arc_summary["supported"]:
            blockers.append("App Recognition (ARC) is not supported on this platform.")
        elif not arc_summary["enabled"]:
            blockers.append("App Recognition (ARC) is not enabled globally (`app-recognition enable`).")
        elif not arc_summary["oper_status_enabled"]:
            reason = arc_summary["arc_failure_reason"] or "unknown reason"
            blockers.append(
                f"ARC is configured but operationally disabled "
                f"(oper_status_enabled=false; cause: {reason})."
            )

        if not ti["supported"]:
            blockers.append(
                "Traffic Insight is not supported/configured "
                "(resource /system/traffic_insights absent)."
            )
        elif not ti["enabled"]:
            blockers.append("No Traffic Insight instance is enabled (`traffic-insight ... enable`).")

        if arc_ifaces["enabled_count"] == 0 and arc_roles["enabled_count"] == 0:
            blockers.append(
                "App Recognition is not applied on any interface or user-role — "
                "no application data will be collected."
            )

        ready = len(blockers) == 0

        # ── 6) Application data collection ────────────────────────────
        collector: dict = {}

        if include_flows:
            flows: list[dict] = []
            try:
                flows_raw = await self._get(
                    "/system/traffic_insight_application_flows", params={"depth": "2"}
                )
                for _, flow in self._collection_items(flows_raw):
                    if isinstance(flow, dict):
                        flows.append(flow)
                        if len(flows) >= max_flows:
                            break
            except ArubaAPIError as exc:
                if exc.status_code != 404:
                    raise
            collector.update(self._aggregate_app_flows(flows, top_n))
            collector["flows_truncated"] = len(flows) >= max_flows

        if include_monitors:
            monitors: list[dict] = []
            try:
                mon_raw = await self._get(
                    "/system/traffic_insight_monitors", params={"depth": "4"}
                )
                for mname, mon in self._collection_items(mon_raw):
                    if not isinstance(mon, dict):
                        continue
                    oper = mon.get("monitor_operation_status") or {}
                    monitors.append({
                        "monitor_name": mon.get("monitor_name", mname),
                        "monitor_type": mon.get("monitor_type", "N/A"),
                        "group_by": mon.get("group_by", "N/A"),
                        "monitor_n_flows": mon.get("monitor_n_flows"),
                        "instance": self._ref_name(mon.get("traffic_insight_instance")),
                        "origin": mon.get("origin", "N/A"),
                        "status": oper.get("status", "N/A") if isinstance(oper, dict) else "N/A",
                        "reports": self._flatten_monitor_reports(mon.get("matched_flows")),
                    })
            except ArubaAPIError as exc:
                if exc.status_code != 404:
                    raise
            collector["monitors"] = monitors

        return {
            "supported": arc_summary["supported"] and ti["supported"],
            "ready": ready,
            "blockers": blockers,
            "prerequisites": {
                "app_recognition": arc_summary,
                "traffic_insight": ti,
                "arc_interfaces": arc_ifaces,
                "arc_user_roles": arc_roles,
            },
            "collector": collector,
        }

    # ─── Provisioning: VLAN / L2VNI / SVI / trunk ───────────────────────────

    def _uri(self, path: str) -> str:
        """Build the relative URI expected by the API for references
        (e.g. '/rest/v10.17/system/vlans/200')."""
        return f"/rest/{self.api_version}{path}"

    @staticmethod
    def _deep_merge(base: dict, overrides: dict) -> dict:
        """Recursively merge `overrides` into `base` in place and return `base`.
        Nested dicts are merged key by key; scalars and lists replace outright.
        Used for read-modify-write so a sparse update never wipes sibling
        writable attributes the firmware would otherwise reset to default."""
        for key, value in overrides.items():
            if isinstance(value, dict) and isinstance(base.get(key), dict):
                ArubaOSCXClient._deep_merge(base[key], value)
            else:
                base[key] = value
        return base

    async def _read_writable(self, path: str, *, depth: int = 1) -> Optional[dict]:
        """GET the writable configuration of a resource for read-modify-write.
        A plain PUT to AOS-CX replaces the whole writable object, so any attribute
        omitted from the body is reset to its default. Fetching the current
        writable payload first lets the caller merge only its changes and PUT the
        full object back, leaving every other attribute intact. Returns None when
        the resource is absent (404) so the caller can POST-create instead."""
        try:
            data = await self._get(
                path, params={"depth": str(depth), "selector": "writable"})
            return data if isinstance(data, dict) else {}
        except ArubaAPIError as exc:
            if exc.status_code == 404:
                return None
            raise

    async def vlan_exists(self, vlan_id: int) -> bool:
        try:
            await self._get(f"/system/vlans/{vlan_id}", params={"depth": "1"})
            return True
        except ArubaAPIError as exc:
            if exc.status_code == 404:
                return False
            raise

    async def create_vlan(self, vlan_id: int, name: Optional[str] = None,
                          description: Optional[str] = None) -> dict:
        """Create the VLAN if it does not exist (idempotent). Return created/exists."""
        vlan_id = _v_vlan(vlan_id, "vlan_id")
        if await self.vlan_exists(vlan_id):
            return {"vlan": vlan_id, "created": False, "status": "already_exists"}
        body: dict[str, Any] = {
            "id": vlan_id,
            "name": name or f"VLAN{vlan_id}",
            "admin": "up",
            "type": "static",
        }
        if description:
            body["description"] = description
        await self._post("/system/vlans", body)
        return {"vlan": vlan_id, "created": True, "status": "created", "name": body["name"]}

    async def get_fabric_context(self) -> dict:
        """
        Gather the context needed to provision a service on this
        VXLAN/EVPN fabric: VTEP interface, existing VLAN↔VNI mapping, derived VNI
        offset, BGP ASN, Route-Targets template and common active-gateway MAC.

        Also returns `fabric=False` if the device is not a VTEP (no
        virtual_network_ids or vxlan interface).
        """
        # 1. VTEP interface
        try:
            ifaces = await self._get("/system/interfaces", params={"depth": "1"})
        except ArubaAPIError:
            ifaces = {}
        vxlan_ifaces = [k for k in (ifaces.keys() if isinstance(ifaces, dict) else []) if "vxlan" in str(k).lower()]
        vxlan_iface = vxlan_ifaces[0] if vxlan_ifaces else None

        # 2. Existing VNI mappings (configuration)
        try:
            vni_raw = await self._get("/system/virtual_network_ids",
                                      params={"depth": "2", "selector": "configuration"})
            if not isinstance(vni_raw, dict):
                vni_raw = {}
        except ArubaAPIError:
            vni_raw = {}

        vni_by_vlan: dict[int, int] = {}
        l2vni_vnis: list[int] = []
        for _key, cfg in self._collection_items(vni_raw):
            if not isinstance(cfg, dict) or cfg.get("routing"):
                continue
            vni_num = cfg.get("id")
            vlan_refs = cfg.get("vlan") or {}
            vlan_id = next(iter(vlan_refs.keys()), None) if isinstance(vlan_refs, dict) else None
            if vni_num is not None and vlan_id is not None:
                try:
                    vni_by_vlan[int(vlan_id)] = int(vni_num)
                    l2vni_vnis.append(int(vni_num))
                except (TypeError, ValueError):
                    continue

        if not vxlan_iface and not vni_by_vlan:
            return {"fabric": False, "vxlan_interface": None, "vni_by_vlan": {}}

        # 3. Consistent VNI offset (vni - vlan constant?)
        offsets = {vni - vlan for vlan, vni in vni_by_vlan.items()}
        vni_offset = offsets.pop() if len(offsets) == 1 else None

        # 4. BGP ASN (VRF default)
        bgp_asn: Optional[int] = None
        try:
            bgp_routers = await self._get("/system/vrfs/default/bgp_routers", params={"depth": "1"})
            if isinstance(bgp_routers, dict) and bgp_routers:
                bgp_asn = int(next(iter(bgp_routers.keys())))
        except (ArubaAPIError, TypeError, ValueError):
            bgp_asn = None

        # 5. Route-Targets template derived from the existing evpn_vlans
        try:
            evpn_vlans_raw = await self._get("/system/evpn/evpn_vlans",
                                             params={"depth": "2", "selector": "configuration"})
            if not isinstance(evpn_vlans_raw, dict):
                evpn_vlans_raw = {}
        except ArubaAPIError:
            evpn_vlans_raw = {}

        rt_template = self._build_rt_template(evpn_vlans_raw, vni_by_vlan)

        # 6. Common active-gateway MAC (vsx_virtual_gw_mac_v4) of the existing SVIs
        gw_mac = await self._common_active_gw_mac(vni_by_vlan.keys())

        return {
            "fabric": True,
            "vxlan_interface": vxlan_iface or "vxlan1",
            "vni_by_vlan": vni_by_vlan,
            "vni_offset": vni_offset,
            "bgp_asn": bgp_asn,
            "rt_template": rt_template,
            "active_gateway_mac": gw_mac,
            "l2vni_count": len(l2vni_vnis),
        }

    def _build_rt_template(self, evpn_vlans_raw: dict, vni_by_vlan: dict[int, int]) -> Optional[list[dict]]:
        """
        Derive the Route-Targets template from the existing evpn_vlans.
        Each RT "A:B" is analyzed: does part B equal the VLAN ID or the VNI?
        Return a list of {"admin": A, "source": "vlan"|"vni"} (the most
        frequent pattern), or None if nothing usable.
        """
        from collections import Counter
        patterns: Counter = Counter()
        for vlan_key, cfg in self._collection_items(evpn_vlans_raw):
            if not isinstance(cfg, dict):
                continue
            try:
                vlan_id = int(cfg.get("vlan", vlan_key))
            except (TypeError, ValueError):
                continue
            vni = vni_by_vlan.get(vlan_id)
            rts = cfg.get("import_route_targets") or cfg.get("export_route_targets") or []
            signature: list[tuple[str, str]] = []
            for rt in rts:
                if not isinstance(rt, str) or ":" not in rt:
                    continue
                admin, _, value = rt.partition(":")
                try:
                    value_int = int(value)
                except ValueError:
                    continue
                if value_int == vlan_id:
                    source = "vlan"
                elif vni is not None and value_int == vni:
                    source = "vni"
                else:
                    source = "vlan"  # fallback: assume indexed on the VLAN
                signature.append((admin, source))
            if signature:
                patterns[tuple(signature)] += 1
        if not patterns:
            return None
        best, _ = patterns.most_common(1)[0]
        return [{"admin": admin, "source": source} for admin, source in best]

    async def _common_active_gw_mac(self, vlan_ids) -> Optional[str]:
        """Return the active-gateway MAC (vsx_virtual_gw_mac_v4) common to the
        existing SVIs, if a single value emerges."""
        from collections import Counter
        macs: Counter = Counter()
        for vlan_id in list(vlan_ids)[:10]:
            try:
                svi = await self._get(f"/system/interfaces/vlan{vlan_id}",
                                      params={"depth": "1", "selector": "configuration"})
            except ArubaAPIError:
                continue
            mac = svi.get("vsx_virtual_gw_mac_v4") if isinstance(svi, dict) else None
            if mac:
                macs[mac] += 1
        if not macs:
            return None
        return macs.most_common(1)[0][0]

    @staticmethod
    def deduce_route_targets(rt_template: Optional[list[dict]], vlan_id: int,
                             vni: int, bgp_asn: Optional[int]) -> list[str]:
        """Generate the Route-Targets of a new L2VNI from the derived template."""
        if not rt_template:
            # Reasonable fallback: auto-derived RT style 1:<vlan> + <asn>:<vlan>
            rts = [f"1:{vlan_id}"]
            if bgp_asn:
                rts.append(f"{bgp_asn}:{vlan_id}")
            return rts
        rts: list[str] = []
        for entry in rt_template:
            value = vni if entry.get("source") == "vni" else vlan_id
            rts.append(f"{entry['admin']}:{value}")
        return rts

    async def create_l2vni(self, vni: int, vlan_id: int, vxlan_interface: str = "vxlan1") -> dict:
        """Create the L2VNI mapping (virtual_network_id) linking the VNI to the VLAN."""
        vni = _v_vni(vni, "vni")
        vlan_id = _v_vlan(vlan_id, "vlan_id")
        existing = await self._get("/system/virtual_network_ids", params={"depth": "1"})
        key = f"vxlan_vni,{vni}"
        if isinstance(existing, dict) and key in existing:
            return {"vni": vni, "vlan": vlan_id, "created": False, "status": "already_exists"}
        body = {
            "id": vni,
            "type": "vxlan_vni",
            "routing": False,
            "interface": {vxlan_interface: self._uri(f"/system/interfaces/{vxlan_interface}")},
            "vlan": {str(vlan_id): self._uri(f"/system/vlans/{vlan_id}")},
        }
        await self._post("/system/virtual_network_ids", body)
        return {"vni": vni, "vlan": vlan_id, "created": True, "status": "created"}

    async def set_evpn_vlan_rt(self, vlan_id: int, import_rts: list[str],
                               export_rts: list[str], rd: str = "auto") -> dict:
        """Configure the EVPN Route-Targets of the VLAN (create or update evpn_vlans).

        The `vlan` field is a URI reference (not the raw ID): a POST with
        a plain string causes a 500 error on the firmware side.
        """
        vlan_id = _v_vlan(vlan_id, "vlan_id")
        import_rts = [_v_route_target(r, "import_rt") for r in import_rts]
        export_rts = [_v_route_target(r, "export_rt") for r in export_rts]
        if rd not in (None, "auto"):
            rd = _v_route_target(rd, "rd")
        # Creation (POST collection) expects `vlan` as a URI reference.
        create_body = {
            "vlan": self._uri(f"/system/vlans/{vlan_id}"),
            "rd": rd,
            "route_target_auto_mode": "default",
            "import_route_targets": import_rts,
            "export_route_targets": export_rts,
            "redistribute": {"host-route": True},
        }
        # Update (PUT resource) only covers the configuration.
        update_body = {k: v for k, v in create_body.items() if k != "vlan"}

        exists = False
        try:
            await self._get(f"/system/evpn/evpn_vlans/{vlan_id}", params={"depth": "1"})
            exists = True
        except ArubaAPIError as exc:
            if exc.status_code != 404:
                raise
        if exists:
            await self._put(f"/system/evpn/evpn_vlans/{vlan_id}", update_body)
            action = "updated"
        else:
            await self._post("/system/evpn/evpn_vlans", create_body)
            action = "created"
        return {"vlan": vlan_id, "import_route_targets": import_rts,
                "export_route_targets": export_rts, "status": action}


    async def create_svi(self, vlan_id: int, vrf: str, ip_cidr: Optional[str] = None,
                         active_gateway_ip: Optional[str] = None,
                         active_gateway_mac: Optional[str] = None) -> dict:
        """
        Create the SVI interface (interface vlan<id>) routed in the given VRF, with
        optionally an anycast active-gateway (vsx_virtual_ip4 /
        vsx_virtual_gw_mac_v4) identical on all VTEPs.
        """
        vlan_id = _v_vlan(vlan_id, "vlan_id")
        if ip_cidr is not None:
            ip_cidr = _v_ipv4_cidr(ip_cidr, "ip_cidr")
        if active_gateway_ip is not None:
            _v_ipv4_host(str(active_gateway_ip).split("/")[0], "active_gateway_ip")
        if active_gateway_mac is not None:
            active_gateway_mac = _v_mac(active_gateway_mac, "active_gateway_mac")
        name = f"vlan{vlan_id}"
        exists = False
        try:
            await self._get(f"/system/interfaces/{name}", params={"depth": "1"})
            exists = True
        except ArubaAPIError as exc:
            if exc.status_code != 404:
                raise
        body: dict[str, Any] = {
            "name": name,
            "type": "vlan",
            "routing": True,
            "vlan_tag": {str(vlan_id): self._uri(f"/system/vlans/{vlan_id}")},
            "vrf": {vrf: self._uri(f"/system/vrfs/{vrf}")},
            "user_config": {"admin": "up"},
        }
        if ip_cidr:
            body["ip4_address"] = ip_cidr
        if active_gateway_ip:
            gw_ip = active_gateway_ip.split("/")[0]
            body["vsx_virtual_ip4"] = [gw_ip]
            if active_gateway_mac:
                body["vsx_virtual_gw_mac_v4"] = active_gateway_mac
        if exists:
            await self._put(f"/system/interfaces/{name}", body)
            action = "updated"
        else:
            await self._post("/system/interfaces", body)
            action = "created"
        return {"interface": name, "vrf": vrf, "ip4_address": ip_cidr,
                "active_gateway_ip": active_gateway_ip, "status": action}

    async def add_vlan_to_trunk(self, interface: str, vlan_id: int) -> dict:
        """Add the VLAN as tagged on the trunk interface (merges vlan_trunks)."""
        vlan_id = _v_vlan(vlan_id, "vlan_id")
        encoded = quote(interface, safe="")
        current = await self._get(f"/system/interfaces/{encoded}",
                                  params={"depth": "1", "selector": "configuration"})
        if not isinstance(current, dict):
            raise ArubaAPIError(f"Interface '{interface}' not found", 404)
        trunks = dict(current.get("vlan_trunks") or {})
        if str(vlan_id) in trunks:
            return {"interface": interface, "vlan": vlan_id, "status": "already_tagged"}
        trunks[str(vlan_id)] = self._uri(f"/system/vlans/{vlan_id}")
        body = {"vlan_trunks": trunks}
        # If no VLAN mode is set, switch the interface to native-untagged trunk.
        if not current.get("vlan_mode"):
            body["vlan_mode"] = "native-untagged"
        await self._put(f"/system/interfaces/{encoded}", body)
        return {"interface": interface, "vlan": vlan_id, "status": "tagged"}

    async def get_uplink_interfaces(self, neighbor_system_names: Optional[set] = None,
                                    neighbor_hosts: Optional[set] = None) -> list[dict]:
        """
        Identify uplinks via LLDP: interfaces whose neighbor matches
        a device in the inventory (by system-name or management address).
        Returns [{interface, neighbor_system_name, neighbor_mgmt_address}].
        """
        uplinks: list[dict] = []
        data = await self._get("/system/interfaces", params={"depth": "1"})
        for iface_name, _ in self._collection_items(data):
            encoded = quote(str(iface_name), safe="")
            try:
                lldp = await self._get(f"/system/interfaces/{encoded}/lldp_neighbors",
                                       params={"depth": "2"})
            except ArubaAPIError:
                continue
            for _, nbr in self._collection_items(lldp):
                if not isinstance(nbr, dict):
                    continue
                # The neighbor info is nested inside 'neighbor_info'.
                info = nbr.get("neighbor_info") if isinstance(nbr.get("neighbor_info"), dict) else nbr
                sysname = (info.get("chassis_name") or info.get("system_name")
                           or nbr.get("system_name") or "")
                mgmt = (info.get("mgmt_ip_list") or info.get("mgmt_addr")
                        or info.get("management_address") or "")
                match = False
                if neighbor_system_names and sysname:
                    match = any(sysname.lower() == n.lower() or n.lower() in sysname.lower()
                                or sysname.lower() in n.lower()
                                for n in neighbor_system_names)
                if not match and neighbor_hosts and mgmt:
                    match = any(h in str(mgmt) for h in neighbor_hosts)
                if match:
                    uplinks.append({
                        "interface": iface_name,
                        "neighbor_system_name": sysname,
                        "neighbor_mgmt_address": mgmt,
                    })
        return uplinks

    # ─── Provisioning: deletion (rollback / cleanup) ───────────────────

    async def evpn_vlan_exists(self, vlan_id: int) -> bool:
        try:
            await self._get(f"/system/evpn/evpn_vlans/{vlan_id}", params={"depth": "1"})
            return True
        except ArubaAPIError as exc:
            if exc.status_code == 404:
                return False
            raise

    async def svi_exists(self, vlan_id: int) -> bool:
        try:
            await self._get(f"/system/interfaces/vlan{vlan_id}", params={"depth": "1"})
            return True
        except ArubaAPIError as exc:
            if exc.status_code == 404:
                return False
            raise

    async def list_trunks_with_vlan(self, vlan_id: int) -> list[str]:
        """List the interfaces that carry this VLAN as tagged (vlan_trunks)."""
        result: list[str] = []
        data = await self._get("/system/interfaces", params={"depth": "2", "selector": "configuration"})
        for name, iface in self._collection_items(data):
            if not isinstance(iface, dict):
                continue
            trunks = iface.get("vlan_trunks") or {}
            if isinstance(trunks, dict) and str(vlan_id) in trunks:
                result.append(name)
        return result

    async def delete_svi(self, vlan_id: int) -> dict:
        """Delete the SVI interface (interface vlan<id>) if it exists."""
        name = f"vlan{vlan_id}"
        try:
            await self._delete(f"/system/interfaces/{name}")
            return {"interface": name, "deleted": True, "status": "deleted"}
        except ArubaAPIError as exc:
            if exc.status_code == 404:
                return {"interface": name, "deleted": False, "status": "absent"}
            raise

    async def delete_evpn_vlan_rt(self, vlan_id: int) -> dict:
        """Delete the per-VLAN EVPN configuration (RT/RD) if it exists."""
        try:
            await self._delete(f"/system/evpn/evpn_vlans/{vlan_id}")
            return {"vlan": vlan_id, "deleted": True, "status": "deleted"}
        except ArubaAPIError as exc:
            if exc.status_code == 404:
                return {"vlan": vlan_id, "deleted": False, "status": "absent"}
            raise

    async def delete_l2vni(self, vni: int) -> dict:
        """Delete the L2VNI mapping (virtual_network_id) if present."""
        key = quote(f"vxlan_vni,{vni}", safe="")
        try:
            await self._delete(f"/system/virtual_network_ids/{key}")
            return {"vni": vni, "deleted": True, "status": "deleted"}
        except ArubaAPIError as exc:
            if exc.status_code == 404:
                return {"vni": vni, "deleted": False, "status": "absent"}
            raise

    async def delete_vlan(self, vlan_id: int) -> dict:
        """Delete the VLAN if present."""
        try:
            await self._delete(f"/system/vlans/{vlan_id}")
            return {"vlan": vlan_id, "deleted": True, "status": "deleted"}
        except ArubaAPIError as exc:
            if exc.status_code == 404:
                return {"vlan": vlan_id, "deleted": False, "status": "absent"}
            raise

    async def remove_vlan_from_trunk(self, interface: str, vlan_id: int) -> dict:
        """Remove the VLAN from the tagged list (vlan_trunks) of the trunk interface."""
        encoded = quote(interface, safe="")
        try:
            current = await self._get(f"/system/interfaces/{encoded}",
                                      params={"depth": "1", "selector": "configuration"})
        except ArubaAPIError as exc:
            if exc.status_code == 404:
                return {"interface": interface, "vlan": vlan_id, "status": "absent"}
            raise
        if not isinstance(current, dict):
            return {"interface": interface, "vlan": vlan_id, "status": "absent"}
        trunks = dict(current.get("vlan_trunks") or {})
        if str(vlan_id) not in trunks:
            return {"interface": interface, "vlan": vlan_id, "status": "not_tagged"}
        trunks.pop(str(vlan_id))
        await self._put(f"/system/interfaces/{encoded}", {"vlan_trunks": trunks})
        return {"interface": interface, "vlan": vlan_id, "status": "untagged"}

    # ══════════════════════════════════════════════════════════════════════
    # CONFIG DOMAINS (write) — derived from openapi.json + live device shapes
    # ══════════════════════════════════════════════════════════════════════

    # Generic interface helpers ------------------------------------------------

    async def interface_exists(self, name: str) -> bool:
        try:
            await self._get(f"/system/interfaces/{quote(name, safe='')}",
                            params={"depth": "1"})
            return True
        except ArubaAPIError as exc:
            if exc.status_code == 404:
                return False
            raise

    async def delete_interface(self, name: str) -> dict:
        """Delete an interface (loopback / SVI / routed port) if present."""
        try:
            await self._delete(f"/system/interfaces/{quote(name, safe='')}")
            return {"interface": name, "deleted": True, "status": "deleted"}
        except ArubaAPIError as exc:
            if exc.status_code == 404:
                return {"interface": name, "deleted": False, "status": "absent"}
            raise

    # ─── Domain: Loopback ─────────────────────────────────────────────────────

    async def create_loopback(self, name: str, ip_cidr: str,
                              vrf: str = "default") -> dict:
        """Create/update a loopback interface (idempotent). `ip_cidr` e.g.
        10.0.0.1/32. `vrf` attaches the loopback to a non-default VRF."""
        ip_cidr = _v_ipv4_cidr(ip_cidr, "ip_cidr")
        encoded = quote(name, safe="")
        body: dict[str, Any] = {
            "name": name,
            "type": "loopback",
            "routing": True,
            "ip4_address": ip_cidr,
            "user_config": {"admin": "up"},
        }
        if vrf and vrf != "default":
            body["vrf"] = {vrf: self._uri(f"/system/vrfs/{quote(vrf, safe='')}")}
        if await self.interface_exists(name):
            await self._put(f"/system/interfaces/{encoded}",
                            {k: v for k, v in body.items() if k != "name"})
            return {"interface": name, "ip4_address": ip_cidr, "vrf": vrf,
                    "status": "updated"}
        await self._post("/system/interfaces", body)
        return {"interface": name, "ip4_address": ip_cidr, "vrf": vrf,
                "status": "created"}

    # ─── Domain: Routed (L3) port ─────────────────────────────────────────────

    async def configure_routed_interface(self, name: str, *,
                                         ip_cidr: Optional[str] = None,
                                         description: Optional[str] = None,
                                         mtu: Optional[int] = None,
                                         vrf: str = "default",
                                         enable: bool = True,
                                         extra: Optional[dict] = None) -> dict:
        """Turn a physical port into a routed (L3) interface (idempotent).
        Used for point-to-point underlay links (no switchport, /31 or /30 IP).

        Read-modify-write: the current writable payload is fetched first and the
        changes merged into it, so sibling attributes are never wiped. `enable`
        drives `user_config.admin`; `mtu` is applied to BOTH `ip_mtu` (L3) and
        `user_config.mtu` (physical) so the effective MTU actually changes;
        omitting `ip_cidr` keeps the existing IP instead of clearing it."""
        if ip_cidr is not None:
            ip_cidr = _v_ipv4_cidr(ip_cidr, "ip_cidr")
        if mtu is not None:
            mtu = _v_mtu(mtu, "mtu")
        encoded = quote(name, safe="")
        path = f"/system/interfaces/{encoded}"
        body = await self._read_writable(path) or {}
        changes: dict[str, Any] = {
            "routing": True,
            "user_config": {"admin": "up" if enable else "down"},
        }
        if ip_cidr is not None:
            changes["ip4_address"] = ip_cidr
        if description is not None:
            changes["description"] = description
        if mtu is not None:
            changes["ip_mtu"] = int(mtu)
            changes["user_config"]["mtu"] = int(mtu)
        if vrf and vrf != "default":
            body["vrf"] = None  # drop any prior VRF ref before re-binding
            changes["vrf"] = {vrf: self._uri(f"/system/vrfs/{quote(vrf, safe='')}")}
        if extra:
            changes.update({k: v for k, v in extra.items() if v is not None})
        # Switching -> routing transition: clear L2-only attributes the firmware
        # rejects on a routed port (the old sparse PUT dropped them implicitly).
        if not body.get("routing"):
            for l2_key in ("vlan_mode", "vlan_tag"):
                if l2_key in body:
                    body[l2_key] = None
            for l2_key in ("vlan_trunks", "vlan_translations"):
                if l2_key in body:
                    body[l2_key] = {}
        self._deep_merge(body, changes)
        await self._put(path, body)
        return {"interface": name, "ip4_address": body.get("ip4_address"),
                "vrf": vrf, "status": "configured"}

    # ─── Domain: VXLAN (VTEP interface + static peers) ────────────────────────

    async def ensure_vxlan_interface(self, name: str = "vxlan1", *,
                                     source_ip: Optional[str] = None,
                                     dest_udp_port: Optional[int] = None,
                                     inter_vxlan_bridging_mode: Optional[str] = None,
                                     extra: Optional[dict] = None) -> dict:
        """Create/update the VTEP interface. The VTEP source IP lives in
        `options.local_ip`, the UDP port in `options.vxlan_dest_udp_port`.
        `inter_vxlan_bridging_mode` (deny/static-evpn/static-all) drives the
        Scaled Design inter-VxLAN bridging behaviour at the tunnel level."""
        if source_ip is not None:
            _v_ip_host(source_ip, "source_ip")
        if dest_udp_port is not None:
            dest_udp_port = _v_int_range(dest_udp_port, 1, 65535, "dest_udp_port")
        encoded = quote(name, safe="")
        options: dict[str, Any] = {}
        if source_ip is not None:
            options["local_ip"] = source_ip.split("/")[0]
        if dest_udp_port is not None:
            options["vxlan_dest_udp_port"] = str(dest_udp_port)
        body: dict[str, Any] = {}
        if options:
            body["options"] = options
        if inter_vxlan_bridging_mode is not None:
            body["inter_vxlan_bridging_mode"] = inter_vxlan_bridging_mode
        if extra:
            body.update({k: v for k, v in extra.items() if v is not None})
        if await self.interface_exists(name):
            if body:
                await self._put(f"/system/interfaces/{encoded}", body)
            return {"interface": name, "source_ip": options.get("local_ip"),
                    "status": "updated" if body else "already_exists"}
        create_body = {"name": name, "user_config": {"admin": "up"}, **body}
        await self._post("/system/interfaces", create_body)
        return {"interface": name, "source_ip": options.get("local_ip"),
                "status": "created"}

    async def add_static_vxlan_peer(self, destination: str, vnis: list, *,
                                    vxlan_interface: str = "vxlan1",
                                    vrf: str = "default",
                                    origin: str = "static") -> dict:
        """Add/update a static VXLAN tunnel endpoint (non-EVPN headend
        replication). `destination` = remote VTEP IP, `vnis` = list of VNIs
        reachable through this peer."""
        destination = _v_ip_host(destination, "destination")
        vnis = [_v_vni(v, "vni") for v in vnis]
        encoded = quote(vxlan_interface, safe="")
        base = f"/system/interfaces/{encoded}/tunnel_endpoints"
        key = quote(f"{vrf},{origin},{destination}", safe="")
        network_id = [self._uri(f"/system/virtual_network_ids/vxlan_vni,{int(v)}")
                      for v in vnis]
        vrf_ref = {vrf: self._uri(f"/system/vrfs/{quote(vrf, safe='')}")}
        exists = False
        try:
            await self._get(f"{base}/{key}", params={"depth": "1"})
            exists = True
        except ArubaAPIError as exc:
            if exc.status_code != 404:
                raise
        if exists:
            await self._put(f"{base}/{key}", {"network_id": network_id})
            action = "updated"
        else:
            await self._post(base, {
                "destination": destination, "origin": origin,
                "vrf": vrf_ref, "network_id": network_id,
                "interface": {vxlan_interface: self._uri(
                    f"/system/interfaces/{encoded}")},
            })
            action = "created"
        return {"destination": destination, "vrf": vrf, "vnis": [int(v) for v in vnis],
                "interface": vxlan_interface, "status": action}

    async def remove_static_vxlan_peer(self, destination: str, *,
                                       vxlan_interface: str = "vxlan1",
                                       vrf: str = "default",
                                       origin: str = "static") -> dict:
        """Remove a static VXLAN tunnel endpoint if present."""
        destination = _v_ip_host(destination, "destination")
        encoded = quote(vxlan_interface, safe="")
        key = quote(f"{vrf},{origin},{destination}", safe="")
        path = f"/system/interfaces/{encoded}/tunnel_endpoints/{key}"
        try:
            await self._delete(path)
            return {"destination": destination, "deleted": True, "status": "deleted"}
        except ArubaAPIError as exc:
            if exc.status_code == 404:
                return {"destination": destination, "deleted": False,
                        "status": "absent"}
            raise

    # ─── Domain: VRF (RD / RT) ────────────────────────────────────────────────

    async def vrf_exists(self, name: str) -> bool:
        try:
            await self._get(f"/system/vrfs/{quote(name, safe='')}",
                            params={"depth": "1"})
            return True
        except ArubaAPIError as exc:
            if exc.status_code == 404:
                return False
            raise

    async def ensure_vrf(self, name: str, *, vrf_type: str = "user",
                         rd: Optional[str] = None,
                         evpn_import_rts: Optional[list] = None,
                         evpn_export_rts: Optional[list] = None,
                         extra: Optional[dict] = None) -> dict:
        """Create (POST) or update (PUT) a VRF. Idempotent. For Symmetric IRB
        the VRF carries the L3 route-distinguisher (`rd`) and the EVPN
        route-targets (`evpn_import_rts`/`evpn_export_rts`)."""
        if rd is not None:
            rd = _v_route_target(rd, "rd")
        if evpn_import_rts is not None:
            evpn_import_rts = [_v_route_target(r, "evpn_import_rt")
                               for r in evpn_import_rts]
        if evpn_export_rts is not None:
            evpn_export_rts = [_v_route_target(r, "evpn_export_rt")
                               for r in evpn_export_rts]
        config: dict[str, Any] = {}
        if rd is not None:
            config["rd"] = rd
        if evpn_import_rts is not None:
            config["evpn_import_route_targets"] = list(evpn_import_rts)
        if evpn_export_rts is not None:
            config["evpn_export_route_targets"] = list(evpn_export_rts)
        if extra:
            config.update({k: v for k, v in extra.items() if v is not None})
        if await self.vrf_exists(name):
            if config:
                await self._put(f"/system/vrfs/{quote(name, safe='')}", config)
            return {"vrf": name, "status": "updated" if config else "already_exists",
                    "config": config}
        await self._post("/system/vrfs", {"name": name, "type": vrf_type, **config})
        return {"vrf": name, "status": "created", "config": config}

    async def set_vrf_address_family(self, vrf: str,
                                     address_family: str = "ipv4-unicast", *,
                                     import_rts: Optional[list] = None,
                                     export_rts: Optional[list] = None,
                                     extra: Optional[dict] = None) -> dict:
        """Configure per-address-family EVPN route-targets on a VRF (idempotent)."""
        if import_rts is not None:
            import_rts = [_v_route_target(r, "import_rt") for r in import_rts]
        if export_rts is not None:
            export_rts = [_v_route_target(r, "export_rt") for r in export_rts]
        base = f"/system/vrfs/{quote(vrf, safe='')}/vrf_address_families"
        key = quote(address_family, safe="")
        config: dict[str, Any] = {}
        if import_rts is not None:
            config["import_route_targets"] = list(import_rts)
        if export_rts is not None:
            config["export_route_targets"] = list(export_rts)
        if extra:
            config.update({k: v for k, v in extra.items() if v is not None})
        exists = False
        try:
            await self._get(f"{base}/{key}", params={"depth": "1"})
            exists = True
        except ArubaAPIError as exc:
            if exc.status_code != 404:
                raise
        if exists:
            if config:
                await self._put(f"{base}/{key}", config)
            action = "updated" if config else "already_exists"
        else:
            await self._post(base, {"address_family": address_family, **config})
            action = "created"
        return {"vrf": vrf, "address_family": address_family, "status": action}

    async def delete_vrf(self, name: str) -> dict:
        """Delete a VRF if present (refuses reserved default/mgmt VRFs)."""
        if name in ("default", "mgmt", "management"):
            return {"vrf": name, "deleted": False, "status": "reserved"}
        try:
            await self._delete(f"/system/vrfs/{quote(name, safe='')}")
            return {"vrf": name, "deleted": True, "status": "deleted"}
        except ArubaAPIError as exc:
            if exc.status_code == 404:
                return {"vrf": name, "deleted": False, "status": "absent"}
            raise

    # ─── Domain: OSPF (per VRF) ───────────────────────────────────────────────

    async def ensure_ospf_router(self, *, vrf: str = "default", instance_tag: int = 1,
                                 router_id: Optional[str] = None,
                                 passive_interface_default: Optional[bool] = None,
                                 extra: Optional[dict] = None) -> dict:
        """Create/update an OSPF router instance (per VRF). Idempotent."""
        if router_id is not None:
            router_id = _v_ipv4_host(router_id, "router_id")
        base = f"/system/vrfs/{quote(vrf, safe='')}/ospf_routers"
        config: dict[str, Any] = {}
        if router_id is not None:
            config["admin_router_id"] = router_id
        if passive_interface_default is not None:
            config["passive_interface_default"] = bool(passive_interface_default)
        if extra:
            config.update({k: v for k, v in extra.items() if v is not None})
        existing = await self._read_writable(f"{base}/{instance_tag}")
        if existing is not None:
            if config:
                self._deep_merge(existing, config)
                await self._put(f"{base}/{instance_tag}", existing)
            action = "updated" if config else "already_exists"
        else:
            await self._post(base, {"instance_tag": int(instance_tag), **config})
            action = "created"
        return {"instance_tag": instance_tag, "vrf": vrf, "status": action}

    async def ensure_ospf_area(self, area_id: str, *, vrf: str = "default",
                               instance_tag: int = 1,
                               area_type: Optional[str] = None) -> dict:
        """Create/update an OSPF area. `area_id` dotted form e.g. '0.0.0.0'."""
        area_id = _v_ospf_area(area_id, "area_id")
        base = f"/system/vrfs/{quote(vrf, safe='')}/ospf_routers/{instance_tag}/areas"
        config: dict[str, Any] = {}
        if area_type is not None:
            config["area_type"] = area_type
        key = quote(str(area_id), safe="")
        existing = await self._read_writable(f"{base}/{key}")
        if existing is not None:
            if config:
                self._deep_merge(existing, config)
                await self._put(f"{base}/{key}", existing)
            action = "updated" if config else "already_exists"
        else:
            await self._post(base, {"area_id": str(area_id), **config})
            action = "created"
        return {"area_id": area_id, "vrf": vrf, "status": action}

    async def add_ospf_interface(self, interface: str, area_id: str, *,
                                 vrf: str = "default", instance_tag: int = 1,
                                 extra: Optional[dict] = None) -> dict:
        """Attach an interface to an OSPF area (idempotent)."""
        base = (f"/system/vrfs/{quote(vrf, safe='')}/ospf_routers/{instance_tag}"
                f"/areas/{quote(str(area_id), safe='')}/ospf_interfaces")
        key = quote(interface, safe="")
        config: dict[str, Any] = {
            "port": self._uri(f"/system/interfaces/{quote(interface, safe='')}")}
        if extra:
            config.update({k: v for k, v in extra.items() if v is not None})
        existing = await self._read_writable(f"{base}/{key}")
        if existing is not None:
            self._deep_merge(existing, config)
            await self._put(f"{base}/{key}", existing)
            action = "updated"
        else:
            await self._post(base, {"interface_name": interface, **config})
            action = "created"
        return {"interface": interface, "area_id": area_id, "vrf": vrf,
                "status": action}

    # ─── Domain: BGP (per VRF, peer-groups, RR clients, EVPN) ─────────────────

    async def bgp_router_exists(self, asn: int, vrf: str = "default") -> bool:
        try:
            await self._get(f"/system/vrfs/{quote(vrf, safe='')}/bgp_routers/{asn}",
                            params={"depth": "1"})
            return True
        except ArubaAPIError as exc:
            if exc.status_code == 404:
                return False
            raise

    async def ensure_bgp_router(self, asn: int, *, vrf: str = "default",
                                router_id: Optional[str] = None,
                                extra: Optional[dict] = None) -> dict:
        """Create (POST) or update (PUT) the BGP router (per VRF/ASN). Idempotent."""
        asn = _v_asn(asn, "asn")
        if router_id is not None:
            router_id = _v_ipv4_host(router_id, "router_id")
        config: dict[str, Any] = {}
        if router_id is not None:
            config["router_id"] = router_id
        if extra:
            config.update({k: v for k, v in extra.items() if v is not None})
        base = f"/system/vrfs/{quote(vrf, safe='')}/bgp_routers"
        existing = await self._read_writable(f"{base}/{asn}")
        if existing is not None:
            if config:
                self._deep_merge(existing, config)
                await self._put(f"{base}/{asn}", existing)
            return {"asn": asn, "vrf": vrf,
                    "status": "updated" if config else "already_exists"}
        await self._post(base, {"asn": int(asn), **config})
        return {"asn": asn, "vrf": vrf, "status": "created"}

    async def create_bgp_neighbor(self, neighbor: str, asn: int, *,
                                  vrf: str = "default",
                                  remote_as: Optional[int] = None,
                                  is_peer_group: bool = False,
                                  peer_group: Optional[str] = None,
                                  update_source: Optional[str] = None,
                                  local_interface: Optional[str] = None,
                                  activate: Optional[dict] = None,
                                  route_reflector_client: Optional[dict] = None,
                                  send_community: Optional[dict] = None,
                                  next_hop_unchanged: Optional[dict] = None,
                                  description: Optional[str] = None,
                                  password: Optional[str] = None,
                                  bfd_enable: Optional[bool] = None,
                                  ebgp_hop_count: Optional[int] = None,
                                  passive: Optional[bool] = None,
                                  shutdown: Optional[bool] = None,
                                  extra: Optional[dict] = None) -> dict:
        """Create/update a BGP neighbor or peer-group (idempotent).

        `neighbor`: peer IP or peer-group name. `activate`/`route_reflector_client`/
        `send_community`/`next_hop_unchanged` are address-family keyed dicts
        (keys: ipv4-unicast, ipv6-unicast, l2vpn-evpn). `local_interface` is a
        loopback name used as BGP update-source for the overlay."""
        asn = _v_asn(asn, "asn")
        if remote_as is not None:
            remote_as = _v_asn(remote_as, "remote_as")
        if not is_peer_group:
            if re.match(r"^[0-9.]+$", str(neighbor)):
                _v_ipv4_host(neighbor, "neighbor")
            elif ":" in str(neighbor) and re.match(r"^[0-9A-Fa-f:]+$", str(neighbor)):
                _v_ip_host(neighbor, "neighbor")
        base = f"/system/vrfs/{quote(vrf, safe='')}/bgp_routers/{asn}/bgp_neighbors"
        key = quote(neighbor, safe="")
        config: dict[str, Any] = {"is_peer_group": bool(is_peer_group)}
        if remote_as is not None:
            config["remote_as"] = int(remote_as)
        if peer_group is not None:
            config["bgp_peer_group"] = self._uri(
                f"{base}/{quote(peer_group, safe='')}")
        if update_source is not None:
            config["update_source"] = update_source
        if local_interface is not None:
            config["local_interface"] = {local_interface: self._uri(
                f"/system/interfaces/{quote(local_interface, safe='')}")}
        if activate is not None:
            config["activate"] = activate
        if route_reflector_client is not None:
            config["route_reflector_client"] = route_reflector_client
        if send_community is not None:
            config["send_community"] = send_community
        if next_hop_unchanged is not None:
            config["next_hop_unchanged"] = next_hop_unchanged
        if description is not None:
            config["description"] = description
        if password is not None:
            config["password"] = password
        if bfd_enable is not None:
            config["bfd_enable"] = bool(bfd_enable)
        if ebgp_hop_count is not None:
            config["ebgp_hop_count"] = int(ebgp_hop_count)
        if passive is not None:
            config["passive"] = bool(passive)
        if shutdown is not None:
            config["shutdown"] = bool(shutdown)
        if extra:
            config.update({k: v for k, v in extra.items() if v is not None})
        existing = await self._read_writable(f"{base}/{key}")
        if existing is not None:
            self._deep_merge(existing, config)
            await self._put(f"{base}/{key}", existing)
            action = "updated"
        else:
            await self._post(base, {"ip_or_ifname_or_group_name": neighbor, **config})
            action = "created"
        return {"neighbor": neighbor, "asn": asn, "vrf": vrf, "status": action,
                "is_peer_group": bool(is_peer_group)}

    async def delete_bgp_neighbor(self, neighbor: str, asn: int,
                                  vrf: str = "default") -> dict:
        asn = _v_asn(asn, "asn")
        base = f"/system/vrfs/{quote(vrf, safe='')}/bgp_routers/{asn}/bgp_neighbors"
        try:
            await self._delete(f"{base}/{quote(neighbor, safe='')}")
            return {"neighbor": neighbor, "deleted": True, "status": "deleted"}
        except ArubaAPIError as exc:
            if exc.status_code == 404:
                return {"neighbor": neighbor, "deleted": False, "status": "absent"}
            raise

    # ─── Domain: EVPN global + L3VNI ──────────────────────────────────────────

    async def set_evpn_global(self, *,
                              dyn_vxlan_tunnel_bridging_mode: Optional[str] = None,
                              arp_suppression_enable: Optional[bool] = None,
                              nd_suppression_enable: Optional[bool] = None,
                              extra: Optional[dict] = None) -> dict:
        """Create/update the global EVPN config. `dyn_vxlan_tunnel_bridging_mode`
        (no-bridging | ibgp-ebgp) drives the Scaled Design inter-VxLAN bridging."""
        config: dict[str, Any] = {}
        if dyn_vxlan_tunnel_bridging_mode is not None:
            config["dyn_vxlan_tunnel_bridging_mode"] = dyn_vxlan_tunnel_bridging_mode
        if arp_suppression_enable is not None:
            config["arp_suppression_enable"] = bool(arp_suppression_enable)
        if nd_suppression_enable is not None:
            config["nd_suppression_enable"] = bool(nd_suppression_enable)
        if extra:
            config.update({k: v for k, v in extra.items() if v is not None})
        if not config:
            return {"status": "noop"}
        exists = False
        try:
            await self._get("/system/evpn", params={"depth": "1"})
            exists = True
        except ArubaAPIError as exc:
            if exc.status_code != 404:
                raise
        if exists:
            await self._put("/system/evpn", config)
            action = "updated"
        else:
            await self._post("/system/evpn", config)
            action = "created"
        return {"status": action, "config": config}

    async def create_l3vni(self, vni: int, vrf: str,
                           vxlan_interface: str = "vxlan1") -> dict:
        """Create the L3VNI (routing virtual_network_id) bound to a VRF.
        Symmetric IRB: routing=True + vrf reference (no VLAN)."""
        vni = _v_vni(vni, "vni")
        key = f"vxlan_vni,{vni}"
        existing = await self._get("/system/virtual_network_ids", params={"depth": "1"})
        if isinstance(existing, dict) and key in existing:
            return {"vni": vni, "vrf": vrf, "routing": True, "created": False,
                    "status": "already_exists"}
        body = {
            "id": int(vni),
            "type": "vxlan_vni",
            "routing": True,
            "interface": {vxlan_interface: self._uri(
                f"/system/interfaces/{quote(vxlan_interface, safe='')}")},
            "vrf": {vrf: self._uri(f"/system/vrfs/{quote(vrf, safe='')}")},
        }
        await self._post("/system/virtual_network_ids", body)
        return {"vni": vni, "vrf": vrf, "routing": True, "created": True,
                "status": "created"}

    async def delete_vni(self, vni: int) -> dict:
        """Delete any VNI (L2 or L3) mapping. Mirrors delete_l2vni."""
        vni = _v_vni(vni, "vni")
        return await self.delete_l2vni(vni)

    # ─── Domain: Port authentication (802.1X / MAC-Auth) ──────────────────────

    # Logical role name → interface field (URI reference to a Port_Access_Role).
    _PORT_ACCESS_ROLE_BINDINGS = {
        "auth": "port_access_auth_role",
        "fallback": "port_access_fallback_role",
        "guest": "port_access_fallback_role",          # alias of fallback
        "critical": "port_access_critical_auth_role",
        "critical_voice": "port_access_critical_voice_role",
        "reject": "port_access_reject_role",
        "pre_auth": "port_access_pre_auth_role",
        "ubt_fallback": "port_access_ubt_fallback_role",
    }

    # Per-method auth-config scalar fields accepted (passthrough whitelist).
    _PORT_ACCESS_AUTH_FIELDS = {
        "auth_enable", "reauth_enable", "reauth_period", "cached_reauth_enable",
        "cached_reauth_period", "max_retries", "max_requests", "eapol_timeout",
        "quiet_period", "discovery_period", "initial_auth_response_timeout",
        "canned_eap_success_enable", "macsec_enable", "mka_cak_length",
        "radius_server_group",
    }

    async def port_access_role_exists(self, name: str) -> bool:
        try:
            await self._get(f"/system/port_access_roles/{quote(name, safe='')}",
                            params={"depth": "1"})
            return True
        except ArubaAPIError as exc:
            if exc.status_code == 404:
                return False
            raise

    async def create_port_access_role(self, name: str, *,
                                      vlan_tag: Optional[int] = None,
                                      vlan_name_tag: Optional[str] = None,
                                      vlan_trunks: Optional[list] = None,
                                      vlan_name_trunks: Optional[list] = None,
                                      vlan_mode: Optional[str] = None,
                                      description: Optional[str] = None,
                                      gateway_zone: Optional[str] = None,
                                      reauth_period: Optional[int] = None,
                                      captive_portal_profile: Optional[str] = None,
                                      extra: Optional[dict] = None) -> dict:
        """Create (POST) or update (PUT) a Port_Access_Role (user role). Idempotent.
        `extra` passes any other Port_Access_Role field verbatim."""
        config: dict[str, Any] = {}
        if vlan_tag is not None:
            config["vlan_tag"] = _v_vlan(vlan_tag, "vlan_tag")
        if vlan_name_tag is not None:
            config["vlan_name_tag"] = vlan_name_tag
        if vlan_trunks is not None:
            config["vlan_trunks"] = [_v_vlan(v, "vlan_trunk") for v in vlan_trunks]
        if vlan_name_trunks is not None:
            config["vlan_name_trunks"] = list(vlan_name_trunks)
        if vlan_mode is not None:
            config["vlan_mode"] = vlan_mode
        if description is not None:
            config["description"] = description
        if gateway_zone is not None:
            config["gateway_zone"] = gateway_zone
        if reauth_period is not None:
            config["reauth_period"] = int(reauth_period)
        if captive_portal_profile is not None:
            config["captive_portal_profile"] = (
                captive_portal_profile if "/" in captive_portal_profile
                else self._uri("/system/captive_portal_profiles/"
                               f"{quote(captive_portal_profile, safe='')}"))
        if extra:
            config.update({k: v for k, v in extra.items() if v is not None})
        if await self.port_access_role_exists(name):
            if config:
                await self._put(f"/system/port_access_roles/{quote(name, safe='')}",
                                config)
            return {"role": name, "status": "updated" if config else "already_exists",
                    "config": config}
        await self._post("/system/port_access_roles", {"name": name, **config})
        return {"role": name, "status": "created", "config": config}

    async def delete_port_access_role(self, name: str) -> dict:
        try:
            await self._delete(f"/system/port_access_roles/{quote(name, safe='')}")
            return {"role": name, "deleted": True, "status": "deleted"}
        except ArubaAPIError as exc:
            if exc.status_code == 404:
                return {"role": name, "deleted": False, "status": "absent"}
            raise

    async def configure_interface_port_access(self, interface: str, *,
                                              auth_mode: Optional[str] = None,
                                              clients_limit: Optional[int] = None,
                                              mda_data_clients_limit: Optional[int] = None,
                                              concurrent_onboarding: Optional[bool] = None,
                                              radius_override: Optional[bool] = None,
                                              auth_precedence: Optional[list] = None,
                                              auth_priority: Optional[list] = None,
                                              roles: Optional[dict] = None,
                                              extra: Optional[dict] = None) -> dict:
        """Configure interface-level port-access settings (PUT on the interface).

        `roles`: logical→role-name map (auth, fallback/guest, critical,
        critical_voice, reject, pre_auth, ubt_fallback) — each sent as a URI ref.
        `auth_precedence`/`auth_priority`: ordered method list (e.g.
        ["dot1x","mac-auth"]) → {"1":"dot1x","2":"mac-auth"}."""
        encoded = quote(interface, safe="")
        body: dict[str, Any] = {}
        if auth_mode is not None:
            body["port_access_auth_mode"] = auth_mode
        if clients_limit is not None:
            body["port_access_clients_limit"] = int(clients_limit)
        if mda_data_clients_limit is not None:
            body["port_access_mda_data_clients_limit"] = int(mda_data_clients_limit)
        if concurrent_onboarding is not None:
            body["port_access_concurrent_onboarding"] = bool(concurrent_onboarding)
        if radius_override is not None:
            body["aaa_port_access_radius_override_enable"] = bool(radius_override)
        if auth_precedence:
            body["aaa_auth_precedence"] = {
                str(i + 1): m for i, m in enumerate(auth_precedence)}
        if auth_priority:
            body["aaa_auth_priority"] = {
                str(i + 1): m for i, m in enumerate(auth_priority)}
        applied_roles: dict[str, str] = {}
        if roles:
            for logical, role_name in roles.items():
                field = self._PORT_ACCESS_ROLE_BINDINGS.get(logical)
                if not field:
                    raise ArubaAPIError(
                        f"Unknown port-access role binding '{logical}'. "
                        f"Valid: {sorted(self._PORT_ACCESS_ROLE_BINDINGS)}", 400)
                if role_name is None:
                    continue
                body[field] = self._uri(
                    f"/system/port_access_roles/{quote(role_name, safe='')}")
                applied_roles[field] = role_name
        if extra:
            body.update({k: v for k, v in extra.items() if v is not None})
        if not body:
            return {"interface": interface, "status": "noop", "applied": {}}
        await self._put(f"/system/interfaces/{encoded}", body)
        return {"interface": interface, "status": "configured",
                "applied": body, "roles": applied_roles}

    async def clear_interface_port_access(self, interface: str,
                                          fields: Optional[list] = None) -> dict:
        """Reset interface-level port-access bindings (rollback helper)."""
        encoded = quote(interface, safe="")
        if fields is None:
            fields = sorted(set(self._PORT_ACCESS_ROLE_BINDINGS.values())) + [
                "port_access_auth_mode", "port_access_clients_limit",
                "port_access_mda_data_clients_limit",
                "port_access_concurrent_onboarding",
                "aaa_port_access_radius_override_enable",
                "aaa_auth_precedence", "aaa_auth_priority"]
        body = {f: [] for f in fields}
        try:
            await self._put(f"/system/interfaces/{encoded}", body)
            return {"interface": interface, "status": "cleared", "fields": fields}
        except ArubaAPIError as exc:
            if exc.status_code == 404:
                return {"interface": interface, "status": "absent"}
            raise

    async def set_port_access_auth_method(self, interface: str, method: str, *,
                                          auth_enable: bool = True,
                                          extra: Optional[dict] = None) -> dict:
        """Create/update a per-method Port_Access_Auth_Configuration.
        `method`: "dot1x" or "mac-auth". `extra` carries any timer/retry field."""
        encoded = quote(interface, safe="")
        method_key = quote(method, safe="")
        config: dict[str, Any] = {"auth_enable": bool(auth_enable)}
        if extra:
            for k, v in extra.items():
                if v is None:
                    continue
                if k not in self._PORT_ACCESS_AUTH_FIELDS:
                    raise ArubaAPIError(
                        f"Unknown port-access auth field '{k}'. "
                        f"Valid: {sorted(self._PORT_ACCESS_AUTH_FIELDS)}", 400)
                config[k] = v
        base = f"/system/interfaces/{encoded}/port_access_auth_configurations"
        exists = False
        try:
            await self._get(f"{base}/{method_key}", params={"depth": "1"})
            exists = True
        except ArubaAPIError as exc:
            if exc.status_code != 404:
                raise
        if exists:
            await self._put(f"{base}/{method_key}", config)
            action = "updated"
        else:
            await self._post(base, {"authentication_method": method, **config})
            action = "created"
        return {"interface": interface, "method": method, "status": action,
                "config": config}

    async def delete_port_access_auth_method(self, interface: str,
                                             method: str) -> dict:
        encoded = quote(interface, safe="")
        method_key = quote(method, safe="")
        path = (f"/system/interfaces/{encoded}/port_access_auth_configurations/"
                f"{method_key}")
        try:
            await self._delete(path)
            return {"interface": interface, "method": method, "deleted": True,
                    "status": "deleted"}
        except ArubaAPIError as exc:
            if exc.status_code == 404:
                return {"interface": interface, "method": method, "deleted": False,
                        "status": "absent"}
            raise

    # ─── Domain: Application Recognition (ARC) ────────────────────────────────

    async def set_app_recognition(self, *, enable: Optional[bool] = None,
                                  mode: Optional[str] = None,
                                  abp_session_limit_exceed_action: Optional[str] = None,
                                  extra: Optional[dict] = None) -> dict:
        """Create/update the Application Recognition (ARC) feature config.
        Note: /system/app_recognition returns 404 when not yet configured → POST
        to create, PUT to update."""
        config: dict[str, Any] = {}
        if enable is not None:
            config["enable"] = bool(enable)
        if mode is not None:
            config["mode"] = mode
        if abp_session_limit_exceed_action is not None:
            config["abp_session_limit_exceed_action"] = abp_session_limit_exceed_action
        if extra:
            config.update({k: v for k, v in extra.items() if v is not None})
        if not config:
            return {"status": "noop"}
        exists = False
        try:
            await self._get("/system/app_recognition", params={"depth": "1"})
            exists = True
        except ArubaAPIError as exc:
            if exc.status_code != 404:
                raise
        if exists:
            await self._put("/system/app_recognition", config)
            action = "updated"
        else:
            await self._post("/system/app_recognition", config)
            action = "created"
        return {"status": action, "config": config}

    # ─── Domain: EVPN global virtual MAC (System.virtual_mac) ─────────────────

    async def set_virtual_mac(self, mac: str) -> dict:
        """Set the global virtual MAC (System.virtual_mac), used by EVPN Symmetric
        IRB as the router MAC advertised for all symmetric routes. This is NOT the
        VSX system MAC. On a VSX pair, BOTH peers must carry the SAME virtual MAC.
        Idempotent (no-op when already set). Format AA:BB:CC:DD:EE:FF."""
        mac = _v_mac(mac, "virtual_mac")
        current = await self._get(
            "/system", params={"depth": "1", "selector": "configuration",
                                "attributes": "virtual_mac"})
        cur = (current or {}).get("virtual_mac") if isinstance(current, dict) else None
        if cur == mac:
            return {"virtual_mac": mac, "status": "already_exists"}
        await self._put("/system", {"virtual_mac": mac})
        return {"virtual_mac": mac, "previous": cur or None, "status": "configured"}

    # ─── Domain: AAA (RADIUS / TACACS+ / server-groups / global authn+acct) ───

    async def _put_or_post(self, path: str, body: dict) -> str:
        """PUT `body` to a (possibly singleton) resource, falling back to POST
        when the resource does not exist yet (404). Returns 'updated'/'created'."""
        try:
            await self._put(path, body)
            return "updated"
        except ArubaAPIError as exc:
            if exc.status_code == 404:
                await self._post(path, body)
                return "created"
            raise

    def _aaa_group_map(self, groups) -> Optional[dict]:
        """['G1','G2'] -> {"0": <G1 URI>, "1": <G2 URI>} (priority order).
        Pass-through for an explicit dict; None stays None; [] clears the list."""
        if groups is None:
            return None
        if isinstance(groups, dict):
            return groups
        return {str(i): self._uri(
            f"/system/aaa_server_groups/{quote(str(g), safe='')}")
            for i, g in enumerate(groups)}

    async def aaa_server_group_exists(self, name: str) -> bool:
        try:
            await self._get(f"/system/aaa_server_groups/{quote(name, safe='')}",
                            params={"depth": "1"})
            return True
        except ArubaAPIError as exc:
            if exc.status_code == 404:
                return False
            raise

    async def ensure_aaa_server_group(self, name: str,
                                      group_type: str = "tacacs") -> dict:
        """Create a user-defined AAA server group (exclusive to one family).
        group_type: radius | tacacs. Idempotent (no update — group_type is the
        key family and cannot be changed in place)."""
        if group_type not in ("radius", "tacacs", "none", "local"):
            raise ArubaAPIError(
                f"Invalid group_type '{group_type}'. Valid: radius, tacacs.", 400)
        if await self.aaa_server_group_exists(name):
            return {"server_group": name, "group_type": group_type,
                    "status": "already_exists"}
        await self._post("/system/aaa_server_groups",
                         {"group_name": name, "group_type": group_type})
        return {"server_group": name, "group_type": group_type, "status": "created"}

    async def delete_aaa_server_group(self, name: str) -> dict:
        try:
            await self._delete(f"/system/aaa_server_groups/{quote(name, safe='')}")
            return {"server_group": name, "deleted": True, "status": "deleted"}
        except ArubaAPIError as exc:
            if exc.status_code == 404:
                return {"server_group": name, "deleted": False, "status": "absent"}
            raise

    async def ensure_radius_server(self, address: str, *, vrf: str = "mgmt",
                                   passkey: Optional[str] = None,
                                   port: int = 1812, port_type: str = "udp",
                                   accounting_udp_port: Optional[int] = None,
                                   auth_type: Optional[str] = None,
                                   timeout: Optional[int] = None,
                                   retries: Optional[int] = None,
                                   server_group: Optional[dict] = None,
                                   tracking_enable: Optional[bool] = None,
                                   extra: Optional[dict] = None) -> dict:
        """Create/update a RADIUS server in `vrf` (default mgmt — AAA servers
        usually live in the mgmt VRF). Resource key = address,port,port_type.
        `server_group` maps a user server-group name to its priority (int>=1).
        Idempotent."""
        address = _v_ip_host(address, "address")
        port = _v_int_range(port, 1, 65535, "port")
        if port_type not in ("udp", "tcp"):
            raise ArubaAPIError("port_type must be 'udp' or 'tcp'.", 400)
        enc_vrf = quote(vrf, safe="")
        base = f"/system/vrfs/{enc_vrf}/radius_servers"
        key = quote(f"{address},{port},{port_type}", safe="")
        config: dict[str, Any] = {}
        if passkey is not None:
            config["passkey"] = passkey
        if accounting_udp_port is not None:
            config["accounting_udp_port"] = _v_int_range(
                accounting_udp_port, 1, 65535, "accounting_udp_port")
        if auth_type is not None:
            if auth_type not in ("pap", "chap"):
                raise ArubaAPIError("auth_type must be 'pap' or 'chap'.", 400)
            config["auth_type"] = auth_type
        if timeout is not None:
            config["timeout"] = _v_int_range(timeout, 1, 60, "timeout")
        if retries is not None:
            config["retries"] = _v_int_range(retries, 0, 5, "retries")
        if server_group:
            config["server_group"] = {
                self._uri(f"/system/aaa_server_groups/{quote(str(g), safe='')}"): int(p)
                for g, p in server_group.items()}
        if tracking_enable is not None:
            config["tracking_enable"] = bool(tracking_enable)
        if extra:
            config.update({k: v for k, v in extra.items() if v is not None})
        exists = False
        try:
            await self._get(f"{base}/{key}", params={"depth": "1"})
            exists = True
        except ArubaAPIError as exc:
            if exc.status_code != 404:
                raise
        if exists:
            if config:
                await self._put(f"{base}/{key}", config)
            return {"radius_server": address, "vrf": vrf, "port": port,
                    "status": "updated" if config else "already_exists"}
        await self._post(base, {"address": address, "port": port,
                                "port_type": port_type,
                                "vrf": self._uri(f"/system/vrfs/{enc_vrf}"), **config})
        return {"radius_server": address, "vrf": vrf, "port": port,
                "status": "created"}

    async def delete_radius_server(self, address: str, *, vrf: str = "mgmt",
                                   port: int = 1812, port_type: str = "udp") -> dict:
        address = _v_ip_host(address, "address")
        key = quote(f"{address},{int(port)},{port_type}", safe="")
        path = f"/system/vrfs/{quote(vrf, safe='')}/radius_servers/{key}"
        try:
            await self._delete(path)
            return {"radius_server": address, "deleted": True, "status": "deleted"}
        except ArubaAPIError as exc:
            if exc.status_code == 404:
                return {"radius_server": address, "deleted": False,
                        "status": "absent"}
            raise

    async def ensure_tacacs_server(self, address: str, *, vrf: str = "mgmt",
                                   passkey: Optional[str] = None,
                                   tcp_port: int = 49,
                                   auth_type: Optional[str] = None,
                                   timeout: Optional[int] = None,
                                   group: Optional[list] = None,
                                   default_group_priority: int = 1,
                                   user_group_priority: Optional[int] = None,
                                   extra: Optional[dict] = None) -> dict:
        """Create/update a TACACS+ server in `vrf` (default mgmt). Resource key =
        address,tcp_port. `group` = list of AAA server-group names (the built-in
        'tacacs' family group is used when omitted). Idempotent."""
        address = _v_ip_host(address, "address")
        tcp_port = _v_int_range(tcp_port, 1, 65535, "tcp_port")
        enc_vrf = quote(vrf, safe="")
        base = f"/system/vrfs/{enc_vrf}/tacacs_servers"
        key = quote(f"{address},{tcp_port}", safe="")
        group_uris = [self._uri(f"/system/aaa_server_groups/{quote(str(g), safe='')}")
                      for g in (group or ["tacacs"])]
        config: dict[str, Any] = {}
        if passkey is not None:
            config["passkey"] = passkey
        if auth_type is not None:
            if auth_type not in ("pap", "chap"):
                raise ArubaAPIError("auth_type must be 'pap' or 'chap'.", 400)
            config["auth_type"] = auth_type
        if timeout is not None:
            config["timeout"] = _v_int_range(timeout, 1, 60, "timeout")
        if user_group_priority is not None:
            config["user_group_priority"] = int(user_group_priority)
        if extra:
            config.update({k: v for k, v in extra.items() if v is not None})
        exists = False
        try:
            await self._get(f"{base}/{key}", params={"depth": "1"})
            exists = True
        except ArubaAPIError as exc:
            if exc.status_code != 404:
                raise
        if exists:
            body = dict(config)
            if group is not None:
                body["group"] = group_uris
            if body:
                await self._put(f"{base}/{key}", body)
            return {"tacacs_server": address, "vrf": vrf, "tcp_port": tcp_port,
                    "status": "updated" if body else "already_exists"}
        await self._post(base, {"address": address, "tcp_port": tcp_port,
                                "vrf": self._uri(f"/system/vrfs/{enc_vrf}"),
                                "group": group_uris,
                                "default_group_priority": int(default_group_priority),
                                **config})
        return {"tacacs_server": address, "vrf": vrf, "tcp_port": tcp_port,
                "status": "created"}

    async def delete_tacacs_server(self, address: str, *, vrf: str = "mgmt",
                                   tcp_port: int = 49) -> dict:
        address = _v_ip_host(address, "address")
        key = quote(f"{address},{int(tcp_port)}", safe="")
        path = f"/system/vrfs/{quote(vrf, safe='')}/tacacs_servers/{key}"
        try:
            await self._delete(path)
            return {"tacacs_server": address, "deleted": True, "status": "deleted"}
        except ArubaAPIError as exc:
            if exc.status_code == 404:
                return {"tacacs_server": address, "deleted": False,
                        "status": "absent"}
            raise

    async def set_aaa_group_prios(self, session_type: str, *,
                                  authentication: Optional[list] = None,
                                  authorization: Optional[list] = None,
                                  accounting: Optional[list] = None,
                                  radius_authorize_only: Optional[list] = None) -> dict:
        """Set the GLOBAL (per management session-type) AAA server-group order for
        authentication / authorization / accounting (NOT per-interface dot1x).
        session_type: ssh | console | https-server | telnet | gnmi | default.
        Each argument is an ordered list of server-group names (highest priority
        first), e.g. ['MYGRP','local']; pass [] to clear. Idempotent."""
        valid_st = ("ssh", "console", "https-server", "telnet", "gnmi", "default")
        if session_type not in valid_st:
            raise ArubaAPIError(
                f"Invalid session_type '{session_type}'. Valid: {', '.join(valid_st)}.",
                400)
        body: dict[str, Any] = {}
        if authentication is not None:
            body["authentication_group_prios"] = self._aaa_group_map(authentication)
        if authorization is not None:
            body["authorization_group_prios"] = self._aaa_group_map(authorization)
        if accounting is not None:
            body["accounting_group_prios"] = self._aaa_group_map(accounting)
        if radius_authorize_only is not None:
            body["radius_authorize_only_group_prios"] = self._aaa_group_map(
                radius_authorize_only)
        if not body:
            return {"session_type": session_type, "status": "noop"}
        key = quote(session_type, safe="")
        exists = False
        try:
            await self._get(f"/system/aaa_server_group_prios/{key}",
                            params={"depth": "1"})
            exists = True
        except ArubaAPIError as exc:
            if exc.status_code != 404:
                raise
        if exists:
            await self._put(f"/system/aaa_server_group_prios/{key}", body)
            action = "updated"
        else:
            await self._post("/system/aaa_server_group_prios",
                             {"session_type": session_type, **body})
            action = "created"
        return {"session_type": session_type, "status": action, "config": body}

    # ─── Domain: User roles / GBP / ABP (Port-Access policies) ────────────────

    async def set_gbp_role_map(self, role_name: str, role_id: int) -> dict:
        """Create/update a GBP role tag (role-name <-> role-id / SGT). Idempotent."""
        role_id = int(role_id)
        key = quote(role_name, safe="")
        exists = False
        try:
            await self._get(f"/system/gbp_role_name_id_maps/{key}",
                            params={"depth": "1"})
            exists = True
        except ArubaAPIError as exc:
            if exc.status_code != 404:
                raise
        if exists:
            await self._put(f"/system/gbp_role_name_id_maps/{key}",
                            {"gbp_role_id": role_id})
            return {"gbp_role": role_name, "role_id": role_id, "status": "updated"}
        await self._post("/system/gbp_role_name_id_maps",
                         {"gbp_role_name": role_name, "gbp_role_id": role_id})
        return {"gbp_role": role_name, "role_id": role_id, "status": "created"}

    async def delete_gbp_role_map(self, role_name: str) -> dict:
        try:
            await self._delete(
                f"/system/gbp_role_name_id_maps/{quote(role_name, safe='')}")
            return {"gbp_role": role_name, "deleted": True, "status": "deleted"}
        except ArubaAPIError as exc:
            if exc.status_code == 404:
                return {"gbp_role": role_name, "deleted": False, "status": "absent"}
            raise

    async def ensure_port_access_gbp(self, name: str) -> dict:
        """Create the GBP (Group-Based Policy) container if absent. Idempotent."""
        key = quote(name, safe="")
        try:
            await self._get(f"/system/port_access_gbps/{key}", params={"depth": "1"})
            return {"gbp": name, "status": "already_exists"}
        except ArubaAPIError as exc:
            if exc.status_code != 404:
                raise
        await self._post("/system/port_access_gbps", {"name": name})
        return {"gbp": name, "status": "created"}

    async def set_gbp_entry(self, gbp_name: str, sequence_number: int, *,
                            class_name: Optional[str] = None,
                            class_type: str = "gbp",
                            comment: Optional[str] = None,
                            drop: Optional[bool] = None,
                            reflect: Optional[bool] = None) -> dict:
        """Create/update a GBP policy entry. `class_name` references an EXISTING
        Class (type gbp); the action (drop/reflect) is written to the entry's
        action-set. Idempotent."""
        enc = quote(gbp_name, safe="")
        seq = int(sequence_number)
        base = f"/system/port_access_gbps/{enc}/cfg_entries"
        entry: dict[str, Any] = {}
        if class_name is not None:
            entry["class"] = self._uri(
                f"/system/classes/{quote(class_name, safe='')},{class_type}")
        if comment is not None:
            entry["comment"] = comment
        exists = False
        try:
            await self._get(f"{base}/{seq}", params={"depth": "1"})
            exists = True
        except ArubaAPIError as exc:
            if exc.status_code != 404:
                raise
        if exists:
            if entry:
                await self._put(f"{base}/{seq}", entry)
            action = "updated"
        else:
            await self._post(base, {"sequence_number": seq, **entry})
            action = "created"
        action_set: dict[str, Any] = {}
        if drop is not None:
            action_set["drop"] = bool(drop)
        if reflect is not None:
            action_set["reflect"] = bool(reflect)
        if action_set:
            await self._put_or_post(f"{base}/{seq}/gbp_action_set", action_set)
        return {"gbp": gbp_name, "sequence": seq, "status": action,
                "entry": entry, "action_set": action_set}

    async def delete_port_access_gbp(self, name: str) -> dict:
        try:
            await self._delete(f"/system/port_access_gbps/{quote(name, safe='')}")
            return {"gbp": name, "deleted": True, "status": "deleted"}
        except ArubaAPIError as exc:
            if exc.status_code == 404:
                return {"gbp": name, "deleted": False, "status": "absent"}
            raise

    async def ensure_port_access_abp(self, name: str) -> dict:
        """Create the ABP (Application-Based Policy) container if absent. Idempotent."""
        key = quote(name, safe="")
        try:
            await self._get(f"/system/port_access_abps/{key}", params={"depth": "1"})
            return {"abp": name, "status": "already_exists"}
        except ArubaAPIError as exc:
            if exc.status_code != 404:
                raise
        await self._post("/system/port_access_abps", {"name": name})
        return {"abp": name, "status": "created"}

    async def set_abp_entry(self, abp_name: str, sequence_number: int, *,
                            class_name: Optional[str] = None,
                            class_type: str = "application",
                            comment: Optional[str] = None,
                            drop: Optional[bool] = None,
                            dscp: Optional[int] = None,
                            local_priority: Optional[int] = None,
                            mirror: Optional[int] = None) -> dict:
        """Create/update an ABP policy entry. `class_name` references an EXISTING
        Class; the action (drop/dscp/local_priority/mirror) is written to the
        entry's action-set. Idempotent."""
        enc = quote(abp_name, safe="")
        seq = int(sequence_number)
        base = f"/system/port_access_abps/{enc}/cfg_entries"
        entry: dict[str, Any] = {}
        if class_name is not None:
            entry["class"] = self._uri(
                f"/system/classes/{quote(class_name, safe='')},{class_type}")
        if comment is not None:
            entry["comment"] = comment
        exists = False
        try:
            await self._get(f"{base}/{seq}", params={"depth": "1"})
            exists = True
        except ArubaAPIError as exc:
            if exc.status_code != 404:
                raise
        if exists:
            if entry:
                await self._put(f"{base}/{seq}", entry)
            action = "updated"
        else:
            await self._post(base, {"sequence_number": seq, **entry})
            action = "created"
        action_set: dict[str, Any] = {}
        if drop is not None:
            action_set["drop"] = bool(drop)
        if dscp is not None:
            action_set["dscp"] = int(dscp)
        if local_priority is not None:
            action_set["local_priority"] = int(local_priority)
        if mirror is not None:
            action_set["mirror"] = int(mirror)
        if action_set:
            await self._put_or_post(f"{base}/{seq}/abp_action_set", action_set)
        return {"abp": abp_name, "sequence": seq, "status": action,
                "entry": entry, "action_set": action_set}

    async def delete_port_access_abp(self, name: str) -> dict:
        try:
            await self._delete(f"/system/port_access_abps/{quote(name, safe='')}")
            return {"abp": name, "deleted": True, "status": "deleted"}
        except ArubaAPIError as exc:
            if exc.status_code == 404:
                return {"abp": name, "deleted": False, "status": "absent"}
            raise

    # ══════════════════════════════════════════════════════════════════════
    # CONFIG DOMAINS (read / verify) — confirm the applied configuration
    # Each reader uses selector=configuration so it reflects the intended
    # (committed) config, not the operational state. Returns present=False
    # when the object does not exist (HTTP 404).
    # ══════════════════════════════════════════════════════════════════════

    async def _get_config(self, path: str, *, depth: int = 2):
        """GET a resource with selector=configuration. Returns the dict, or
        None when the resource is absent (404)."""
        try:
            return await self._get(
                path, params={"depth": str(depth), "selector": "configuration"})
        except ArubaAPIError as exc:
            if exc.status_code == 404:
                return None
            raise

    def _vni_from_ref(self, ref: Any):
        """'/.../virtual_network_ids/vxlan_vni,10010' → 10010 (int) when possible."""
        name = self._ref_name(ref)
        if isinstance(name, str) and "," in name:
            tail = name.split(",")[-1]
            return int(tail) if tail.isdigit() else tail
        return name

    async def read_loopback(self, name: str) -> dict:
        """Verify a loopback interface (ip/vrf/admin)."""
        data = await self._get_config(f"/system/interfaces/{quote(name, safe='')}")
        if data is None:
            return {"interface": name, "present": False}
        return {"interface": name, "present": True, "type": data.get("type"),
                "routing": data.get("routing"), "ip4_address": data.get("ip4_address"),
                "admin": (data.get("user_config") or {}).get("admin"),
                "vrf": self._ref_name(data.get("vrf")) or "default"}

    async def read_routed_interface(self, name: str) -> dict:
        """Verify a routed (L3) port (routing/ip/mtu/vrf)."""
        data = await self._get_config(f"/system/interfaces/{quote(name, safe='')}")
        if data is None:
            return {"interface": name, "present": False}
        return {"interface": name, "present": True, "routing": data.get("routing"),
                "ip4_address": data.get("ip4_address"), "ip_mtu": data.get("ip_mtu"),
                "description": data.get("description"),
                "admin": (data.get("user_config") or {}).get("admin"),
                "vrf": self._ref_name(data.get("vrf")) or "default"}

    async def read_vxlan_interface(self, name: str = "vxlan1") -> dict:
        """Verify the VTEP interface (source IP, UDP port, bridging mode) and its
        static VXLAN peers."""
        data = await self._get_config(f"/system/interfaces/{quote(name, safe='')}")
        if data is None:
            return {"interface": name, "present": False, "static_peers": []}
        options = data.get("options") or {}
        peers = []
        raw = await self._get_config(
            f"/system/interfaces/{quote(name, safe='')}/tunnel_endpoints", depth=2)
        if isinstance(raw, dict):
            for ep in raw.values():
                if not isinstance(ep, dict):
                    continue
                destination = ep.get("destination")
                if not destination:
                    continue  # skip endpoints with no configured destination
                vnis = sorted(
                    v for v in (self._vni_from_ref(u) for u in (ep.get("network_id") or []))
                    if isinstance(v, int))
                peers.append({"destination": destination,
                              "origin": ep.get("origin"),
                              "vrf": self._ref_name(ep.get("vrf")) or "default",
                              "vnis": vnis})
        return {"interface": name, "present": True,
                "source_ip": options.get("local_ip"),
                "dest_udp_port": options.get("vxlan_dest_udp_port"),
                "inter_vxlan_bridging_mode": data.get("inter_vxlan_bridging_mode"),
                "static_peers": peers}

    async def read_evpn(self) -> dict:
        """Verify the global EVPN config."""
        data = await self._get_config("/system/evpn", depth=1)
        if data is None:
            return {"present": False}
        return {"present": True,
                "dyn_vxlan_tunnel_bridging_mode": data.get("dyn_vxlan_tunnel_bridging_mode"),
                "arp_suppression_enable": data.get("arp_suppression_enable"),
                "nd_suppression_enable": data.get("nd_suppression_enable")}

    async def read_vrf(self, name: str) -> dict:
        """Verify a VRF (RD/RT + per-AF route-targets)."""
        data = await self._get_config(f"/system/vrfs/{quote(name, safe='')}", depth=1)
        if data is None:
            return {"vrf": name, "present": False}
        afs = {}
        raw = await self._get_config(
            f"/system/vrfs/{quote(name, safe='')}/vrf_address_families", depth=2)
        if isinstance(raw, dict):
            for key, af in raw.items():
                if not isinstance(af, dict):
                    continue
                afs[af.get("address_family") or key] = {
                    "import_route_targets": af.get("import_route_targets"),
                    "export_route_targets": af.get("export_route_targets")}
        return {"vrf": name, "present": True, "type": data.get("type"),
                "rd": data.get("rd"),
                "evpn_import_route_targets": data.get("evpn_import_route_targets"),
                "evpn_export_route_targets": data.get("evpn_export_route_targets"),
                "address_families": afs}

    async def read_ospf(self, vrf: str = "default", instance_tag: int = 1) -> dict:
        """Verify an OSPF router instance (router-id, areas, attached interfaces)."""
        base = f"/system/vrfs/{quote(vrf, safe='')}/ospf_routers"
        router = await self._get_config(f"{base}/{instance_tag}", depth=1)
        if router is None:
            return {"vrf": vrf, "instance_tag": instance_tag, "present": False,
                    "areas": []}
        areas = []
        raw_areas = await self._get_config(f"{base}/{instance_tag}/areas", depth=1)
        if isinstance(raw_areas, dict):
            for area_id in raw_areas:
                abase = f"{base}/{instance_tag}/areas/{quote(str(area_id), safe='')}"
                adata = await self._get_config(abase, depth=1) or {}
                raw_if = await self._get_config(f"{abase}/ospf_interfaces", depth=1)
                intfs = list(raw_if.keys()) if isinstance(raw_if, dict) else []
                areas.append({"area_id": area_id,
                              "area_type": adata.get("area_type"),
                              "interfaces": intfs})
        return {"vrf": vrf, "instance_tag": instance_tag, "present": True,
                "router_id": router.get("admin_router_id"),
                "passive_interface_default": router.get("passive_interface_default"),
                "areas": areas}

    async def read_bgp(self, asn: int, vrf: str = "default") -> dict:
        """Verify a BGP router and its neighbors/peer-groups (incl. EVPN AF and
        route-reflector-client flags)."""
        base = f"/system/vrfs/{quote(vrf, safe='')}/bgp_routers"
        router = await self._get_config(f"{base}/{asn}", depth=1)
        if router is None:
            return {"asn": asn, "vrf": vrf, "present": False, "neighbors": []}
        neighbors = []
        raw = await self._get_config(f"{base}/{asn}/bgp_neighbors", depth=2)
        if isinstance(raw, dict):
            for key, nb in raw.items():
                if not isinstance(nb, dict):
                    nb = await self._get_config(
                        f"{base}/{asn}/bgp_neighbors/{quote(key, safe='')}",
                        depth=1) or {}
                neighbors.append({
                    "neighbor": key, "is_peer_group": nb.get("is_peer_group"),
                    "remote_as": nb.get("remote_as"),
                    "peer_group": self._ref_name(nb.get("bgp_peer_group")),
                    "local_interface": self._ref_name(nb.get("local_interface")),
                    "update_source": nb.get("update_source"),
                    "activate": nb.get("activate"),
                    "route_reflector_client": nb.get("route_reflector_client"),
                    "send_community": nb.get("send_community"),
                    "shutdown": nb.get("shutdown")})
        return {"asn": asn, "vrf": vrf, "present": True,
                "router_id": router.get("router_id"), "neighbors": neighbors}

    async def read_port_auth(self, interface: str) -> dict:
        """Verify per-port authentication (802.1X/MAC-Auth methods, mode, limits,
        role bindings)."""
        encoded = quote(interface, safe="")
        iface = await self._get_config(f"/system/interfaces/{encoded}", depth=2)
        if iface is None:
            return {"interface": interface, "present": False, "methods": {}}
        methods = {}
        raw = await self._get_config(
            f"/system/interfaces/{encoded}/port_access_auth_configurations", depth=2)
        if isinstance(raw, dict):
            for key, m in raw.items():
                if not isinstance(m, dict):
                    continue
                name = m.get("authentication_method") or key
                methods[name] = {"auth_enable": m.get("auth_enable"), **{
                    k: m.get(k) for k in self._PORT_ACCESS_AUTH_FIELDS
                    if k in m and k != "auth_enable"}}
        roles = {}
        for field in set(self._PORT_ACCESS_ROLE_BINDINGS.values()):
            val = iface.get(field)
            if val:
                roles[field] = self._ref_name(val)
        return {"interface": interface, "present": True,
                "auth_mode": iface.get("port_access_auth_mode"),
                "clients_limit": iface.get("port_access_clients_limit"),
                "mda_data_clients_limit": iface.get("port_access_mda_data_clients_limit"),
                "concurrent_onboarding": iface.get("port_access_concurrent_onboarding"),
                "radius_override": iface.get("aaa_port_access_radius_override_enable"),
                "auth_precedence": iface.get("aaa_auth_precedence"),
                "auth_priority": iface.get("aaa_auth_priority"),
                "roles": roles, "methods": methods}

    async def read_app_recognition(self) -> dict:
        """Verify the Application Recognition (ARC) global config."""
        data = await self._get_config("/system/app_recognition", depth=1)
        if data is None:
            return {"present": False}
        return {"present": True, "enable": data.get("enable"),
                "mode": data.get("mode"),
                "abp_session_limit_exceed_action": data.get(
                    "abp_session_limit_exceed_action")}

    async def read_virtual_mac(self) -> dict:
        """Verify the global EVPN virtual MAC (System.virtual_mac)."""
        data = await self._get(
            "/system", params={"depth": "1", "selector": "configuration",
                                "attributes": "virtual_mac"})
        mac = (data or {}).get("virtual_mac") if isinstance(data, dict) else None
        return {"present": bool(mac), "virtual_mac": mac or None}


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _format_interface(name: str, data: dict) -> dict:
    if not isinstance(data, dict):
        return {"name": name}
    try:
        ip4      = data.get("ip4_address")
        ip6      = data.get("ip6_address")
        vlan_tag = data.get("vlan_tag")
        stats    = data.get("statistics")
        # vlan_tag may be {"100": "/rest/..."} — the ID is the key
        if isinstance(vlan_tag, dict):
            raw_id = vlan_tag.get("id") or next(iter(vlan_tag.keys()), None)
            try:
                vlan_tag_id = int(raw_id) if raw_id is not None else None
            except (ValueError, TypeError):
                vlan_tag_id = raw_id
        else:
            vlan_tag_id = None
        # vrf: at depth=2 it is {"<vrf_name>": {...}} for a non-default VRF,
        # None/{} when the interface is in the 'default' VRF.
        vrf_raw = data.get("vrf")
        if isinstance(vrf_raw, dict) and vrf_raw:
            vrf_name = next(iter(vrf_raw.keys()))
        elif isinstance(vrf_raw, str) and vrf_raw:
            vrf_name = vrf_raw.rstrip("/").split("/")[-1]
        else:
            vrf_name = "default"
        return {
            "name": name,
            "description": data.get("description", ""),
            "admin_state": data.get("admin_state", "N/A"),
            "link_state": data.get("link_state", "N/A"),
            "link_speed": data.get("link_speed", "N/A"),
            "duplex": data.get("duplex", "N/A"),
            "mtu": data.get("mtu", "N/A"),
            "type": data.get("type", "N/A"),
            "routing": data.get("routing"),
            "vrf": vrf_name,
            "ip4_addresses": list(ip4.keys()) if isinstance(ip4, dict) else ([ip4] if isinstance(ip4, str) and ip4 else []),
            "ip6_addresses": list(ip6.keys()) if isinstance(ip6, dict) else ([ip6] if isinstance(ip6, str) and ip6 else []),
            "vlan_mode": data.get("vlan_mode", "N/A"),
            "vlan_tag": vlan_tag_id,
            "statistics": {
                "rx_bytes": stats.get("rx_bytes", 0) if isinstance(stats, dict) else 0,
                "tx_bytes": stats.get("tx_bytes", 0) if isinstance(stats, dict) else 0,
                "rx_errors": stats.get("rx_crc_err", 0) if isinstance(stats, dict) else 0,
                "tx_errors": stats.get("tx_errors", 0) if isinstance(stats, dict) else 0,
            },
        }
    except (AttributeError, TypeError) as exc:
        logger.warning("_format_interface(%s) : type inattendu — %s", name, exc)
        return {"name": name}


# Interface statistics keys grouped by category (from the AOS-CX Interface
# `statistics` object). Only keys actually present in the payload are surfaced.
_IFACE_RX_COUNTERS = (
    "rx_bytes", "rx_packets", "rx_pause",
)
_IFACE_TX_COUNTERS = (
    "tx_bytes", "tx_packets", "tx_pause",
)
_IFACE_ERROR_COUNTERS = (
    "rx_errors", "rx_crc_err", "rx_frame_err", "rx_over_err",
    "rx_giants", "rx_runts", "tx_errors", "total_errors",
)
_IFACE_DROP_COUNTERS = (
    "rx_dropped", "rx_filtered", "tx_dropped", "tx_filtered", "total_dropped",
)
_IFACE_TOTAL_COUNTERS = (
    "total_packets_no_errors", "total_uc_packets", "total_jumbos",
    "total_pause", "rx_jumbos", "tx_jumbos",
)


def _format_interface_counters(name: str, data: dict) -> dict:
    """Normalize the traffic counters of an interface from its `statistics`
    object into rx / tx / errors / drops / totals groups. Only the counters the
    device actually reports are included; a `counters_available` flag tells the
    caller whether any statistics were present at all."""
    if not isinstance(data, dict):
        return {"name": name, "counters_available": False}
    stats = data.get("statistics")
    stats = stats if isinstance(stats, dict) else {}

    def _group(keys: tuple) -> dict:
        return {k: _safe_int(stats[k]) for k in keys if k in stats}

    rx = _group(_IFACE_RX_COUNTERS)
    tx = _group(_IFACE_TX_COUNTERS)
    errors = _group(_IFACE_ERROR_COUNTERS)
    drops = _group(_IFACE_DROP_COUNTERS)
    totals = _group(_IFACE_TOTAL_COUNTERS)
    return {
        "name": name,
        "admin_state": data.get("admin_state", "N/A"),
        "link_state": data.get("link_state", "N/A"),
        "counters_available": bool(stats),
        "rx": rx,
        "tx": tx,
        "errors": errors,
        "drops": drops,
        "totals": totals,
    }


# LACP actor/partner state flag labels (AOS-CX abbreviations → readable names).
_LACP_STATE_LABELS = {
    "Activ": "activity", "TmOut": "timeout", "Aggr": "aggregation",
    "Sync": "synchronization", "Col": "collecting", "Dist": "distributing",
    "Def": "defaulted", "Exp": "expired",
}


def _parse_lacp_state(value: Any) -> dict:
    """Parse an AOS-CX LACP state string such as
    ``'Activ:1,TmOut:0,Aggr:1,Sync:1,Col:1,Dist:1,Def:0,Exp:0'`` into a flag
    dict using readable keys (activity/timeout/aggregation/synchronization/
    collecting/distributing/defaulted/expired). Unknown values yield {}."""
    flags: dict[str, bool] = {}
    if isinstance(value, str):
        for part in value.split(","):
            key, _sep, val = part.partition(":")
            key = key.strip()
            if key:
                flags[_LACP_STATE_LABELS.get(key, key)] = val.strip() == "1"
    return flags


def _human_speed(bps: Any) -> str:
    """Format a bitrate (bits/s) as a readable string (Gbps/Mbps/Kbps)."""
    n = _safe_int(bps)
    if n <= 0:
        return "N/A"
    for unit, div in (("Gbps", 1_000_000_000), ("Mbps", 1_000_000), ("Kbps", 1_000)):
        if n >= div:
            return f"{n / div:.0f} {unit}"
    return f"{n} bps"


def _format_lag_member(name: str, raw: dict) -> dict:
    """Normalize a LAG member (physical) interface: link/bond state and the
    parsed LACP actor/partner flags. ``collecting_distributing`` is the practical
    'is this link actively forwarding in the bundle' signal (Sync+Col+Dist)."""
    raw = raw if isinstance(raw, dict) else {}
    lacp_status = raw.get("lacp_status") if isinstance(raw.get("lacp_status"), dict) else {}
    bond = raw.get("bond_status") if isinstance(raw.get("bond_status"), dict) else {}
    other = raw.get("other_config") if isinstance(raw.get("other_config"), dict) else {}
    actor = _parse_lacp_state(lacp_status.get("actor_state"))
    partner = _parse_lacp_state(lacp_status.get("partner_state"))
    collecting_distributing = bool(
        actor.get("synchronization") and actor.get("collecting") and actor.get("distributing")
    )
    return {
        "interface": name,
        "link_state": raw.get("link_state", "N/A"),
        "admin_state": raw.get("admin_state", "N/A"),
        "bond_state": bond.get("state", "N/A"),
        "lacp_current": raw.get("lacp_current"),
        "aggregation_key": other.get("lacp-aggregation-key"),
        "port_priority": other.get("lacp-port-priority"),
        "actor_system_id": lacp_status.get("actor_system_id", "N/A"),
        "partner_system_id": lacp_status.get("partner_system_id", "N/A"),
        "actor_port_id": lacp_status.get("actor_port_id", "N/A"),
        "partner_port_id": lacp_status.get("partner_port_id", "N/A"),
        "actor_state": actor,
        "partner_state": partner,
        "collecting_distributing": collecting_distributing,
    }


def _format_lag(name: str, data: dict, by_name: dict) -> dict:
    """Normalize a LAG interface and resolve its members from ``by_name`` (the
    depth=2 interface map) so no extra REST calls are needed."""
    data = data if isinstance(data, dict) else {}
    lacp_raw = data.get("lacp")
    if lacp_raw in (None, "", "off", "disabled"):
        mode = "static"
    else:
        mode = f"lacp-{lacp_raw}"  # lacp-active / lacp-passive
    bond = data.get("bond_status") if isinstance(data.get("bond_status"), dict) else {}
    lacp_status = data.get("lacp_status") if isinstance(data.get("lacp_status"), dict) else {}
    other = data.get("other_config") if isinstance(data.get("other_config"), dict) else {}

    member_refs = data.get("interfaces")
    member_names = sorted(member_refs.keys()) if isinstance(member_refs, dict) else []
    members = [_format_lag_member(m, by_name.get(m, {})) for m in member_names]
    if mode == "static":
        bundled = [m for m in members if str(m["bond_state"]).lower() == "up"]
    else:
        bundled = [m for m in members if m["collecting_distributing"]]

    return {
        "name": name,
        "description": data.get("description", ""),
        "mode": mode,
        "admin_state": data.get("admin_state") or data.get("admin", "N/A"),
        "link_state": data.get("link_state") or bond.get("state", "N/A"),
        "bond_state": bond.get("state", "N/A"),
        "lacp_status": lacp_status.get("bond_status", "N/A"),
        "aggregate_speed_bps": bond.get("bond_speed"),
        "aggregate_speed": _human_speed(bond.get("bond_speed")),
        "lacp_rate": other.get("lacp-time", "N/A"),
        "lacp_fallback": other.get("lacp-fallback"),
        "mclag_enabled": other.get("mclag_enabled"),
        "vlan_mode": data.get("vlan_mode", "N/A"),
        "routing": data.get("routing"),
        "member_count": len(members),
        "members_bundled": len(bundled),
        "members": members,
    }


def _format_vlan(vid: Any, data: dict) -> dict:
    return {
        "id": int(vid),
        "name": data.get("name", f"VLAN{vid}"),
        "description": data.get("description", ""),
        "admin_state": data.get("admin", "N/A"),
        "oper_state": data.get("oper_state", "N/A"),
        "type": data.get("type", "N/A"),
        "voice": data.get("voice", False),
    }


def _collection_items(data: Any) -> list[tuple[str, Any]]:
    if isinstance(data, dict):
        return list(data.items())
    if isinstance(data, list):
        items: list[tuple[str, Any]] = []
        for index, item in enumerate(data):
            if isinstance(item, dict):
                key = (
                    item.get("name")
                    or item.get("id")
                    or item.get("interface_name")
                    or item.get("ip_or_ifname_or_group_name")
                    or item.get("prefix")
                    or item.get("interface")
                    or str(index)
                )
                items.append((str(key), item))
            else:
                items.append((str(index), item))
        return items
    return []


def _uri_tail(value: Any, default: str = "N/A") -> str:
    if isinstance(value, str) and value:
        return value.rsplit("/", 1)[-1]
    if isinstance(value, dict) and value:
        return str(next(iter(value.keys())))
    return default


def _safe_int(value: Any) -> int:
    """Convert a value to an integer, 0 if not possible (None, non-numeric str, ...)."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _human_bytes(num: int) -> str:
    """Format a number of bytes as a readable string (B/KiB/MiB/GiB/TiB)."""
    value = float(num)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(value) < 1024.0 or unit == "TiB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.2f} {unit}"
        value /= 1024.0
    return f"{value:.2f} PiB"



def _sum_bgp_prefix_stat(peer: dict, metric: str) -> int:
    """Sum a prefix counter in peer.prefix_statistics, across all AFs."""
    stats = peer.get("prefix_statistics", {})
    if not isinstance(stats, dict):
        return 0

    total = 0
    for af_stats in stats.values():
        if not isinstance(af_stats, dict):
            continue
        value = af_stats.get(metric, 0)
        try:
            total += int(value)
        except (TypeError, ValueError):
            continue
    return total


def _parse_subsystem_key(key: str) -> tuple[str, str]:
    """Split a subsystem key 'type,name' (e.g. 'management_module,1/1')."""
    if "," in key:
        stype, _, sname = key.partition(",")
        return stype.strip(), sname.strip()
    return key, key


# Format of ArubaOS-CX boot_history timestamps: 'Mon 08 Jun 26 14:18:47 UTC'.
_CX_TS_FORMATS = ("%a %d %b %y %H:%M:%S", "%a %d %b %Y %H:%M:%S")
# Offsets (seconds) of the timezone abbreviations returned by the firmware.
# strptime/%Z does not reliably recognize these abbreviations -> handle them explicitly.
_CX_TZ_OFFSETS = {
    "UTC": 0, "GMT": 0,
    "CET": 3600, "CEST": 7200,
    "EST": -18000, "EDT": -14400,
    "CST": -21600, "CDT": -18000,
    "MST": -25200, "MDT": -21600,
    "PST": -28800, "PDT": -25200,
    "BST": 3600, "IST": 19800,
    "JST": 32400,
}


def _parse_cx_timestamp(value: Any) -> Optional[float]:
    """Convert a boot_history timestamp to epoch (seconds, UTC). None if unreadable.
    Handles timezone abbreviations (UTC, CEST, CET, ...) by applying their offset."""
    if not isinstance(value, str) or not value.strip():
        return None
    parts = value.strip().split()
    if not parts:
        return None
    # The last token is usually the timezone abbreviation.
    tz_offset = 0
    if parts[-1].upper() in _CX_TZ_OFFSETS:
        tz_offset = _CX_TZ_OFFSETS[parts[-1].upper()]
        parts = parts[:-1]
    text = " ".join(parts)
    for fmt in _CX_TS_FORMATS:
        try:
            tm = time.strptime(text, fmt)
            return calendar.timegm(tm) - tz_offset  # local time -> UTC
        except (ValueError, OverflowError):
            continue
    return None


def _build_mgmt_module(name: str, sub: dict, product: dict) -> dict:
    """Build the detail of a management module: active/standby role, state,
    serial, and — option (b) — last boot + uptime derived from boot_history."""
    cp_state = sub.get("control_plane_target_state", "N/A")
    role = "active" if cp_state == "running_active" else "standby"

    # boot_history is a dict indexed "0","1","2"... where "0" = the most recent boot.
    last_boot: dict = {}
    uptime_seconds: Any = "N/A"
    history = sub.get("boot_history")
    if isinstance(history, dict) and history:
        try:
            latest_key = min(history.keys(), key=lambda k: int(k))
        except (ValueError, TypeError):
            latest_key = next(iter(history.keys()))
        entry = history.get(latest_key)
        if isinstance(entry, dict):
            ts = entry.get("timestamp")
            reason = entry.get("reason")
            last_boot = {
                "timestamp": ts or "N/A",
                "reason": reason.strip() if isinstance(reason, str) else "N/A",
            }
            epoch = _parse_cx_timestamp(ts)
            if epoch is not None:
                last_boot["epoch"] = int(epoch)
                uptime_seconds = max(0, int(time.time()) - int(epoch))

    return {
        "name": name,
        "role": role,
        "state": sub.get("state", "N/A"),
        "admin_state": sub.get("admin_state", "N/A"),
        "control_plane_state": cp_state,
        "product_name": product.get("product_name", "N/A"),
        "serial_number": product.get("serial_number", "N/A"),
        "part_number": product.get("part_number", "N/A"),
        "device_version": product.get("device_version", "N/A"),
        "last_boot": last_boot,
        "uptime_seconds": uptime_seconds,
        "reboot_statistics": sub.get("reboot_statistics") if isinstance(sub.get("reboot_statistics"), dict) else {},
    }


_VERSION_RE = re.compile(r"Version:\s*([^\s,]+)")


def _format_boot_history(history: dict) -> list[dict]:
    """Format a boot_history dict (keys "0","1"...; "0" = most recent) into a
    list sorted from the most recent reboot to the oldest, with derived epoch and
    version extracted from the 'Version: <ver>' pattern present in the reason."""
    rows: list[tuple[int, dict]] = []
    for idx, entry in history.items():
        if not isinstance(entry, dict):
            continue
        try:
            order = int(idx)
        except (TypeError, ValueError):
            order = 9999
        ts = entry.get("timestamp")
        reason = entry.get("reason")
        reason_clean = reason.strip() if isinstance(reason, str) else "N/A"
        row = {
            "index": order,
            "timestamp": ts or "N/A",
            "reason": reason_clean,
        }
        epoch = _parse_cx_timestamp(ts)
        if epoch is not None:
            row["epoch"] = int(epoch)
        match = _VERSION_RE.search(reason_clean) if isinstance(reason_clean, str) else None
        if match:
            row["version"] = match.group(1)
        rows.append((order, row))
    rows.sort(key=lambda r: r[0])  # index 0 = most recent boot at the top
    return [row for _, row in rows]


_FAULT_KEYWORDS = (
    "fault", "fail", "critical", "emergency", "warning", "alert",
    "overtemp", "overvoltage", "undervoltage", "error", "norecov",
)


def _is_fault(status: Any) -> bool:
    """True if the hardware state signals an anomaly (case-insensitive)."""
    if status is None:
        return False
    s = str(status).lower()
    return any(keyword in s for keyword in _FAULT_KEYWORDS)


def _millideg_to_c(value: Any) -> Any:
    """Convert a temperature in milli-degrees Celsius to degrees Celsius."""
    try:
        return round(int(value) / 1000.0, 1)
    except (TypeError, ValueError):
        return value


def _extract_fans_from_sub(sub: dict) -> list[dict]:
    out = []
    fans = sub.get("fans")
    if not isinstance(fans, dict):
        return out
    for name, fan in fans.items():
        if not isinstance(fan, dict):
            continue
        out.append({
            "name": fan.get("name", name),
            "status": fan.get("status", "N/A"),
            "rpm": fan.get("rpm", "N/A"),
            "speed": fan.get("speed", "N/A"),
            "direction": fan.get("direction", "N/A"),
        })
    return out


def _extract_psus_from_sub(sub: dict) -> list[dict]:
    out = []
    psus = sub.get("power_supplies")
    if not isinstance(psus, dict):
        return out
    for name, psu in psus.items():
        if not isinstance(psu, dict):
            continue
        identity = psu.get("identity") if isinstance(psu.get("identity"), dict) else {}
        characteristics = psu.get("characteristics") if isinstance(psu.get("characteristics"), dict) else {}
        out.append({
            "name": psu.get("name", name),
            "status": psu.get("status", "N/A"),
            "model": identity.get("model_number") or identity.get("product_name", "N/A"),
            "serial_number": identity.get("serial_number", "N/A"),
            "manufacturer": identity.get("manufacturer_name", "N/A"),
            "voltage_type": identity.get("voltage_type", "N/A"),
            "instantaneous_power_w": characteristics.get("instantaneous_power", "N/A"),
            "maximum_power_w": characteristics.get("maximum_power", "N/A"),
            "redundant": psu.get("redundant_psu", "N/A"),
        })
    return out


def _extract_temps_from_sub(sub: dict) -> list[dict]:
    out = []
    sensors = sub.get("temp_sensors")
    if not isinstance(sensors, dict):
        return out
    for name, sensor in sensors.items():
        if not isinstance(sensor, dict):
            continue
        out.append({
            "name": sensor.get("name", name),
            "status": sensor.get("status", "N/A"),
            "temperature_c": _millideg_to_c(sensor.get("temperature")),
            "min_c": _millideg_to_c(sensor.get("min")),
            "max_c": _millideg_to_c(sensor.get("max")),
            "location": sensor.get("location", "N/A"),
            "fan_state": sensor.get("fan_state", "N/A"),
        })
    return out


def _format_poe_interface(name: str, data: dict) -> dict:
    """Format a PoE_Interface payload (GET /system/interfaces/{name}/poe_interface).

    `status`/`pd_information` are keyed by 'port' for single-signature PDs, or
    by 'pair-a'/'pair-b' for 4-pair dual-signature PDs — the first (or only)
    entry is surfaced as the primary status, and classifications are kept per
    pair."""
    config = data.get("config") if isinstance(data.get("config"), dict) else {}
    measurements = data.get("measurements") if isinstance(data.get("measurements"), dict) else {}
    status = data.get("status") if isinstance(data.get("status"), dict) else {}
    pd_info = data.get("pd_information") if isinstance(data.get("pd_information"), dict) else {}

    primary_status = status.get("port") if isinstance(status.get("port"), dict) else None
    if primary_status is None:
        primary_status = next((v for v in status.values() if isinstance(v, dict)), {})
    classifications = {
        key: (val.get("power_classification", "N/A") if isinstance(val, dict) else "N/A")
        for key, val in pd_info.items()
    }

    return {
        "interface": name,
        "admin_disabled": bool(config.get("admin_disable", False)),
        "priority": config.get("priority", "N/A"),
        "allocate_by_method": config.get("allocate_by_method", "N/A"),
        "powering_status": primary_status.get("powering_status", "N/A"),
        "fault_reason": primary_status.get("fault_reason", "N/A"),
        "pd_type": data.get("pd_type", "N/A"),
        "pd_signature": data.get("pd_signature", "N/A"),
        "pd_classification": classifications or {},
        "average_power_w": measurements.get("average_power", "N/A"),
        "peak_power_w": measurements.get("peak_power", "N/A"),
        "power_drawn_w": measurements.get("power_drawn", "N/A"),
        "current_a": measurements.get("current", "N/A"),
        "voltage_v": measurements.get("voltage", "N/A"),
    }


def _extract_leds_from_sub(sub: dict) -> list[dict]:
    out = []
    leds = sub.get("leds")
    if not isinstance(leds, dict):
        return out
    for name, led in leds.items():
        if not isinstance(led, dict):
            continue
        out.append({"name": led.get("name", name), "state": led.get("state", "N/A")})
    return out


_DOM_METRICS = ("temperature", "vcc", "tx_power", "rx_power", "tx_bias")
_DOM_FLAG_SUFFIXES = ("_high_alarm", "_low_alarm", "_high_warning", "_low_warning")


def _format_transceiver(name: str, iface: dict) -> dict:
    """Format the state of a transceiver from pm_info (static) and
    pm_monitor (digital optical diagnostics per lane)."""
    pm = iface.get("pm_info") if isinstance(iface.get("pm_info"), dict) else {}
    monitor = iface.get("pm_monitor") if isinstance(iface.get("pm_monitor"), dict) else {}

    lanes: dict = {}
    alarms: list[dict] = []
    for lane_key, lane in monitor.items():
        if not isinstance(lane, dict):
            continue
        measurements = {m: lane[m] for m in _DOM_METRICS if lane.get(m) is not None}
        for field, value in lane.items():
            if value is True and field.endswith(_DOM_FLAG_SUFFIXES):
                alarms.append({"lane": lane_key, "flag": field})
        if measurements:
            lanes[lane_key] = measurements

    status = "ok"
    if any(a["flag"].endswith("_alarm") for a in alarms):
        status = "alarm"
    elif alarms:
        status = "warning"

    present = bool(pm.get("connector") or pm.get("vendor_name") or pm.get("vendor_serial_number"))
    return {
        "interface": name,
        "present": present,
        "status": status,
        "connector": pm.get("connector", "N/A"),
        "vendor_name": pm.get("vendor_name", "N/A"),
        "vendor_part_number": pm.get("vendor_part_number", "N/A"),
        "vendor_serial_number": pm.get("vendor_serial_number", "N/A"),
        "vendor_revision": pm.get("vendor_revision", "N/A"),
        "cable_length": pm.get("cable_length", "N/A"),
        "cable_technology": pm.get("cable_technology", "N/A"),
        "adapter_status": pm.get("adapter_status", "N/A"),
        "wavelength_nm": pm.get("wavelength", "N/A"),
        "dom": lanes,
        "alarms": alarms,
    }


def _parse_evpn_l2_vni(vni_key: str, vni: dict, global_cfg: dict) -> dict:
    """Build an L2 VNI entry from an EVPN object."""
    vni_num = int(vni_key) if str(vni_key).isdigit() else vni.get("vni", vni_key)

    vlan_ref = vni.get("vlan", {})
    if isinstance(vlan_ref, dict):
        vlan_id_val = next(iter(vlan_ref.keys()), "N/A")
    else:
        vlan_id_val = vlan_ref

    rt_import = list((vni.get("import_route_targets") or {}).keys())
    rt_export = list((vni.get("export_route_targets") or {}).keys())
    rt_both   = list((vni.get("route_targets") or {}).keys())

    return {
        "vni": int(vni_num) if str(vni_num).isdigit() else vni_num,
        "type": "L2",
        "vlan": vlan_id_val,
        "route_distinguisher": vni.get("route_distinguisher", "N/A"),
        "route_targets_import": rt_import or rt_both,
        "route_targets_export": rt_export or rt_both,
        "arp_suppression": vni.get("arp_suppression", global_cfg.get("arp_suppression", False)),
        "nd_suppression": vni.get("nd_suppression", global_cfg.get("nd_suppression", False)),
    }


def _extract_vni_from_vlan(vlan_data: dict) -> Optional[int]:
    """Extract the VNI from a VLAN object (several structures possible per ArubaOS-CX version)."""
    # Direct format: vlan.vni = 10100
    vni = vlan_data.get("vni")
    if vni is not None:
        try:
            return int(vni)
        except (ValueError, TypeError):
            pass

    # Nested format: vlan.evpn_vni = {"10100": {...}}
    evpn_vni = vlan_data.get("evpn_vni", {})
    if isinstance(evpn_vni, dict) and evpn_vni:
        key = next(iter(evpn_vni.keys()))
        try:
            return int(key)
        except (ValueError, TypeError):
            pass

    return None


def _parse_evpn_route(prefix: str, entry: dict) -> dict:
    """Decode an EVPN route from the BGP RIB l2vpn-evpn."""
    # The prefix in the ArubaOS-CX RIB encodes the route-type, e.g.:
    # "2:[0]:[48]:[aa:bb:cc:dd:ee:ff]:[32]:[10.1.1.1]/272"
    # "3:[0]:[32]:[10.0.0.1]/184"
    # "5:[0]:[24]:[192.168.1.0]/224"
    route_type = entry.get("route_type", None)
    if route_type is None:
        # Extract from the prefix
        try:
            route_type = int(prefix.split(":")[0])
        except (ValueError, IndexError):
            route_type = 0

    _type_names = {
        1: "ethernet-auto-discovery",
        2: "mac-ip",
        3: "inclusive-multicast",
        4: "ethernet-segment",
        5: "ip-prefix",
    }

    result = {
        "prefix": prefix,
        "route_type": route_type,
        "route_type_name": _type_names.get(route_type, f"type-{route_type}"),
        "rd": entry.get("route_distinguisher", entry.get("rd", "N/A")),
        "next_hop": entry.get("next_hop", "N/A"),
        "as_path": entry.get("as_path", "N/A"),
        "local_pref": entry.get("local_preference", "N/A"),
        "origin": entry.get("origin", "N/A"),
        "best": entry.get("best", False),
        "peer": entry.get("peer", "N/A"),
        "vni": entry.get("vni", entry.get("label", "N/A")),
        "esi": entry.get("esi", "N/A"),
    }

    # Type-specific fields
    if route_type == 2:
        result["mac"] = entry.get("mac_address", _extract_field_from_prefix(prefix, "mac"))
        result["ip"] = entry.get("ip_address", _extract_field_from_prefix(prefix, "ip"))
    elif route_type == 3:
        result["originator_ip"] = entry.get("originator_ip", entry.get("next_hop", "N/A"))
    elif route_type == 5:
        result["gateway_ip"] = entry.get("gateway_ip", entry.get("next_hop", "N/A"))
        result["prefix_route"] = entry.get("prefix", _extract_field_from_prefix(prefix, "prefix"))

    return result


def _extract_field_from_prefix(prefix: str, field: str) -> str:
    """Try to extract a field from the encoded EVPN prefix format."""
    parts = prefix.split(":")
    try:
        if field == "mac" and len(parts) >= 4:
            # Type-2: "2:[0]:[48]:[aa:bb:cc:dd:ee:ff]:..."
            # The MAC is between the brackets after [48]
            mac_start = prefix.find("[48]:[") + 5
            if mac_start > 5:
                mac_end = prefix.find("]", mac_start)
                return prefix[mac_start + 1:mac_end] if mac_end > mac_start else "N/A"
        elif field == "ip" and len(parts) >= 5:
            # Type-2: "...:[32]:[10.1.1.1]/272"
            ip_start = prefix.rfind(":[")
            if ip_start > 0:
                ip_part = prefix[ip_start + 2:].rstrip("/0123456789").rstrip("]")
                return ip_part if ip_part else "N/A"
        elif field == "prefix":
            # Type-5: "5:[0]:[24]:[192.168.1.0]/224"
            bracket_parts = prefix.split(":[")
            if len(bracket_parts) >= 4:
                ip_part = bracket_parts[3].split("]")[0]
                mask = bracket_parts[2].split("]")[0]
                return f"{ip_part}/{mask}"
    except (IndexError, ValueError):
        pass
    return "N/A"



def _extract_group_prios(prios: Any) -> list[str]:
    """Extract an ordered list of group names from an AAA priorities dict."""
    if not prios:
        return []
    if isinstance(prios, dict):
        sorted_items = sorted(prios.items(), key=lambda x: int(x[0]) if str(x[0]).isdigit() else 999)
        result = []
        for _, val in sorted_items:
            if isinstance(val, str):
                result.append(_uri_tail(val))
            elif isinstance(val, dict):
                result.append(next(iter(val.keys()), "N/A"))
        return result
    if isinstance(prios, list):
        return [_uri_tail(x) if isinstance(x, str) else str(x) for x in prios]
    return []


def _format_port_access_policy(name: str, data: dict) -> dict:
    if not isinstance(data, dict):
        return {"name": name}
    cfg_entries = data.get("cfg_entries", {})
    entries: list[dict] = []
    if isinstance(cfg_entries, dict):
        for seq, entry in sorted(cfg_entries.items(), key=lambda x: int(x[0]) if str(x[0]).isdigit() else 0):
            if not isinstance(entry, dict):
                continue
            action_set = entry.get("policy_action_set", {})
            entries.append({
                "sequence": seq,
                "action_set": action_set if isinstance(action_set, dict) else {},
            })
    return {
        "name": data.get("name", name),
        "base_policy": _uri_tail(data.get("base_policy_name")) if data.get("base_policy_name") else None,
        "cfg_version": data.get("cfg_version", "N/A"),
        "acl_names": data.get("acl_names", []),
        "entries_count": len(entries),
        "entries": entries,
        "client_in_statistics": data.get("client_in_statistics") if isinstance(data.get("client_in_statistics"), dict) else {},
    }


def _format_port_access_role(name: str, data: dict) -> dict:
    if not isinstance(data, dict):
        return {"name": name}
    return {
        "name": data.get("name", name),
        "description": data.get("description", ""),
        "auth_mode": data.get("auth_mode", "N/A"),
        "vlan_mode": data.get("vlan_mode", "N/A"),
        "vlan_tag": _uri_tail(data.get("vlan_tag")) if data.get("vlan_tag") else None,
        "vlan_name": data.get("vlan_name_tag", "N/A"),
        "reauth_period": data.get("reauth_period", "N/A"),
        "cached_reauth_period": data.get("cached_reauth_period", "N/A"),
        "max_session_time": data.get("max_session_time", "N/A"),
        "client_inactivity_timeout": data.get("client_inactivity_timeout", "N/A"),
        "policy_mode": data.get("policy_mode", "N/A"),
        "in_policy": _uri_tail(data.get("in_policy")) if data.get("in_policy") else None,
        "in_abp": _uri_tail(data.get("in_abp")) if data.get("in_abp") else None,
        "in_gbp": _uri_tail(data.get("in_gbp")) if data.get("in_gbp") else None,
        "stp_admin_edge_port": data.get("stp_admin_edge_port", False),
        "poe_priority": data.get("poe_priority", "N/A"),
        "qos_trust_mode": data.get("qos_trust_mode", "N/A"),
        "download_status": data.get("download_status", "N/A"),
        "origin": data.get("origin", "N/A"),
        "captive_portal_profile": data.get("captive_portal_profile", "N/A"),
        "traffic_inspection_enable": data.get("traffic_inspection_enable", False),
        "radius_overridden_attributes": data.get("radius_overridden_attributes", []),
    }


def _format_gbp_action_set(data: Any) -> dict:
    if not isinstance(data, dict):
        return {}
    return {
        "drop": data.get("drop", False),
        "reflect": data.get("reflect", False),
        "origin": data.get("origin", "N/A"),
    }


def _format_abp_action_set(data: Any) -> dict:
    if not isinstance(data, dict):
        return {}
    return {
        "drop": data.get("drop", False),
        "dscp": data.get("dscp", "N/A"),
        "local_priority": data.get("local_priority", "N/A"),
        "mirror": data.get("mirror", "N/A"),
        "origin": data.get("origin", "N/A"),
    }


def _format_port_access_gbp(name: str, data: dict, entries: Optional[list]) -> dict:
    if not isinstance(data, dict):
        return {"name": name}
    status = data.get("status", {})
    status_state = status.get("state", "N/A") if isinstance(status, dict) else "N/A"
    status_msg = status.get("message", "") if isinstance(status, dict) else ""
    in_stats = data.get("in_statistics", {})
    result: dict = {
        "name": data.get("name", name),
        "origin": data.get("origin", "N/A"),
        "cfg_version": data.get("cfg_version", "N/A"),
        "status_state": status_state,
        "status_message": status_msg,
        "in_statistics": in_stats if isinstance(in_stats, dict) else {},
        "in_reflexive_reverse_statistics": data.get("in_reflexive_reverse_statistics") if isinstance(data.get("in_reflexive_reverse_statistics"), dict) else {},
    }
    if entries is not None:
        result["entries"] = entries
        result["entries_count"] = len(entries)
    else:
        result["entries_count"] = len(data.get("cfg_entries", {}) or {})
    return result


def _format_port_access_abp(name: str, data: dict, entries: Optional[list]) -> dict:
    if not isinstance(data, dict):
        return {"name": name}
    status = data.get("status", {})
    status_state = status.get("state", "N/A") if isinstance(status, dict) else "N/A"
    status_msg = status.get("message", "") if isinstance(status, dict) else ""
    in_stats = data.get("in_statistics", {})
    result: dict = {
        "name": data.get("name", name),
        "origin": data.get("origin", "N/A"),
        "cfg_version": data.get("cfg_version", "N/A"),
        "status_state": status_state,
        "status_message": status_msg,
        "in_statistics": in_stats if isinstance(in_stats, dict) else {},
        "in_statistics_clear_performed": data.get("in_statistics_clear_performed", 0),
        "in_statistics_clear_requested": data.get("in_statistics_clear_requested", 0),
    }
    if entries is not None:
        result["entries"] = entries
        result["entries_count"] = len(entries)
    else:
        result["entries_count"] = len(data.get("cfg_entries", {}) or {})
    return result
