import ipaddress

import aiohttp
import pytest

from clients.aruba_client import (
    ArubaAPIError,
    ArubaOSCXClient,
    _v_mac,
    _v_ipv4_host,
    _v_ip_host,
    _v_ipv4_cidr,
    _v_int_range,
    _v_vlan,
    _v_vni,
    _v_mtu,
    _v_asn,
    _v_route_target,
    _v_ospf_area,
)


# ── Validators ───────────────────────────────────────────────────────────

def test_v_mac_accepts_and_normalizes():
    assert _v_mac("AA:BB:CC:DD:EE:FF") == "aa:bb:cc:dd:ee:ff"


def test_v_mac_rejects_invalid():
    with pytest.raises(ArubaAPIError) as exc:
        _v_mac("not-a-mac")
    assert exc.value.status_code == 400


def test_v_ipv4_host_accepts_ipv4():
    assert _v_ipv4_host("10.0.0.1") == "10.0.0.1"


def test_v_ipv4_host_rejects_ipv6():
    with pytest.raises(ArubaAPIError):
        _v_ipv4_host("2001:db8::1")


def test_v_ipv4_host_rejects_garbage():
    with pytest.raises(ArubaAPIError):
        _v_ipv4_host("not-an-ip")


def test_v_ip_host_accepts_ipv4_and_ipv6():
    assert _v_ip_host("10.0.0.1") == "10.0.0.1"
    assert _v_ip_host("2001:db8::1") == "2001:db8::1"


def test_v_ipv4_cidr_requires_prefix():
    with pytest.raises(ArubaAPIError):
        _v_ipv4_cidr("10.0.0.1")


def test_v_ipv4_cidr_accepts_valid():
    assert _v_ipv4_cidr("10.0.0.1/31") == "10.0.0.1/31"


def test_v_ipv4_cidr_rejects_ipv6():
    with pytest.raises(ArubaAPIError):
        _v_ipv4_cidr("2001:db8::1/64")


def test_v_int_range_bounds():
    assert _v_int_range("10", 1, 20, "field") == 10
    with pytest.raises(ArubaAPIError):
        _v_int_range("100", 1, 20, "field")
    with pytest.raises(ArubaAPIError):
        _v_int_range("notanint", 1, 20, "field")


def test_v_vlan_bounds():
    assert _v_vlan(1) == 1
    assert _v_vlan(4094) == 4094
    with pytest.raises(ArubaAPIError):
        _v_vlan(4095)
    with pytest.raises(ArubaAPIError):
        _v_vlan(0)


def test_v_vni_bounds():
    assert _v_vni(16777215) == 16777215
    with pytest.raises(ArubaAPIError):
        _v_vni(16777216)


def test_v_mtu_bounds():
    assert _v_mtu(68) == 68
    assert _v_mtu(9198) == 9198
    with pytest.raises(ArubaAPIError):
        _v_mtu(67)


def test_v_asn_plain_integer():
    assert _v_asn(65000) == 65000


def test_v_asn_asdot_notation():
    # 1.1 -> 1*65536 + 1 = 65537
    assert _v_asn("1.1") == 65537


def test_v_asn_rejects_out_of_range():
    with pytest.raises(ArubaAPIError):
        _v_asn(4294967296)


def test_v_route_target_asn_form():
    assert _v_route_target("65001:250") == "65001:250"


def test_v_route_target_ipv4_form():
    assert _v_route_target("10.0.0.1:250") == "10.0.0.1:250"


def test_v_route_target_rejects_malformed():
    with pytest.raises(ArubaAPIError):
        _v_route_target("no-colon-here")
    with pytest.raises(ArubaAPIError):
        _v_route_target("65001:notanumber")


def test_v_ospf_area_numeric_and_dotted():
    assert _v_ospf_area("0") == "0"
    assert _v_ospf_area("0.0.0.0") == "0.0.0.0"


def test_v_ospf_area_rejects_invalid():
    with pytest.raises(ArubaAPIError):
        _v_ospf_area("not-an-area")


# ── ArubaOSCXClient: pure helpers (no network) ──────────────────────────

def test_normalize_api_version_latest_passthrough():
    assert ArubaOSCXClient._normalize_api_version("latest") == "latest"


def test_normalize_api_version_adds_v_prefix():
    assert ArubaOSCXClient._normalize_api_version("10.13") == "v10.13"


def test_normalize_api_version_rejects_garbage():
    with pytest.raises(ArubaAPIError):
        ArubaOSCXClient._normalize_api_version("garbage")


def _make_client(**kwargs):
    defaults = dict(host="sw1.example.net", username="admin", password="secret",
                     api_version="v10.09", verify_ssl=False, timeout=5)
    defaults.update(kwargs)
    return ArubaOSCXClient(**defaults)


def test_api_version_tuple_parses_major_minor():
    client = _make_client(api_version="v10.13")
    assert client._api_version_tuple() == (10, 13)


def test_api_version_tuple_defaults_on_garbage():
    client = _make_client()
    client.api_version = "not-a-version"
    assert client._api_version_tuple() == (0, 0)


def test_collection_items_from_dict():
    items = ArubaOSCXClient._collection_items({"a": 1, "b": 2})
    assert items == [("a", 1), ("b", 2)]


def test_collection_items_from_list_of_dicts_uses_name_key():
    items = ArubaOSCXClient._collection_items([{"name": "vlan10"}, {"id": "42"}])
    assert items == [("vlan10", {"name": "vlan10"}), ("42", {"id": "42"})]


def test_collection_items_from_list_of_scalars_uses_index():
    items = ArubaOSCXClient._collection_items(["a", "b"])
    assert items == [("0", "a"), ("1", "b")]


def test_collection_items_unsupported_type_returns_empty():
    assert ArubaOSCXClient._collection_items(None) == []
    assert ArubaOSCXClient._collection_items("a string") == []


# ── Write-protection guard (no network needed: raises before any request) ──

def test_write_blocked_on_read_only_device():
    client = _make_client()
    client.set_write_enabled(False)
    with pytest.raises(ArubaAPIError) as exc:
        client._assert_write_allowed("POST", "/system/vlans/10")
    assert exc.value.status_code == 403
    assert "read-only" in str(exc.value)


def test_write_allowed_on_read_write_device():
    client = _make_client()
    client.set_write_enabled(True)
    client._assert_write_allowed("POST", "/system/vlans/10")  # must not raise


def test_login_logout_always_allowed_even_read_only():
    client = _make_client()
    client.set_write_enabled(False)
    client._assert_write_allowed("POST", "/login")
    client._assert_write_allowed("POST", "/logout")


def test_troubleshoot_instances_allowed_even_read_only():
    client = _make_client()
    client.set_write_enabled(False)
    client._assert_write_allowed("POST", "/system/troubleshoots/foo")


# ── HTTP-level behavior (mocked with a hand-rolled fake aiohttp session) ──
#
# `aioresponses` (the usual aiohttp-mocking library) is not compatible with
# recent aiohttp releases (ClientResponse's constructor changed), so the
# fakes below directly stand in for aiohttp.ClientSession / ClientResponse,
# giving full control over status codes and call sequencing without any
# extra dependency.

class _FakeResponse:
    def __init__(self, status=200, payload=None, text=""):
        self.status = status
        self._payload = payload if payload is not None else {}
        self._text = text

    async def json(self):
        return self._payload

    async def text(self):
        return self._text

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False


class _FakeSession:
    """Queues one or more canned responses per (method, url) and records every
    call made, so tests can assert exactly what the client sent."""

    def __init__(self):
        self.calls: list[tuple[str, str]] = []
        self._queued: dict[tuple[str, str], list[_FakeResponse]] = {}
        self.closed = False

    def queue(self, method: str, url: str, response: _FakeResponse) -> None:
        self._queued.setdefault((method.upper(), url), []).append(response)

    def _pop(self, method: str, url):
        self.calls.append((method, url))
        key = (method.upper(), url)
        bucket = self._queued.get(key)
        if not bucket:
            raise AssertionError(f"Unexpected request: {method} {url}")
        return bucket.pop(0)

    def get(self, url, **kwargs):
        return self._pop("GET", url)

    def post(self, url, **kwargs):
        return self._pop("POST", url)

    def put(self, url, **kwargs):
        return self._pop("PUT", url)

    def delete(self, url, **kwargs):
        return self._pop("DELETE", url)

    async def close(self):
        self.closed = True


BASE = "https://sw1.example.net/rest/v10.09"


@pytest.fixture
def fake_session(monkeypatch):
    session = _FakeSession()

    def _factory(*_args, **_kwargs):
        # Mirrors real aiohttp: a freshly constructed ClientSession is open.
        session.closed = False
        return session

    monkeypatch.setattr(aiohttp, "ClientSession", _factory)
    return session


@pytest.mark.asyncio
async def test_connect_success_and_logout(fake_session):
    client = _make_client()
    fake_session.queue("POST", f"{BASE}/login", _FakeResponse(status=200))
    await client._connect()
    assert client.is_connected

    fake_session.queue("POST", f"{BASE}/logout", _FakeResponse(status=200))
    closed = await client.logout()
    assert closed is True
    assert not client.is_connected


@pytest.mark.asyncio
async def test_connect_failure_raises_aruba_api_error(fake_session):
    client = _make_client()
    fake_session.queue("POST", f"{BASE}/login", _FakeResponse(status=401, text="Invalid credentials"))
    with pytest.raises(ArubaAPIError) as exc:
        await client._connect()
    assert exc.value.status_code == 401
    assert not client.is_connected


@pytest.mark.asyncio
async def test_get_returns_parsed_json(fake_session):
    client = _make_client()
    fake_session.queue("POST", f"{BASE}/login", _FakeResponse(status=200))
    fake_session.queue("GET", f"{BASE}/system/vlans/10", _FakeResponse(status=200, payload={"vlan_id": 10}))
    result = await client._get("/system/vlans/10")
    assert result == {"vlan_id": 10}


@pytest.mark.asyncio
async def test_get_404_raises_not_found(fake_session):
    client = _make_client()
    fake_session.queue("POST", f"{BASE}/login", _FakeResponse(status=200))
    fake_session.queue("GET", f"{BASE}/system/vlans/999", _FakeResponse(status=404))
    with pytest.raises(ArubaAPIError) as exc:
        await client._get("/system/vlans/999")
    assert exc.value.status_code == 404


@pytest.mark.asyncio
async def test_get_401_triggers_relogin_and_retries_once(fake_session):
    client = _make_client()
    fake_session.queue("POST", f"{BASE}/login", _FakeResponse(status=200))  # initial connect
    fake_session.queue("GET", f"{BASE}/system/vlans/10", _FakeResponse(status=401))  # session expired
    fake_session.queue("POST", f"{BASE}/login", _FakeResponse(status=200))  # transparent re-login
    fake_session.queue("GET", f"{BASE}/system/vlans/10", _FakeResponse(status=200, payload={"vlan_id": 10}))
    result = await client._get("/system/vlans/10")
    assert result == {"vlan_id": 10}
    assert fake_session.calls.count(("POST", f"{BASE}/login")) == 2


@pytest.mark.asyncio
async def test_post_blocked_before_any_http_call_on_read_only_device(fake_session):
    client = _make_client()
    client.set_write_enabled(False)
    with pytest.raises(ArubaAPIError) as exc:
        await client._post("/system/vlans", body={"id": 10})
    assert exc.value.status_code == 403
    assert fake_session.calls == []  # refused before touching the network


@pytest.mark.asyncio
async def test_post_success_when_write_enabled(fake_session):
    client = _make_client()
    client.set_write_enabled(True)
    fake_session.queue("POST", f"{BASE}/login", _FakeResponse(status=200))
    fake_session.queue("POST", f"{BASE}/system/vlans", _FakeResponse(status=201, payload={"status": "created"}))
    result = await client._post("/system/vlans", body={"id": 10})
    assert result == {"status": "created"}

