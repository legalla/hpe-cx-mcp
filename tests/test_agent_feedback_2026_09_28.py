"""Regression tests for the 2026-09-28 agent-feedback fixes:

A1 - configure_ospf(scope='ospf') crashed with 'quote_from_bytes() expected
     bytes' as soon as `interfaces` contained a dict entry (the documented
     per-interface network_type/passive/cost/bfd shape) instead of a plain
     interface name string.
A2 - configure_routed_interface didn't reliably apply/verify the admin state.
A3 - configure_routed_interface silently accepted routing+IP on a port with
     an empty 'system internal-vlan-range' pool (no connected route ever
     installed, no error surfaced).
B3 - LAG member -> routed conversion required a separate manual step.
"""
import asyncio

import pytest

from clients.aruba_client import ArubaAPIError, ArubaOSCXClient
from tests.test_put_merge import _Recorder  # reuse the low-level stub harness
from tools.tools_configure import _normalize_ospf_interfaces


@pytest.fixture
def client():
    return ArubaOSCXClient("192.0.2.1", "admin", "pw", api_version="v10.17")


# ─── A1: interfaces normalization (the actual crash site) ─────────────────

def test_normalize_ospf_interfaces_accepts_plain_names():
    assert _normalize_ospf_interfaces(["1/1/1", "1/1/2"]) == [
        {"interface": "1/1/1"}, {"interface": "1/1/2"}]


def test_normalize_ospf_interfaces_accepts_dicts_with_options():
    out = _normalize_ospf_interfaces(
        [{"interface": "1/3/42", "network_type": "point_to_point",
          "passive": True, "cost": 10, "bfd": "enable"}])
    assert out == [{"interface": "1/3/42", "network_type": "point_to_point",
                    "passive": True, "cost": 10, "bfd": "enable"}]


def test_normalize_ospf_interfaces_rejects_malformed_entry():
    with pytest.raises(ArubaAPIError):
        _normalize_ospf_interfaces([{"network_type": "point_to_point"}])  # no 'interface' key
    with pytest.raises(ArubaAPIError):
        _normalize_ospf_interfaces([123])


# ─── A1: per-interface OSPF options land on the Port object ───────────────

def test_configure_ospf_interface_options(client):
    rec = _Recorder(client, {"/system/interfaces/1%2F1%2F1": {"name": "1/1/1"}})
    asyncio.run(client.configure_ospf_interface_options(
        "1/1/1", network_type="point_to_point", cost=10, bfd="enable"))
    assert len(rec.puts) == 1
    path, body = rec.puts[0]
    assert path == "/system/interfaces/1%2F1%2F1"
    assert body["ospf_if_type"] == "ospf_iftype_pointopoint"
    assert body["ospf_if_out_cost"] == 10
    assert body["ospf_bfd"] == "enable"


def test_set_ospf_interface_passive_adds_and_removes(client):
    rec = _Recorder(client, {
        "/system/vrfs/default/ospf_routers/1": {"instance_tag": 1,
                                                "passive_interfaces": {}},
    })
    asyncio.run(client.set_ospf_interface_passive("1/1/1", True))
    _, body = rec.puts[0]
    assert "1/1/1" in body["passive_interfaces"]

    rec.resources["/system/vrfs/default/ospf_routers/1"]["passive_interfaces"] = {
        "1/1/1": "/rest/v10.17/system/interfaces/1%2F1%2F1"}
    asyncio.run(client.set_ospf_interface_passive("1/1/1", False))
    _, body2 = rec.puts[1]
    assert "1/1/1" not in body2["passive_interfaces"]


# ─── A3: internal-vlan-range trap ──────────────────────────────────────────

def test_configure_routed_interface_blocks_when_internal_vlan_range_empty(client):
    rec = _Recorder(client, {
        "/system": {"internal_vlan_range_base": 0, "internal_vlan_range_size": 0},
        "/system/interfaces/1%2F1%2F1": {"name": "1/1/1", "routing": False},
    })
    with pytest.raises(ArubaAPIError):
        asyncio.run(client.configure_routed_interface("1/1/1", ip_cidr="10.0.0.0/31"))
    # no write attempted before the guard raised
    assert rec.puts == []


def test_configure_routed_interface_auto_fixes_internal_vlan_range(client):
    rec = _Recorder(client, {
        "/system": {"internal_vlan_range_base": 0, "internal_vlan_range_size": 0},
        "/system/interfaces/1%2F1%2F1": {"name": "1/1/1", "routing": False,
                                        "user_config": {"admin": "down"}},
    })
    orig_put = client._put

    async def _put_and_apply(path, body=None, params=None, _retried=False):
        await orig_put(path, body, params)
        if path == "/system":  # the device keeps the pool it was given
            rec.resources["/system"] = dict(body)
    client._put = _put_and_apply
    asyncio.run(client.configure_routed_interface(
        "1/1/1", ip_cidr="10.0.0.0/31", ensure_internal_vlan_range=True,
        verify_connected_route=False))
    fixed = [b for p, b in rec.puts if p == "/system"]
    assert fixed and fixed[0]["internal_vlan_range_size"] == 128


def test_ensure_internal_vlan_range_errors_when_rest_write_not_kept(client):
    _Recorder(client, {
        "/system": {"internal_vlan_range_base": 0, "internal_vlan_range_size": 0},
        "/system/interfaces/1%2F1%2F1": {"name": "1/1/1", "routing": False},
    })
    with pytest.raises(ArubaAPIError, match="start 1024 end 1151 confirm"):
        asyncio.run(client.configure_routed_interface(
            "1/1/1", ip_cidr="10.0.0.0/31", ensure_internal_vlan_range=True,
            verify_connected_route=False))


# ─── A2: admin state is verified, not just assumed ─────────────────────────

def test_configure_routed_interface_flags_admin_mismatch(client):
    class _StuckDown(_Recorder):
        def __init__(self, client, resources):
            super().__init__(client, resources)

            async def _get(path, params=None, _retried=False):
                if path == "/system":
                    return {"internal_vlan_range_base": 1024, "internal_vlan_range_size": 128}
                if (params or {}).get("selector") == "configuration":
                    # firmware reports the admin state never actually flipped
                    return {"user_config": {"admin": "down"}}
                data = self.resources.get(path)
                if data is None:
                    raise ArubaAPIError(f"Resource not found: {path}", 404)
                return dict(data)
            client._get = _get

    rec = _StuckDown(client, {
        "/system/interfaces/1%2F1%2F1": {"name": "1/1/1", "routing": False,
                                        "user_config": {"admin": "down"}},
    })
    result = asyncio.run(client.configure_routed_interface(
        "1/1/1", ip_cidr="10.0.0.0/31", verify_connected_route=False))
    assert result["status"] == "partial"
    assert "admin state" in result["warning"]


# ─── B3: LAG member -> routed conversion in one call ───────────────────────

# ─── A3b: schema without the internal-vlan-range attributes at all ────────

def test_configure_routed_interface_skips_guard_when_attribute_unsupported(client):
    class _NoAttrSchema(_Recorder):
        def __init__(self, client, resources):
            super().__init__(client, resources)

            async def _get(path, params=None, _retried=False):
                if path == "/system" and (params or {}).get("attributes"):
                    raise ArubaAPIError(
                        "GET /system error: attribute: internal_vlan_range_base, "
                        "not found for resource: System", 400)
                if path == "/system":
                    return {"hostname": "sw1"}  # schema has no such fields at all
                data = self.resources.get(path)
                if data is None:
                    raise ArubaAPIError(f"Resource not found: {path}", 404)
                return dict(data)
            client._get = _get

    rec = _NoAttrSchema(client, {
        "/system/interfaces/1%2F1%2F1": {"name": "1/1/1", "routing": False,
                                        "user_config": {"admin": "up"}},
    })
    result = asyncio.run(client.configure_routed_interface(
        "1/1/1", ip_cidr="10.0.0.0/31", verify_connected_route=False))
    assert result["status"] == "configured"
    assert rec.puts  # the routed-port write proceeded despite the unsupported attribute


def test_configure_routed_interface_removes_from_lag_first(client):
    rec = _Recorder(client, {
        "/system": {"internal_vlan_range_base": 1024, "internal_vlan_range_size": 128},
        "/system/interfaces": {
            "lag1": {"name": "lag1", "type": "lag",
                    "interfaces": {"1/1/1": "/rest/v10.17/system/interfaces/1%2F1%2F1"}},
        },
        "/system/interfaces/lag1": {"name": "lag1", "type": "lag",
                                    "interfaces": {"1/1/1": "/rest/v10.17/system/interfaces/1%2F1%2F1"}},
        "/system/interfaces/1%2F1%2F1": {"name": "1/1/1", "routing": False,
                                        "user_config": {"admin": "down"}},
    })
    result = asyncio.run(client.configure_routed_interface(
        "1/1/1", ip_cidr="10.0.0.0/31", remove_from_lag=True,
        verify_connected_route=False))
    assert result["removed_from_lag"] == "lag1"
    lag_puts = [b for p, b in rec.puts if p == "/system/interfaces/lag1"]
    assert lag_puts and "1/1/1" not in lag_puts[0]["interfaces"]


# ─── IP-unnumbered ─────────────────────────────────────────────────────────

def test_configure_routed_interface_unnumbered(client):
    rec = _Recorder(client, {
        "/system/interfaces/1%2F1%2F1": {"name": "1/1/1", "routing": True,
                                        "ip4_address": "10.0.0.0/31",
                                        "user_config": {"admin": "up"}},
        "/system/interfaces/loopback0": {"name": "loopback0"},
    })
    res = asyncio.run(client.configure_routed_interface(
        "1/1/1", unnumbered_interface="loopback0", verify_connected_route=False))
    body = rec.puts[0][1]
    assert "ip4_address" not in body
    assert list(body["unnumbered"]["ipv4_address_owner_interface"]) == ["loopback0"]
    assert res["unnumbered_interface"] == "loopback0"
    with pytest.raises(ValueError):
        asyncio.run(client.configure_routed_interface(
            "1/1/1", ip_cidr="10.0.0.0/31", unnumbered_interface="loopback0"))
