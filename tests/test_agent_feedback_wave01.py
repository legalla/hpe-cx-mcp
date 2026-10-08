"""Regression tests for the agent-feedback fixes (waves 0/1 + hostname):
SSH config-mode prompts, multi-device targeting for writes, port_auth param
normalisation, batched VLANs, compacted apply results, hostname tool."""
import asyncio

import pytest

from clients import ssh_client
from clients.aruba_client import ArubaAPIError
from core import server_core
from core.config import DeviceConfig
from tools import tools_configure


def _run(coro):
    return asyncio.run(coro)


# ── SSH prompt detection ──────────────────────────────────────────────
@pytest.mark.parametrize("prompt", [
    "\nswitch#", "\nswitch>", "\nsw-01(config)#",
    "\nCampus-6405(config-if-1/1/1)#",
    "\nCampus-6405(config-if-<1/1/1-1/1/24>)#",
    "\nsw(config-if-<1/1/1,1/1/5-1/1/8>)#",
    "\nsw(config-vlan-10)#", "\nsw(config-lag-if)# ",
    "\nsw(config-vsx)#", "\nsw(config-radius-server)#",
])
def test_prompt_regex_accepts_config_sub_modes(prompt):
    assert ssh_client._PROMPT_RE.search(prompt) is not None
    assert ssh_client._PROMPT_ONLY_RE.match(prompt.strip()) is not None


def test_prompt_regex_ignores_mid_output_hash():
    assert ssh_client._PROMPT_RE.search("\nsome text # not a prompt\nmore") is None


def test_arubassherror_carries_partial_output():
    exc = ssh_client.ArubaSSHError("boom", partial="abc")
    assert exc.partial == "abc"
    assert str(exc) == "boom"


# ── Device targeting (writes fan out) ────────────────────────────────
@pytest.fixture
def fake_inventory(monkeypatch):
    def mk(name, host, site="lab"):
        return DeviceConfig(name=name, host=host, username="u", password="p", site=site)
    devices = {"A": mk("A", "10.0.0.1"), "B": mk("B", "10.0.0.2"),
               "C": mk("C", "10.0.0.3", site="other")}
    monkeypatch.setattr(server_core, "_devices", devices)
    return devices


@pytest.mark.parametrize("value,expected", [
    ("A", ["A"]), ("A,B", ["A", "B"]), ("A, B ,", ["A", "B"]),
    (["A", "B"], ["A", "B"]), ('["A","B"]', ["A", "B"]), ("['A','B']", ["A", "B"]),
    (None, []), ("", []),
])
def test_coerce_device_list(value, expected):
    assert server_core._coerce_device_list(value) == expected


def test_resolve_devices_csv_and_ip(fake_inventory):
    assert server_core._resolve_devices(device="A,B") == ["A", "B"]
    assert server_core._resolve_devices(device=["10.0.0.1", "B", "B"]) == ["A", "B"]
    assert server_core._resolve_devices(site="lab") == ["A", "B"]
    assert server_core._resolve_devices(device="B,A", site="lab") == ["B", "A"]


def test_resolve_devices_site_mismatch_raises(fake_inventory):
    with pytest.raises(ValueError):
        server_core._resolve_devices(device="C", site="lab")
    with pytest.raises(ValueError):
        server_core._resolve_devices()


def test_resolve_devices_unknown_passthrough(fake_inventory):
    # Unknown names are kept so the per-device call surfaces the error.
    assert server_core._resolve_devices(device="A,ZZZ") == ["A", "ZZZ"]


# ── configure_port_auth normalisation ────────────────────────────────
def test_port_auth_bool_shortcut_normalised(fake_inventory):
    res = _run(tools_configure.configure_port_auth(
        ["1/1/1"], device="A", methods={"dot1x": True, "mac_auth": {"reauth_period": 60}},
        auth_precedence="dot1x mac-auth"))
    assert res["status"] == "planned"
    p = res["plan"]["A"]
    assert p["methods"] == {"dot1x": {"auth_enable": True},
                            "mac-auth": {"auth_enable": True, "reauth_period": 60}}
    assert p["auth_precedence"] == ["dot1x", "mac-auth"]


def test_port_auth_top_level_shortcuts_and_csv_interfaces(fake_inventory):
    res = _run(tools_configure.configure_port_auth(
        "1/1/1, 1/1/2", device="A", dot1x=True, mac_auth=False,
        auth_precedence=["802.1x", "mac"]))
    assert res["status"] == "planned"
    p = res["plan"]["A"]
    assert p["interfaces"] == ["1/1/1", "1/1/2"]
    assert p["methods"] == {"dot1x": {"auth_enable": True}, "mac-auth": {"auth_enable": False}}
    assert p["auth_precedence"] == ["dot1x", "mac-auth"]


@pytest.mark.parametrize("kwargs,field", [
    ({"methods": "dot1x"}, "methods"),
    ({"methods": {"dot1x": 13}}, "methods.dot1x"),
    ({"methods": {"eap": True}}, "methods"),
    ({"auth_precedence": "dot1x bogus"}, "auth_precedence"),
    ({"auth_precedence": {"1": "dot1x"}}, "auth_precedence"),
    ({"auth_mode": "nope"}, "auth_mode"),
    ({"roles": ["EMPLOYEE"]}, "roles"),
    ({"create_roles": [{"vlan_tag": 10}]}, "create_roles[0]"),
])
def test_port_auth_bad_shapes_return_schema(fake_inventory, kwargs, field):
    res = _run(tools_configure.configure_port_auth(["1/1/1"], device="A", **kwargs))
    assert res["status"] == "invalid_input"
    assert res["field"] == field
    assert "expected_schema" in res


def test_port_auth_missing_interfaces(fake_inventory):
    res = _run(tools_configure.configure_port_auth([], device="A", dot1x=True))
    assert res["status"] == "invalid_input" and res["field"] == "interfaces"


@pytest.mark.parametrize("value,expected", [
    ("1/1/1-1/1/3", ["1/1/1", "1/1/2", "1/1/3"]),
    ("1/1/1-3, 1/1/10", ["1/1/1", "1/1/2", "1/1/3", "1/1/10"]),
    (["1/1/5", "1/1/5", "lag1"], ["1/1/5", "lag1"]),
    ("1/1/4-1/1/2", ["1/1/4-1/1/2"]),  # inverted range left as-is
])
def test_expand_interfaces(value, expected):
    assert tools_configure._expand_interfaces(value) == expected


# ── configure_vlan batch ─────────────────────────────────────────────
def test_configure_vlan_batch_plan_matrix(fake_inventory):
    res = _run(tools_configure.configure_vlan(
        device="A,B", vlans=[{"vlan_id": 10, "name": "USERS"}, 20, {"id": 30}]))
    assert res["status"] == "planned"
    assert res["targets"] == ["A", "B"]
    assert [s["vlan"] for s in res["plan"]["A"]] == [10, 20, 30]
    assert res["plan"]["B"][0] == {"action": "create_vlan", "vlan": 10, "name": "USERS"}


def test_configure_vlan_single_still_works(fake_inventory):
    res = _run(tools_configure.configure_vlan(10, device="A", name="X"))
    assert res["plan"]["A"] == [{"action": "create_vlan", "vlan": 10, "name": "X"}]
    res = _run(tools_configure.configure_vlan(10, device="A", delete=True))
    assert res["plan"]["A"] == [{"action": "delete_vlan", "vlan": 10}]


def test_configure_vlan_validation(fake_inventory):
    assert _run(tools_configure.configure_vlan(device="A"))["status"] == "invalid_input"
    assert _run(tools_configure.configure_vlan(
        device="A", vlans=[{"name": "no-id"}]))["status"] == "invalid_input"
    assert _run(tools_configure.configure_vlan(
        device="A", vlans=[10, 5000]))["status"] == "invalid_input"


def test_configure_vlan_batch_exec_tolerates_failures(fake_inventory):
    class _Client:
        async def create_vlan(self, vid, name=None, description=None):
            if vid == 20:
                raise ArubaAPIError("boom", 400)
            return {"vlan": vid, "status": "created"}

    captured = {}

    async def _fake_domain_write(operation, device, site, plan, executor, apply):
        captured["result"] = await executor("A", _Client())
        return {"status": "applied"}

    tools_configure._domain_write, orig = _fake_domain_write, tools_configure._domain_write
    try:
        _run(tools_configure.configure_vlan(device="A", vlans=[10, 20, 30], apply=True))
    finally:
        tools_configure._domain_write = orig
    r = captured["result"]
    assert r["summary"] == {"ok": 2, "failed": 1, "failed_vlans": [20]}
    assert [c["ok"] for c in r["vlans"]] == [True, False, True]


# ── result compaction ────────────────────────────────────────────────
def test_compact_result_collapses_long_lists():
    items = [{"interface": f"1/1/{i}", "ok": True, "status": "configured"} for i in range(1, 10)]
    items[3] = {"interface": "1/1/4", "ok": False, "status": "failed", "error": "x"}
    out = tools_configure._compact_result({"interfaces": items, "roles": [{"a": 1}]})
    c = out["interfaces"]
    assert c["count"] == 9 and c["ok"] == 8 and c["failed"] == 1
    assert c["failed_items"][0]["interface"] == "1/1/4"
    assert c["statuses"] == {"configured": 8, "failed": 1}
    assert out["roles"] == [{"a": 1}]  # short list untouched


def test_compact_result_keeps_short_lists():
    short = [{"x": i} for i in range(3)]
    assert tools_configure._compact_result(short) == short


# ── configure_hostname / routed_port create_vrf ──────────────────────
def test_configure_hostname_plan_and_validation(fake_inventory):
    res = _run(tools_configure.configure_hostname("Campus-6405-Core1", device="A"))
    assert res["status"] == "planned" and res["plan"] == {"A": {"hostname": "Campus-6405-Core1"}}
    assert _run(tools_configure.configure_hostname("-bad", device="A"))["status"] == "invalid_input"
    assert _run(tools_configure.configure_hostname("dup", device="A,B"))["status"] == "error"


def test_routed_port_create_vrf_adds_step(fake_inventory):
    res = _run(tools_configure.configure_routed_port(
        "1/1/48", device="A", ip_address="10.0.0.0/31", vrf="KEEPALIVE", create_vrf=True))
    assert [s["action"] for s in res["plan"]["A"]] == ["ensure_vrf", "configure_routed_interface"]
    res = _run(tools_configure.configure_routed_port(
        "1/1/48", device="A", ip_address="10.0.0.0/31", vrf="default", create_vrf=True))
    assert [s["action"] for s in res["plan"]["A"]] == ["configure_routed_interface"]
