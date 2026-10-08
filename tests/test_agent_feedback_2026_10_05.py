"""Regression tests for the Campus -> EVPN/VXLAN migration field feedback
(2026-10-05, AOS-CX 10.16-10.18): SVI active-gateway read, CLI-text config,
compact failure listing, LAG release, vxlan1 creation/post-check, BGP
peer-group inheritance, SSH prompts/errors, fabric overlay, per-device ids,
VRF rd 'auto' + BGP VRF context, extended edges, batch deletes, VSF members."""
import asyncio

import pytest

from clients import ssh_client
from clients.aruba_client import ArubaOSCXClient, _format_interface
from core import server_core
from core.config import DeviceConfig
from tests.test_agent_feedback_2026_10_01 import _Stateful
from tests.test_put_merge import _Recorder
from tools import tools_configure, tools_orchestrate as orch


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture
def client():
    return ArubaOSCXClient("192.0.2.1", "admin", "pw", api_version="v10.17")


@pytest.fixture
def inv(monkeypatch):
    def mk(name, host):
        return DeviceConfig(name=name, host=host, username="u", password="p", site="lab")
    monkeypatch.setattr(server_core, "_devices", {
        "S1": mk("S1", "10.0.0.1"), "S2": mk("S2", "10.0.0.2"),
        "L1": mk("L1", "10.0.0.11"), "L2": mk("L2", "10.0.0.12"),
        "Campus-6300-VSF": mk("Campus-6300-VSF", "10.0.0.24"),
        "Campus-6300-VSF2": mk("Campus-6300-VSF2", "Campus-6300-VSF2")})


# ─── A1 SVI read ────────────────────────────────────────────────────────────

def test_svi_exposes_active_gateway_and_effective_routing():
    out = _format_interface("vlan10", {
        "type": "vlan", "routing": False, "ip4_address": "10.0.10.13/24",
        "vsx_virtual_ip4": ["10.0.10.1"], "vsx_virtual_gw_mac_v4": "02:00:00:00:00:04",
        "statistics": {}, "l3_counters_enable": {"rx": False, "tx": False}})
    assert out["routing"] is True and out["routing_configured"] is False
    assert out["vsx_virtual_ip4"] == ["10.0.10.1"]
    assert out["vsx_virtual_gw_mac_v4"] == "02:00:00:00:00:04"
    assert out["vsx_virtual_ip6"] == [] and out["active_gateway"] is True
    assert out["statistics"] is None and "L3 counters disabled" in out["statistics_note"]


def test_physical_port_without_ip_keeps_raw_routing():
    out = _format_interface("1/1/1", {"type": "system", "routing": False,
                                      "statistics": {"rx_bytes": 5}})
    assert out["routing"] is False and "routing_configured" not in out
    assert out["statistics"]["rx_bytes"] == 5 and "vsx_virtual_ip4" not in out


# ─── A2 running-config as CLI text ─────────────────────────────────────────

def test_get_config_reports_actual_format(client, monkeypatch):
    async def _text(path, params=None):
        return "!\n!Version AOS-CX\nhostname X\n"
    monkeypatch.setattr(client, "_get_text", _text)
    assert _run(client.get_config())["format"] == "cli-text"

    async def _json(path, params=None):
        return '{"System": {}}'
    monkeypatch.setattr(client, "_get_text", _json)
    assert _run(client.get_config())["format"] == "json"


# ─── A3 compact results always list failures ───────────────────────────────

def test_compact_result_lists_partial_orchestrator_steps():
    steps = [{"action": f"s{i}", "result": {"status": "configured"}} for i in range(6)]
    steps[3]["result"] = {"status": "partial", "interface": "1/1/1"}
    out = tools_configure._compact_result({"steps": steps})
    assert out["steps"]["failed"] == 1
    assert out["steps"]["failed_items"][0]["action"] == "s3"


def test_run_steps_summary_carries_failed_items():
    async def ok(c):
        return {"status": "configured"}

    async def bad(c):
        return {"status": "partial", "interface": "1/1/49", "warning": "no route"}
    res = _run(orch._run_steps("d", None, [orch._step("a", ok), orch._step("b", bad)]))
    assert res["summary"]["failed"] == 1
    assert res["summary"]["failed_items"] == [
        {"action": "b", "interface": "1/1/49", "warning": "no route"}]


# ─── B1/B2 LAG release ─────────────────────────────────────────────────────

def test_release_lag_members_keeps_mode_and_deletes_empty_lag(client):
    st = _Stateful(client, {
        "/system/interfaces": {
            "lag1": {"type": "lag", "interfaces": {"1/1/1": "u", "1/1/2": "u"}},
            "lag2": {"type": "lag", "interfaces": {"1/1/3": "u", "1/1/4": "u"}}},
        "/system/interfaces/lag1": {"type": "lag", "lacp": "active",
                                    "interfaces": {"1/1/1": "u", "1/1/2": "u"}},
        "/system/interfaces/lag2": {"type": "lag", "lacp": "active",
                                    "interfaces": {"1/1/3": "u", "1/1/4": "u"}},
        "/system/interfaces/1%2F1%2F1": {}, "/system/interfaces/1%2F1%2F2": {},
        "/system/interfaces/1%2F1%2F3": {}})
    res = _run(client.release_lag_members(["1/1/1", "1/1/2", "1/1/3"], delete_empty=True))
    assert res["released"] == {"1/1/1": "lag1", "1/1/2": "lag1", "1/1/3": "lag2"}
    assert res["lags_deleted"] == ["lag1"] and res["lags_left_empty"] == []
    lag2_put = [b for p, b in st.puts if p == "/system/interfaces/lag2"][0]
    assert lag2_put["lacp"] == "active" and set(lag2_put["interfaces"]) == {"1/1/4"}


def test_underlay_releases_lags_first_when_requested():
    res = _run(orch.orchestrate_fabric_underlay(
        spines=["S1"], leafs=["L1"], underlay_subnet="10.1.0.0/30",
        loopback0_subnet="10.2.0.0/29", remove_from_lag=True, delete_empty_lags=True,
        cabling=[{"a_device": "S1", "a_interface": "1/1/1",
                  "b_device": "L1", "b_interface": "1/1/49"}]))
    first = res["plan"]["S1"][0]
    assert first["action"] == "release_lag_members"
    assert first["interfaces"] == ["1/1/1"] and first["delete_empty_lags"] is True


# ─── B3 vxlan1 ─────────────────────────────────────────────────────────────

def test_vxlan_create_sets_top_level_admin_and_udp_port(client):
    rec = _Recorder(client, {})
    _run(client.ensure_vxlan_interface("vxlan1", source_ip="10.1.1.1"))
    _, body = rec.posts[0]
    assert body["admin"] == "up" and body["user_config"] == {"admin": "up"}
    assert body["options"]["vxlan_dest_udp_port"] == "4789"


def test_l2vni_post_body_has_no_routing_field(client):
    # 10.16 (6200) rejects `routing` on a VNI: "values in post body not configurable"
    rec = _Recorder(client, {"/system/virtual_network_ids": {}})
    res = _run(client.create_l2vni(10021, 21))
    assert res["status"] == "created"
    path, body = rec.posts[0]
    assert path == "/system/virtual_network_ids" and "routing" not in body
    assert body["type"] == "vxlan_vni" and list(body["vlan"]) == ["21"]


def test_vxlan_operational_check_reports_bad_evi(client, monkeypatch):
    async def _get(path, params=None, _retried=False):
        if path == "/system/interfaces/vxlan1":
            return {"admin": "up", "forwarding_state": {"operational": False, "enablement": True}}
        if path == "/system/virtual_network_ids":
            return {"vxlan_vni,10010": {"state": "operational"}}
        return {"10010": {"operational_status": "down"}}
    client._get = _get

    async def _nosleep(_):
        return None
    monkeypatch.setattr(asyncio, "sleep", _nosleep)
    res = _run(client.check_vxlan_operational(attempts=2))
    assert res["operational"] is False and len(res["problems"]) == 2


# ─── B4 BGP ────────────────────────────────────────────────────────────────

def test_update_source_interface_name_goes_to_local_interface(client):
    rec = _Recorder(client, {})
    _run(client.create_bgp_neighbor("10.0.0.1", 65000, update_source="loopback 0"))
    _, body = rec.posts[0]
    assert "update_source" not in body
    assert list(body["local_interface"]) == ["loopback0"]


def test_wait_bgp_established_reports_last_error(client, monkeypatch):
    async def _nbrs(vrf="default"):
        return {"bgp_neighbors": [
            {"peer_ip": "10.0.0.1", "state": "Established"},
            {"peer_ip": "10.0.0.2", "state": "Idle",
             "last_error_received": {"code": 6, "sub_code": 2}}]}
    monkeypatch.setattr(client, "get_bgp_neighbors", _nbrs)
    res = _run(client.wait_bgp_established(["10.0.0.1", "10.0.0.2"], timeout=0))
    assert res["established"] == ["10.0.0.1"]
    assert res["not_established"]["10.0.0.2"]["last_error_received"]["code"] == 6


# ─── C1/C3 SSH ─────────────────────────────────────────────────────────────

def test_cli_error_detection():
    assert ssh_client.cli_error("Invalid input: foo") == "Invalid input: foo"
    assert ssh_client.cli_error("% Command incomplete.")
    assert ssh_client.cli_error("Neighbor 10.0.0.1 is not configured")
    assert ssh_client.cli_error("Interface  Status\n1/1/1 up") is None


def test_run_commands_declined_prompt_and_stop_on_error():
    c = ssh_client.ArubaOSCXSSHClient("h", "u", "p")
    c._closed = False
    sent = []

    async def _run_command(cmd, auto_confirm=False):
        sent.append(cmd)
        c.last_confirmations = ([{"prompt": "Continue (y/n)?", "answer": "n"}]
                                if cmd == "shutdown" else [])
        return ""
    c.run_command = _run_command
    res = _run(c.run_commands(["interface vxlan1", "shutdown", "no shutdown"],
                              stop_on_error=True))
    assert [r["ok"] for r in res] == [True, False, False]
    assert "auto_confirm" in res[1]["error"]
    assert res[2]["executed"] is False and sent == ["interface vxlan1", "shutdown"]


# ─── D1 fabric overlay ─────────────────────────────────────────────────────

def test_fabric_overlay_plan(inv):
    lo0 = {"S1": "10.9.0.1", "S2": "10.9.0.2", "L1": "10.9.0.11", "L2": "10.9.0.12"}
    res = _run(orch.orchestrate_fabric_overlay(
        spines=["S1", "S2"], leafs=["L1", "L2"], asn=65001, loopback0=lo0))
    assert res["status"] == "planned"
    s1 = res["plan"]["S1"]
    assert s1[0]["router_id"] == "10.9.0.1"
    assert s1[1]["peer_group"] == "EVPN-RR-CLIENTS" and s1[1]["members"] == ["10.9.0.11", "10.9.0.12"]
    assert res["plan"]["L1"][1]["members"] == ["10.9.0.1", "10.9.0.2"]


def test_fabric_overlay_members_inherit_from_rr_group(inv):
    calls = []

    class _C:
        async def create_bgp_neighbor(self, name, asn, **kw):
            calls.append((name, kw))
            return {"neighbor": name, "status": "created", "is_peer_group": kw["is_peer_group"]}
    group = {"neighbor": "G", "is_peer_group": True, "remote_as": 65001,
             "local_interface": "loopback0", "activate": dict(orch._EVPN_AF),
             "send_community": {"l2vpn-evpn": "extended"},
             "route_reflector_client": {"l2vpn-evpn": True}}
    _run(orch._bgp_neighbors_step(_C(), 65001, "default",
                                  [group, {"neighbor": "10.9.0.11", "peer_group": "G"}]))
    member = calls[1][1]
    assert member["activate"] == {"l2vpn-evpn": True, "ipv4-unicast": False}
    assert member["local_interface"] is None and member["route_reflector_client"] is None


# ─── D2/D3/D4 per-device ids, VRF rd auto + BGP VRF ────────────────────────

def test_shared_router_id_refused_for_several_devices(inv):
    res = _run(tools_configure.configure_bgp(65001, device="S1,S2", router_id="10.0.0.9"))
    assert res["status"] == "invalid_input" and res["field"] == "router_id"
    ok = _run(tools_configure.configure_bgp(65001, device="S1,S2", router_id="loopback0"))
    assert ok["status"] == "planned"
    ok = _run(tools_configure.configure_ospf(device="S1,S2",
                                             router_id={"S1": "1.1.1.1", "S2": "2.2.2.2"}))
    assert ok["plan"]["S2"]["router_id"] == "2.2.2.2"


def test_vrf_rd_auto_needs_l3vni_and_plans_bgp_vrf(inv):
    bad = _run(tools_configure.configure_vrf("T", device="L1", rd="auto"))
    assert bad["status"] == "invalid_input"
    res = _run(tools_configure.configure_vrf("T", device="L1,L2", rd="auto", l3vni=5000,
                                             redistribute=["connected"]))
    assert res["plan"]["L1"]["rd"] == "auto"
    assert res["plan"]["L1"]["bgp_vrf"]["redistribute"] == ["connected"]


def test_vrf_rd_auto_resolved_from_loopback0(inv, monkeypatch):
    calls = {}

    class _C:
        async def loopback_ip(self, name):
            return "10.9.0.11"

        async def ensure_vrf(self, name, rd=None, **kw):
            calls["rd"] = rd
            return {"vrf": name, "status": "created"}

        async def create_l3vni(self, *a):
            return {"status": "created"}

        async def detect_bgp_asn(self, vrf):
            return 65001

        async def ensure_bgp_vrf(self, asn, vrf, redistribute=None):
            calls["bgp"] = (asn, vrf, redistribute)
            return {"status": "created"}

    async def _fake_domain(op, device, site, plan, executor, apply):
        return await executor("L1", _C())
    monkeypatch.setattr(tools_configure, "_domain_write", _fake_domain)
    _run(tools_configure.configure_vrf("T", device="L1", rd="auto", l3vni=5000,
                                       redistribute=["connected"], apply=True))
    assert calls["rd"] == "10.9.0.11:5000" and calls["bgp"] == (65001, "T", ["connected"])


# ─── D5 extended edges ─────────────────────────────────────────────────────

def test_underlay_extended_edge_gets_loopback0_and_p2p():
    res = _run(orch.orchestrate_fabric_underlay(
        spines=["S1"], leafs=["L1"], underlay_subnet="10.1.0.0/29",
        loopback0_subnet="10.2.0.0/29",
        cabling=[{"a_device": "S1", "a_interface": "1/1/1",
                  "b_device": "L1", "b_interface": "1/1/49"}],
        extended_edges=[{"edge": "E1", "stub": "L1",
                         "links": [{"stub_interface": "1/1/10", "edge_interface": "1/1/52"}]}]))
    alloc = res["ip_allocation"]
    assert "E1" in alloc["loopback0"]
    edge_link = [l for l in alloc["p2p_links"] if l.get("extended_edge")][0]
    assert edge_link["a_device"] == "L1" and edge_link["b_device"] == "E1"
    assert any(s["action"] == "add_ospf_interface" and s["interface"] == "1/1/52"
               for s in res["plan"]["E1"])


def test_underlay_extended_edge_stub_must_be_leaf():
    res = _run(orch.orchestrate_fabric_underlay(
        spines=["S1"], leafs=["L1"], underlay_subnet="10.1.0.0/29",
        loopback0_subnet="10.2.0.0/29",
        cabling=[{"a_device": "S1", "a_interface": "1/1/1",
                  "b_device": "L1", "b_interface": "1/1/49"}],
        extended_edges=[{"edge": "E1", "stub": "X",
                         "links": [{"stub_interface": "1", "edge_interface": "2"}]}]))
    assert res["status"] == "invalid_input"


# ─── D7 batch deletes ──────────────────────────────────────────────────────

def test_vlan_cascade_delete_plan(inv):
    res = _run(tools_configure.configure_vlan(vlans=[10, 20], device="S1",
                                              delete=True, cascade=True))
    acts = [s["action"] for s in res["plan"]["S1"]]
    assert acts[:4] == ["delete_svi", "delete_evpn_vlan_rt", "delete_l2vni", "delete_vlan"]
    assert len(acts) == 8


def test_svi_and_static_route_batch_delete_plan(inv):
    res = _run(tools_configure.configure_svi(vlans=[10, 20, 30], device="S1", delete=True))
    assert [s["vlan"] for s in res["plan"]["S1"]] == [10, 20, 30]
    res = _run(tools_configure.configure_static_route(
        device="S1", prefixes=["10.0.0.0/8", "0.0.0.0/0"], delete=True))
    assert [s["prefix"] for s in res["plan"]["S1"]] == ["10.0.0.0/8", "0.0.0.0/0"]


# ─── D8 VSF members ────────────────────────────────────────────────────────

def test_vsf_secondary_member_flagged_and_not_targetable(inv):
    assert server_core._vsf_member_of("Campus-6300-VSF2") == "Campus-6300-VSF"
    assert server_core._vsf_member_of("Campus-6300-VSF") is None
    with pytest.raises(ValueError, match="member of 'Campus-6300-VSF'"):
        server_core._resolve_devices(device="Campus-6300-VSF2")
    assert "Campus-6300-VSF2" not in server_core._resolve_devices(site="lab")
    listed = {d["name"]: d for d in server_core.list_devices()["devices"]}
    assert listed["Campus-6300-VSF2"]["vsf_member_of"] == "Campus-6300-VSF"
