"""orchestrate_overlay (device-level VTEP bring-up) and
orchestrate_overlay_service (batch VLAN->L2VNI->EVPN/static service),
plus the generic `orchestrator` name/params dispatcher in flat_tools.py.
Plan-mode only (no client I/O needed — mirrors tests/test_orchestrators_wave3.py)."""
import asyncio

import pytest

from core import server_core
from core.config import DeviceConfig
from tools import tools_orchestrate as orch


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture
def inv(monkeypatch):
    def mk(name, host, site="lab"):
        return DeviceConfig(name=name, host=host, username="u", password="p", site=site)
    monkeypatch.setattr(server_core, "_devices", {
        "Core1": mk("Core1", "10.0.0.1"), "Core2": mk("Core2", "10.0.0.2"),
        "Edge": mk("Edge", "10.0.0.3")})


def _actions(res, dev):
    return [s["action"] for s in res["plan"][dev]]


# ── orchestrate_overlay ──────────────────────────────────────────────
def test_overlay_evpn_mode_full_plan(inv):
    res = _run(orch.orchestrate_overlay(
        device="Core1", source_ip="10.0.1.1", dest_udp_port=4789,
        evpn_options={"arp_suppression": True, "dyn_vxlan_tunnel_bridging_mode": "ibgp-ebgp"},
        virtual_mac="02:00:00:00:aa:01",
        bgp_evpn={"asn": 65000, "router_id": "10.0.0.1",
                  "neighbors": [{"neighbor": "10.0.1.2", "remote_as": 65000,
                                "update_source": "10.0.1.1", "activate": ["l2vpn-evpn"]}]}))
    assert res["status"] == "planned"
    assert _actions(res, "Core1") == [
        "ensure_vxlan_interface", "configure_evpn_global", "set_virtual_mac",
        "ensure_bgp_router", "configure_bgp_neighbors"]
    steps = res["plan"]["Core1"]
    assert steps[0]["source_ip"] == "10.0.1.1" and steps[0]["dest_udp_port"] == 4789
    assert steps[2]["mac"] == "02:00:00:00:aa:01"
    assert steps[3]["asn"] == 65000
    assert steps[4]["neighbors"] == ["10.0.1.2"]
    assert "warnings" not in res


def test_overlay_no_bgp_by_default_and_virtual_mac_warning(inv):
    res = _run(orch.orchestrate_overlay(device="Core1", source_ip="10.0.1.1"))
    assert _actions(res, "Core1") == ["ensure_vxlan_interface", "configure_evpn_global"]
    assert any("virtual_mac" in w for w in res.get("warnings", []))


def test_overlay_stub_mode_defaults_bridging(inv):
    res = _run(orch.orchestrate_overlay(device="Core1", source_ip="10.0.1.1", mode="stub"))
    assert res["plan"]["Core1"][0]["inter_vxlan_bridging_mode"] == "static-evpn"
    # explicit override still respected
    res = _run(orch.orchestrate_overlay(device="Core1", source_ip="10.0.1.1", mode="stub",
                                        inter_vxlan_bridging_mode="static-all"))
    assert res["plan"]["Core1"][0]["inter_vxlan_bridging_mode"] == "static-all"


def test_overlay_static_mode_skips_evpn_bgp_mac(inv):
    res = _run(orch.orchestrate_overlay(
        device="Core1", source_ip="10.0.2.1", mode="static",
        evpn_options={"arp_suppression": True}, virtual_mac="02:00:00:00:aa:01",
        bgp_evpn={"asn": 65000}))
    assert _actions(res, "Core1") == ["ensure_vxlan_interface"]
    assert res["skipped"] == {"evpn_options": True, "virtual_mac": True, "bgp_evpn": True}


def test_overlay_validation(inv):
    assert _run(orch.orchestrate_overlay(device="Core1", mode="bogus"))["field"] == "mode"
    assert _run(orch.orchestrate_overlay(device="Core1",
                                         source_ip="not-an-ip"))["field"] == "source_ip[Core1]"
    assert _run(orch.orchestrate_overlay(device="Core1",
                                         bgp_evpn={"router_id": "10.0.0.1"}))["field"] == "bgp_evpn.asn"
    assert _run(orch.orchestrate_overlay(
        device="Core1", inter_vxlan_bridging_mode="x"))["field"] == "inter_vxlan_bridging_mode"


def test_overlay_delete_plan(inv):
    res = _run(orch.orchestrate_overlay(
        device="Core1", bgp_evpn={"asn": 65000, "neighbors": [{"neighbor": "10.0.1.2"}]},
        delete=True, delete_vxlan_interface=True))
    assert _actions(res, "Core1") == ["delete_bgp_neighbor", "delete_interface"]
    assert _run(orch.orchestrate_overlay(device="Core1", delete=True))["field"] == "delete"


# ── orchestrate_overlay_service ──────────────────────────────────────
def test_overlay_service_batch_evpn_and_static_and_stub(inv):
    res = _run(orch.orchestrate_overlay_service(
        device="Core1",
        services=[
            {"vlan_id": 100, "vni": 10100, "attach": "evpn", "svi_vrf": "TENANT",
             "svi_ip": "10.100.0.2/24"},
            {"vlan_id": 105, "vni": 10105, "attach": "static",
             "static_peers": [{"destination": "10.0.9.9"}]},
            {"vlan_id": 106, "vni": 10106, "attach": "stub",
             "static_peers": [{"destination": "10.0.9.9", "vnis": [10106]}]},
        ]))
    assert res["status"] == "planned"
    actions = _actions(res, "Core1")
    assert actions == [
        "check_vxlan_interface",
        "create_vlan", "create_l2vni", "set_evpn_vlan_rt", "create_svi",
        "create_vlan", "create_l2vni", "add_static_vxlan_peer",
        "create_vlan", "create_l2vni", "set_evpn_vlan_rt", "add_static_vxlan_peer",
    ]
    steps = res["plan"]["Core1"]
    assert steps[7]["destination"] == "10.0.9.9" and steps[7]["vnis"] == [10105]
    assert steps[11]["destination"] == "10.0.9.9" and steps[11]["vnis"] == [10106]


def test_overlay_service_requires_static_peers_for_static_and_stub(inv):
    for attach in ("static", "stub"):
        res = _run(orch.orchestrate_overlay_service(
            device="Core1", services=[{"vlan_id": 100, "vni": 10100, "attach": attach}]))
        assert res["status"] == "invalid_input" and "static_peers" in res["field"]


def test_overlay_service_validation(inv):
    assert _run(orch.orchestrate_overlay_service(device="Core1", services=None))["field"] == "services"
    assert _run(orch.orchestrate_overlay_service(device="Core1", services=[{"vlan_id": 1}]))["field"] == "services[0]"
    assert _run(orch.orchestrate_overlay_service(
        device="Core1", services=[{"vlan_id": 1, "vni": 100, "attach": "bogus"}]))["field"] == "services[0].attach"


def test_overlay_service_require_vxlan_interface_flag(inv):
    res = _run(orch.orchestrate_overlay_service(
        device="Core1", require_vxlan_interface=False,
        services=[{"vlan_id": 100, "vni": 10100}]))
    assert _actions(res, "Core1") == ["create_vlan", "create_l2vni", "set_evpn_vlan_rt"]


def test_overlay_service_delete_plan_reverse_order(inv):
    res = _run(orch.orchestrate_overlay_service(
        device="Core1", delete=True,
        services=[
            {"vlan_id": 100, "vni": 10100, "attach": "evpn", "svi_ip": "10.100.0.2/24"},
            {"vlan_id": 105, "vni": 10105, "attach": "static",
             "static_peers": [{"destination": "10.0.9.9"}]},
        ]))
    assert _actions(res, "Core1") == [
        "remove_static_vxlan_peer", "delete_l2vni", "delete_vlan",
        "delete_svi", "delete_evpn_vlan_rt", "delete_l2vni", "delete_vlan",
    ]


# ── generic `orchestrator` dispatcher (flat_tools.py) ────────────────
def test_generic_orchestrator_dispatcher_routes_to_overlay(monkeypatch, inv):
    import server
    from dispatch import flat_tools

    monkeypatch.setattr(flat_tools, "_SRV", server)
    res = _run(flat_tools.orchestrator(
        name="overlay", action="plan", device="Core1",
        params={"source_ip": "10.0.1.1", "mode": "stub"}))
    assert res["status"] == "planned"
    assert res["plan"]["Core1"][0]["inter_vxlan_bridging_mode"] == "static-evpn"


def test_generic_orchestrator_dispatcher_unknown_name_and_action(monkeypatch, inv):
    import server
    from dispatch import flat_tools

    monkeypatch.setattr(flat_tools, "_SRV", server)
    res = _run(flat_tools.orchestrator(name="bogus", action="plan", device="Core1"))
    assert "unknown name" in res["error"] and "overlay" in res["valid_names"]
    res = _run(flat_tools.orchestrator(name="overlay", action="bogus", device="Core1"))
    assert "invalid action" in res["error"]


def test_generic_orchestrator_dispatcher_excludes_fabric_underlay():
    from dispatch import flat_tools
    assert "fabric_underlay" not in flat_tools._MAP_ORCHESTRATORS
