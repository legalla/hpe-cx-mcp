"""Wave 3: orchestrators (vsx_pair / l3_link / access_port / radius_dot1x) and
hostname batch — plan shape, validation, create vs delete step lists, and a
fake-client execution of the step runner."""
import asyncio

import pytest

from clients.aruba_client import ArubaAPIError
from core import server_core
from core.config import DeviceConfig
from tools import tools_configure, tools_orchestrate as orch


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture
def inv(monkeypatch):
    def mk(name, host, site="lab"):
        return DeviceConfig(name=name, host=host, username="u", password="p", site=site)
    monkeypatch.setattr(server_core, "_devices", {
        "Core1": mk("Core1", "10.0.0.1"), "Core2": mk("Core2", "10.0.0.2"),
        "Edge": mk("Edge", "10.0.0.3")})


@pytest.fixture
def vsx_pairs(monkeypatch):
    """Pretend Core1/Core2 are one VSX cluster; anything else is not."""
    async def _fake(a, b):
        ok = {a, b} == {"Core1", "Core2"}
        return ok, "" if ok else f"{a}/{b} not VSX peers (test)"
    monkeypatch.setattr(tools_configure, "_is_vsx_pair", _fake)


def _actions(res, dev):
    return [s["action"] for s in res["plan"][dev]]


# ── hostname batch ───────────────────────────────────────────────────
def test_hostname_batch_dict_and_list(inv):
    res = _run(tools_configure.configure_hostname(hostnames={"Core1": "c1", "10.0.0.2": "c2"}))
    assert res["status"] == "planned"
    assert res["plan"] == {"Core1": {"hostname": "c1"}, "Core2": {"hostname": "c2"}}
    res = _run(tools_configure.configure_hostname(
        hostnames=[{"device": "Edge", "hostname": "edge-1"}]))
    assert res["plan"] == {"Edge": {"hostname": "edge-1"}}


def test_hostname_batch_validation(inv):
    assert _run(tools_configure.configure_hostname(hostnames={"Core1": "-bad"}))["status"] == "invalid_input"
    assert _run(tools_configure.configure_hostname(hostnames=[{"device": "Core1"}]))["status"] == "invalid_input"
    assert _run(tools_configure.configure_hostname(hostnames="Core1=c1"))["status"] == "invalid_input"
    # site restricts the batch
    res = _run(tools_configure.configure_hostname(hostnames={"Core1": "c1", "Edge": "e"}, device="Edge"))
    assert list(res["plan"]) == ["Edge"]
    # one hostname for many devices is refused
    assert _run(tools_configure.configure_hostname("x", device="Core1,Core2"))["status"] == "error"


# ── vsx_pair ─────────────────────────────────────────────────────────
_VSX = dict(device="Core1", peer_device="Core2", isl_members=["1/1/49", "1/1/50"],
            keepalive_interface="1/1/48", keepalive_ip="192.168.255.1/30",
            peer_keepalive_ip="192.168.255.2/30", system_mac="02:00:00:00:01:00",
            config_sync_features=["vlan", "vrf"], linkup_delay_timer=30, split_recovery=True)


def test_vsx_pair_plan_is_asymmetric(inv):
    res = _run(orch.orchestrate_vsx_pair(**_VSX))
    assert res["status"] == "planned" and res["targets"] == ["Core1", "Core2"]
    for d in ("Core1", "Core2"):
        assert _actions(res, d) == ["ensure_vrf", "configure_routed_interface", "configure_lag",
                                    "configure_vsx"]
    p1 = res["plan"]["Core1"][3]
    p2 = res["plan"]["Core2"][3]
    assert (p1["role"], p2["role"]) == ("primary", "secondary")
    assert p1["keepalive_src_ip"] == "192.168.255.1" and p1["keepalive_peer_ip"] == "192.168.255.2"
    assert p2["keepalive_src_ip"] == "192.168.255.2" and p2["keepalive_peer_ip"] == "192.168.255.1"
    assert p1["system_mac"] == p2["system_mac"] == "02:00:00:00:01:00"
    assert p1["config_sync_features"] == ["vlan", "vrf"] and p1["split_recovery_disable"] is False
    assert res["plan"]["Core1"][2]["lag"] == "lag256"
    assert "_run" not in p1


def test_vsx_pair_validation(inv):
    assert _run(orch.orchestrate_vsx_pair(device="Core1"))["field"] == "peer_device"
    assert _run(orch.orchestrate_vsx_pair(device="Core1", peer_device="Core1"))["field"] == "device"
    bad = dict(_VSX, peer_keepalive_ip="10.9.9.2/30")
    assert _run(orch.orchestrate_vsx_pair(**bad))["field"] == "peer_keepalive_ip"
    bad = dict(_VSX, config_sync_features=["bogus"])
    assert _run(orch.orchestrate_vsx_pair(**bad))["field"] == "config_sync_features"
    bad = dict(_VSX); del bad["isl_members"]
    assert _run(orch.orchestrate_vsx_pair(**bad))["status"] == "invalid_input"


def test_vsx_pair_delete_plan(inv):
    res = _run(orch.orchestrate_vsx_pair(device="Core1", peer_device="Core2",
                                         keepalive_interface="1/1/48", delete=True))
    assert res["status"] == "planned"
    assert _actions(res, "Core1") == ["delete_vsx", "delete_interface", "reset_routed_interface",
                                      "delete_vrf"]
    res = _run(orch.orchestrate_vsx_pair(device="Core1", peer_device="Core2", delete=True,
                                         delete_keepalive_vrf=False))
    assert _actions(res, "Core2") == ["delete_vsx", "delete_interface"]


# ── l3_link ──────────────────────────────────────────────────────────
def test_l3_link_plan_with_evpn_vrf_and_ospf(inv):
    res = _run(orch.orchestrate_l3_link(
        "1/1/1", device="Core1,Core2", ip_address={"Core1": "10.1.1.0/31", "Core2": "10.1.1.1/31"},
        vrf="TENANT",
        vrf_rd="65000:10", vrf_import_rts=["65000:10"], vrf_export_rts=["65000:10"],
        mtu=9100, ospf_area="0.0.0.0"))
    assert res["status"] == "planned" and res["targets"] == ["Core1", "Core2"]
    assert _actions(res, "Core1") == [
        "ensure_vrf", "configure_routed_interface", "ensure_ospf_router",
        "ensure_ospf_area", "add_ospf_interface", "configure_ospf_interface_options"]
    assert res["plan"]["Core1"][0]["rd"] == "65000:10"
    assert res["plan"]["Core1"][0]["evpn_import_rts"] == ["65000:10"]
    assert res["plan"]["Core1"][1]["ip4_address"] == "10.1.1.0/31"
    assert res["plan"]["Core2"][1]["ip4_address"] == "10.1.1.1/31"


def test_l3_link_same_ip_on_two_devices_refused_unless_vsx(inv, vsx_pairs):
    res = _run(orch.orchestrate_l3_link("1/1/1", device="Core1,Edge", ip_address="10.1.1.0/31"))
    assert res["status"] == "invalid_input" and res["field"] == "ip_address"
    assert "VSX" in res["error"]
    res = _run(orch.orchestrate_l3_link("1/1/1", device="Core1,Core2", ip_address="10.1.1.0/31"))
    assert res["status"] == "planned"  # VSX peers may share
    res = _run(orch.orchestrate_l3_link("1/1/1", device="Core1,Core2,Edge", ip_address="10.1.1.0/31"))
    assert res["status"] == "invalid_input" and "mapping" in res["error"]
    res = _run(orch.orchestrate_l3_link("1/1/1", device="Core1,Core2",
                                        ip_address={"Core1": "10.1.1.0/31"}))
    assert res["status"] == "invalid_input" and "Core2" in res["error"]


def test_l3_link_default_vrf_no_ospf(inv):
    res = _run(orch.orchestrate_l3_link("1/1/1", device="Core1", ip_address="10.1.1.0/31"))
    assert _actions(res, "Core1") == ["configure_routed_interface"]
    assert _run(orch.orchestrate_l3_link("1/1/1", device="Core1"))["field"] == "ip_address"
    assert _run(orch.orchestrate_l3_link("1/1/1", device="Core1", ip_address="10.1.1.0/31",
                                         vrf_rd="nope"))["status"] == "invalid_input"


def test_l3_link_delete_plan(inv):
    res = _run(orch.orchestrate_l3_link("1/1/1", device="Core1", vrf="TENANT", ospf_area="0",
                                        delete=True, delete_vrf=True))
    assert _actions(res, "Core1") == ["remove_ospf_interface", "reset_routed_interface", "delete_vrf"]


# ── access_port ──────────────────────────────────────────────────────
def test_access_port_plan(inv):
    res = _run(orch.orchestrate_access_port(
        "1/1/1-1/1/3", device="Edge", access_vlan=10, voice_vlan=20, description="users",
        port_auth={"dot1x": True, "mac_auth": True, "auth_precedence": "dot1x mac-auth",
                   "roles": {"reject": "QUARANTINE"}}))
    assert res["status"] == "planned"
    steps = res["plan"]["Edge"]
    assert [s["action"] for s in steps] == ["configure_l2_access_port", "configure_port_auth"]
    assert steps[0]["interfaces"] == ["1/1/1", "1/1/2", "1/1/3"]
    assert steps[0]["stp"] == {"admin_edge_port_enable": True, "bpdu_guard_enable": True}
    assert steps[1]["methods"] == {"dot1x": {"auth_enable": True}, "mac-auth": {"auth_enable": True}}
    assert steps[1]["auth_precedence"] == ["dot1x", "mac-auth"]


def test_access_port_validation_and_delete(inv):
    assert _run(orch.orchestrate_access_port("", device="Edge"))["field"] == "interfaces"
    assert _run(orch.orchestrate_access_port("1/1/1", device="Edge", access_vlan=5000))["status"] == "invalid_input"
    bad = _run(orch.orchestrate_access_port("1/1/1", device="Edge", port_auth={"methods": "dot1x"}))
    assert bad["status"] == "invalid_input" and "expected_schema" in bad
    res = _run(orch.orchestrate_access_port("1/1/1-2", device="Edge", delete=True))
    assert _actions(res, "Edge") == ["clear_port_auth", "reset_l2_access_port"]


# ── radius_dot1x ─────────────────────────────────────────────────────
_RAD = dict(device="Edge", radius_servers=[{"address": "10.10.10.10", "passkey": "s3cret",
                                             "tracking_enable": True}],
            roles=[{"name": "QUARANTINE", "vlan_tag": 999}], interfaces="1/1/1-1/1/2")


def test_radius_dot1x_plan(inv):
    res = _run(orch.orchestrate_radius_dot1x(**_RAD))
    assert res["status"] == "planned"
    steps = res["plan"]["Edge"]
    assert [s["action"] for s in steps] == [
        "ensure_aaa_server_group", "ensure_radius_server", "set_port_access_global",
        "create_port_access_role", "configure_port_auth"]
    assert steps[1]["passkey"] == "***"  # never echoed in the plan
    glob = steps[2]
    assert glob["dot1x_enable"] and glob["mac_auth_enable"] and glob["coa_enable"]
    assert glob["server_group"] == "RADIUS"
    assert steps[4]["methods"] == {"dot1x": {"auth_enable": True}, "mac-auth": {"auth_enable": True}}
    assert steps[4]["auth_precedence"] == ["dot1x", "mac-auth"]


def test_radius_dot1x_mac_only_and_validation(inv):
    res = _run(orch.orchestrate_radius_dot1x(**dict(_RAD, dot1x=False)))
    assert res["plan"]["Edge"][4]["methods"] == {"mac-auth": {"auth_enable": True}}
    assert _run(orch.orchestrate_radius_dot1x(device="Edge"))["field"] == "radius_servers"
    assert _run(orch.orchestrate_radius_dot1x(
        device="Edge", radius_servers=[{"address": "nope"}]))["status"] == "invalid_input"
    assert _run(orch.orchestrate_radius_dot1x(
        device="Edge", radius_servers=[{"address": "10.0.0.1"}], roles=[{"vlan_tag": 1}]))["field"] == "roles[0]"


def test_radius_dot1x_delete_plan_reverse_order(inv):
    res = _run(orch.orchestrate_radius_dot1x(**_RAD, delete=True))
    assert _actions(res, "Edge") == [
        "clear_port_auth", "delete_port_access_role", "set_port_access_global",
        "delete_radius_server", "delete_aaa_server_group"]
    assert res["plan"]["Edge"][2] == {"action": "set_port_access_global", "dot1x_enable": False,
                                      "mac_auth_enable": False, "coa_enable": False}


# ── evpn_vlan ────────────────────────────────────────────────────────
def test_evpn_vlan_full_plan_explicit_rd_rt(inv):
    res = _run(orch.orchestrate_evpn_vlan(
        100, device="Core1,Core2", name="USERS", vni=10100,
        vxlan_source_ip={"Core1": "10.0.0.1", "Core2": "10.0.0.2"},
        rd="65000:100", import_rts="65000:100 1:100", export_rts=["65000:100"],
        route_target_auto_mode="default", svi_vrf="TENANT", svi_ip="10.100.0.2/24",
        active_gateway_ip="10.100.0.1", active_gateway_mac="00:00:00:00:00:01"))
    assert res["status"] == "planned" and res["targets"] == ["Core1", "Core2"]
    steps = res["plan"]["Core1"]
    assert [s["action"] for s in steps] == ["create_vlan", "ensure_vxlan_interface", "create_l2vni",
                                            "set_evpn_vlan_rt", "create_svi"]
    assert steps[2] == {"action": "create_l2vni", "vni": 10100, "vlan": 100, "interface": "vxlan1"}
    assert steps[1]["source_ip"] == "10.0.0.1"
    assert res["plan"]["Core2"][1]["source_ip"] == "10.0.0.2"
    assert steps[3]["rd"] == "65000:100"
    assert steps[3]["import_route_targets"] == ["65000:100", "1:100"]
    assert steps[3]["route_target_auto_mode"] == "default"
    assert steps[4]["vrf"] == "TENANT" and steps[4]["active_gateway_ip"] == "10.100.0.1"


def test_evpn_vlan_defaults_auto_and_no_svi(inv):
    res = _run(orch.orchestrate_evpn_vlan(100, device="Core1", vni=10100))
    steps = res["plan"]["Core1"]
    assert [s["action"] for s in steps] == ["create_vlan", "create_l2vni", "set_evpn_vlan_rt"]
    assert steps[2]["rd"] == "auto" and steps[2]["import_route_targets"] == ["auto"]
    res = _run(orch.orchestrate_evpn_vlan(100, device="Core1", vni=10100, evpn=False))
    assert [s["action"] for s in res["plan"]["Core1"]] == ["create_vlan", "create_l2vni"]


def test_evpn_vlan_validation_and_delete(inv):
    assert _run(orch.orchestrate_evpn_vlan(100, device="Core1"))["field"] == "vni"
    assert _run(orch.orchestrate_evpn_vlan(100, device="Core1", vni=10100, rd="bad"))["status"] == "invalid_input"
    assert _run(orch.orchestrate_evpn_vlan(100, device="Core1", vni=10100,
                                           import_rts=["nope"]))["status"] == "invalid_input"
    assert _run(orch.orchestrate_evpn_vlan(100, device="Core1", vni=10100,
                                           route_target_auto_mode="x"))["field"] == "route_target_auto_mode"
    res = _run(orch.orchestrate_evpn_vlan(100, device="Core1", vni=10100, delete=True))
    assert _actions(res, "Core1") == ["delete_svi", "delete_evpn_vlan_rt", "delete_l2vni", "delete_vlan"]
    res = _run(orch.orchestrate_evpn_vlan(100, device="Core1", delete=True))
    assert _actions(res, "Core1") == ["delete_svi", "delete_evpn_vlan_rt", "delete_vlan"]
    assert "warning" in res


# ── static_vxlan ─────────────────────────────────────────────────────
def test_static_vxlan_full_plan(inv):
    res = _run(orch.orchestrate_static_vxlan(
        device="Core1,Core2", source_ip={"Core1": "10.0.0.1", "Core2": "10.0.0.2"},
        inter_vxlan_bridging_mode="static-all",
        vlans=[{"vlan_id": 10, "vni": 10010, "name": "A"}, [20, 10020]],
        peers=[{"destination": "10.0.0.3", "vnis": [10010]}]))
    assert res["status"] == "planned" and res["targets"] == ["Core1", "Core2"]
    steps = res["plan"]["Core1"]
    assert [s["action"] for s in steps] == [
        "ensure_vxlan_interface", "create_vlan", "create_l2vni", "create_vlan", "create_l2vni",
        "add_static_vxlan_peer", "add_static_vxlan_peer"]
    assert steps[0]["source_ip"] == "10.0.0.1" and steps[0]["inter_vxlan_bridging_mode"] == "static-all"
    # explicit peer, then the auto-mesh peer (the OTHER VTEP, never itself)
    assert steps[5]["destination"] == "10.0.0.3" and steps[5]["vnis"] == [10010]
    assert steps[6]["destination"] == "10.0.0.2" and steps[6]["vnis"] == [10010, 10020] and steps[6]["mesh"]
    c2 = res["plan"]["Core2"]
    assert c2[0]["source_ip"] == "10.0.0.2"
    assert [p["destination"] for p in c2 if p["action"] == "add_static_vxlan_peer"] == ["10.0.0.3", "10.0.0.1"]


def test_static_vxlan_source_ip_rules(inv, vsx_pairs):
    res = _run(orch.orchestrate_static_vxlan(device="Core1,Edge", source_ip="10.0.0.9", vlans={"10": 10010}))
    assert res["status"] == "invalid_input" and res["field"] == "source_ip"
    res = _run(orch.orchestrate_static_vxlan(device="Core1,Core2", source_ip="10.0.0.9", vlans={"10": 10010}))
    assert res["status"] == "planned"  # anycast VTEP on a VSX pair
    assert [s["action"] for s in res["plan"]["Core1"]] == ["ensure_vxlan_interface", "create_vlan", "create_l2vni"]
    res = _run(orch.orchestrate_static_vxlan(
        device="Core1,Edge", source_ip={"Core1": "10.0.0.1", "Edge": "10.0.0.1"}, vlans={"10": 10010}))
    assert res["status"] == "invalid_input" and "not a VSX pair" in res["error"]
    res = _run(orch.orchestrate_static_vxlan(
        device="Core1,Edge", source_ip={"Core1": "10.0.0.1", "Edge": "10.0.0.3"}, vlans={"10": 10010},
        full_mesh=False))
    assert [s["action"] for s in res["plan"]["Core1"]] == ["ensure_vxlan_interface", "create_vlan", "create_l2vni"]


def test_static_vxlan_dict_form_validation_delete(inv):
    res = _run(orch.orchestrate_static_vxlan(device="Core1", vlans={"10": 10010}))
    assert [s["action"] for s in res["plan"]["Core1"]] == ["ensure_vxlan_interface", "create_vlan", "create_l2vni"]
    assert _run(orch.orchestrate_static_vxlan(device="Core1"))["field"] == "vlans"
    assert _run(orch.orchestrate_static_vxlan(device="Core1", vlans=[{"vlan_id": 10}]))["field"] == "vlans[0]"
    assert _run(orch.orchestrate_static_vxlan(
        device="Core1", peers=[{"destination": "10.0.0.2"}]))["field"] == "peers[0].vnis"
    assert _run(orch.orchestrate_static_vxlan(
        device="Core1", vlans={"10": 10010}, inter_vxlan_bridging_mode="x"))["field"] == "inter_vxlan_bridging_mode"
    res = _run(orch.orchestrate_static_vxlan(
        device="Core1", vlans={"10": 10010}, peers=[{"destination": "10.0.0.2"}],
        delete=True, delete_vxlan_interface=True))
    assert _actions(res, "Core1") == ["remove_static_vxlan_peer", "delete_l2vni", "delete_vlan", "delete_interface"]
    res = _run(orch.orchestrate_static_vxlan(device="Core1", vlans={"10": 10010}, delete=True, delete_vlans=False))
    assert _actions(res, "Core1") == ["delete_l2vni"]


# ── step runner ──────────────────────────────────────────────────────
def test_run_steps_stops_at_first_failure():
    class C:
        pass

    async def ok(c):
        return {"status": "created"}

    async def boom(c):
        raise ArubaAPIError("nope", 400)

    steps = [orch._step("a", ok), orch._step("b", boom), orch._step("c", ok)]
    with pytest.raises(ArubaAPIError) as exc:
        _run(orch._run_steps("dev", C(), steps))
    assert "step 'b' failed after 1 step(s)" in str(exc.value)
    res = _run(orch._run_steps("dev", C(), steps[:1]))
    assert res["steps"] == [{"action": "a", "result": {"status": "created"}}]
    assert orch._plan_view(steps)[0] == {"action": "a"}
