"""Regression tests for the legacy->fabric migration agent feedback (2026-10-01):
vxlan1 creation, OSPF/BGP REST write fidelity, admin-state flap, VRF/L3VNI,
concurrent-session close, token restore/origin, ignored-param reporting."""
import asyncio

import pytest

from clients.aruba_client import ArubaAPIError, ArubaOSCXClient, _v_vrf_rd, _v_vrf_route_target
from core import server_core
from core.config import DeviceConfig
from dispatch import flat_tools
from dispatch.write_safety import WriteSafety
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
        "A": mk("A", "10.0.0.1"), "B": mk("B", "10.0.0.2")})


class _Stateful:
    """GET/POST/PUT/DELETE stub backed by a dict that really changes."""

    def __init__(self, client, resources=None, reject_post=None):
        self.res = dict(resources or {})
        self.posts, self.puts, self.deletes = [], [], []
        self.reject_post = reject_post or (lambda path, body: None)

        async def _get(path, params=None, _retried=False):
            if path not in self.res:
                raise ArubaAPIError(f"Resource not found: {path}", 404)
            return dict(self.res[path])

        async def _post(path, body=None, params=None, _retried=False):
            err = self.reject_post(path, body)
            if err:
                raise ArubaAPIError(err, 400)
            self.posts.append((path, body))
            key = body.get("interface_name") or body.get("ip_or_ifname_or_group_name") \
                or body.get("name")
            from urllib.parse import quote
            self.res[f"{path}/{quote(str(key), safe='')}"] = dict(body)
            return {}

        async def _put(path, body=None, params=None, _retried=False):
            self.puts.append((path, body))
            self.res[path] = dict(body)
            return {}

        async def _delete(path, _retried=False):
            self.deletes.append(path)
            self.res.pop(path, None)
            return {}

        client._get, client._post, client._put, client._delete = _get, _post, _put, _delete


# ─── #1 vxlan1 creation needs `type` ───────────────────────────────────────

def test_ensure_vxlan_interface_create_body_has_type(client):
    rec = _Recorder(client, {})
    res = _run(client.ensure_vxlan_interface("vxlan1", source_ip="10.1.1.1"))
    assert res["status"] == "created"
    _, body = rec.posts[0]
    assert body["type"] == "vxlan" and body["options"]["local_ip"] == "10.1.1.1"


# ─── #2 OSPF interface is created WITH its port binding ────────────────────

OSPF_BASE = "/system/vrfs/default/ospf_routers/1/areas/0.0.0.0/ospf_interfaces"


def test_add_ospf_interface_binds_port_in_the_creating_post(client):
    st = _Stateful(client)
    res = _run(client.add_ospf_interface("1/1/1", "0.0.0.0"))
    assert res["status"] == "created"
    _, body = st.posts[0]
    assert body["interface_name"] == "1/1/1"
    assert list(body["port"]) == ["1/1/1"]          # map form, bound at creation
    assert st.puts == []                              # no late binding PUT


def test_add_ospf_interface_falls_back_to_split_write(client):
    st = _Stateful(client, reject_post=lambda p, b: "Invalid data" if "port" in b else None)
    res = _run(client.add_ospf_interface("1/1/1", "0.0.0.0"))
    assert res["status"] == "created"
    assert st.puts and "port" in st.puts[-1][1]


def test_add_ospf_interface_rebinds_row_without_port(client):
    key = OSPF_BASE + "/1%2F1%2F1"
    st = _Stateful(client, {key: {"interface_name": "1/1/1"}})
    res = _run(client.add_ospf_interface("1/1/1", "0.0.0.0"))
    assert res["status"] == "rebound"
    assert st.deletes == [key] and st.posts


# ─── #3 BGP ────────────────────────────────────────────────────────────────

def test_send_community_both_maps_to_extended_for_evpn():
    n = ArubaOSCXClient._norm_send_community
    assert n("both", {"l2vpn-evpn": True}) == {"l2vpn-evpn": "extended"}
    assert n({"l2vpn-evpn": "both"}) == {"l2vpn-evpn": "extended"}
    assert n({"ipv4-unicast": "both"}) == {"ipv4-unicast": "both"}
    assert n(["l2vpn-evpn"]) == {"l2vpn-evpn": "extended"}


def test_bgp_neighbor_creation_is_explicitly_not_shutdown(client):
    st = _Stateful(client)
    _run(client.create_bgp_neighbor("10.0.0.1", 65000, remote_as=65000,
                                    activate={"l2vpn-evpn": True}))
    _, body = st.posts[0]
    assert body["shutdown"] is False and body["activate"] == {"l2vpn-evpn": True}


def test_bgp_neighbor_reports_fields_the_device_dropped(client):
    st = _Stateful(client)
    orig_post = client._post

    async def _lossy(path, body=None, params=None, _retried=False):
        await orig_post(path, {k: v for k, v in body.items() if k != "activate"})
    client._post = _lossy
    res = _run(client.create_bgp_neighbor("10.0.0.1", 65000, remote_as=65000,
                                          activate={"l2vpn-evpn": True}))
    assert res["status"] == "partial" and "activate.l2vpn-evpn" in res["not_applied"]


def test_peer_group_ref_uses_map_form(client):
    st = _Stateful(client)
    _run(client.create_bgp_neighbor("10.0.0.1", 65000, remote_as=65000, peer_group="spine-RR"))
    ref = st.posts[0][1]["bgp_peer_group"]
    assert isinstance(ref, dict) and list(ref) == ["spine-RR"]


def test_configure_bgp_members_inherit_peer_group_settings(inv, monkeypatch):
    calls = []

    class _C:
        async def ensure_bgp_router(self, *a, **k):
            return {"status": "already_exists"}

        async def create_bgp_neighbor(self, name, asn, **kw):
            calls.append((name, kw))
            return {"neighbor": name, "status": "created"}

    async def _fake_domain(op, device, site, plan, executor, apply):
        return {"result": await executor("A", _C())}
    monkeypatch.setattr(tools_configure, "_domain_write", _fake_domain)
    _run(tools_configure.configure_bgp(
        65000, device="A", apply=True, neighbors=[
            {"neighbor": "10.0.0.1", "peer_group": "RR", "remote_as": 65000},
            {"neighbor": "RR", "is_peer_group": True, "update_source": "10.9.9.9",
             "activate": ["l2vpn-evpn"], "route_reflector_client": ["l2vpn-evpn"]},
        ]))
    assert [c[0] for c in calls] == ["RR", "10.0.0.1"]        # group first
    member = dict(calls[1][1])
    assert member["activate"] == {"l2vpn-evpn": True}
    # 2026-10-05: inherited attributes stay on the group (CLI conflict otherwise)
    assert member["update_source"] is None
    assert member["route_reflector_client"] is None
    assert member["remote_as"] == 65000


# ─── #4 admin state: real flap when the operational state disagrees ────────

def test_ensure_operational_admin_flaps_when_admin_state_lags(client, monkeypatch):
    async def _nosleep(_):
        return None
    monkeypatch.setattr(asyncio, "sleep", _nosleep)
    path = "/system/interfaces/1%2F1%2F5"
    state = {"admin_state": "down", "user_config": {"admin": "up"}}
    writes = []

    async def _get(p, params=None, _retried=False):
        return dict(state)

    async def _put(p, body=None, params=None, _retried=False):
        writes.append(body["user_config"]["admin"])
        state["user_config"] = dict(body["user_config"])
        if writes[-2:] == ["down", "up"]:
            state["admin_state"] = "up"
        return {}
    client._get, client._put = _get, _put
    ok, flapped = _run(client._ensure_operational_admin(path, "up"))
    assert ok and flapped and writes == ["down", "up"]


def test_ensure_operational_admin_noop_when_consistent(client, monkeypatch):
    async def _nosleep(_):
        return None
    monkeypatch.setattr(asyncio, "sleep", _nosleep)

    async def _get(p, params=None, _retried=False):
        return {"admin_state": "up"}
    client._get = _get
    assert _run(client._ensure_operational_admin("/x", "up")) == (True, False)


# ─── #5 internal-vlan-range via the l3_link orchestrator ───────────────────

def test_l3_link_exposes_internal_vlan_range_flags(inv):
    res = _run(orch.orchestrate_l3_link("1/1/1", device="A", ip_address="10.1.1.0/31",
                                        ensure_internal_vlan_range=True))
    assert res["status"] == "planned"


def test_dispatcher_reports_params_it_ignored():
    out = flat_tools._flag_ignored_params({"status": "planned"},
                                          {"vni": 20000, "name": "X"}, {"name": "X"}, "vrf")
    assert out["ignored_params"] == ["vni"] and "vni" in out["warning"]


# ─── #6 VRF ────────────────────────────────────────────────────────────────

def test_vrf_rd_auto_rejected_with_hint_but_rt_auto_accepted():
    with pytest.raises(ArubaAPIError, match="explicit"):
        _v_vrf_rd("auto")
    assert _v_vrf_rd("65000:20000") == "65000:20000"
    assert _v_vrf_route_target("auto") == "auto"


def test_configure_vrf_plan_carries_l3vni(inv):
    res = _run(tools_configure.configure_vrf("CAMPUS", device="A", rd="65000:20000",
                                             l3vni=20000))
    assert res["status"] == "planned"
    assert res["plan"]["A"]["l3vni"] == 20000 and res["plan"]["A"]["vxlan_interface"] == "vxlan1"
    res = _run(tools_configure.configure_vrf("CAMPUS", device="A", vni=20000))
    assert res["plan"]["A"]["l3vni"] == 20000
    assert _run(tools_configure.configure_vrf("CAMPUS", device="A", rd="auto"))["status"] == "invalid_input"


def test_ensure_vrf_flags_rd_not_kept(client):
    _Recorder(client, {})
    res = _run(client.ensure_vrf("CAMPUS", rd="65000:20000"))
    assert res["status"] == "created" and res["not_applied"] == ["rd"]


# ─── #7 concurrent applies must not close each other's session ─────────────

def test_close_sessions_defers_while_a_peer_is_active(inv, monkeypatch):
    class _Cl:
        _active = 1
        _close_when_idle = False
        closed = False

        async def logout(self):
            self.closed = True
            return True
    cl = _Cl()
    monkeypatch.setattr(server_core, "_CLIENT_POOL", {"A": {"client": cl, "last_used": 0}})
    assert _run(server_core._close_sessions(["A"])) == []
    assert cl._close_when_idle and not cl.closed and "A" in server_core._CLIENT_POOL


def test_last_user_closes_a_deferred_session(client):
    closed = []

    async def _disc():
        closed.append(True)
    client._disconnect = _disc

    async def _conn():
        return None
    client._connect = _conn
    client._auto_logout = False

    async def scenario():
        async with client:
            async with client:
                client._close_when_idle = True
            assert closed == []          # one user still inside
        assert closed == [True]
    _run(scenario())


# ─── #7 token is given back when nothing was written ───────────────────────

def test_nothing_written_detection():
    nw = flat_tools._nothing_written
    assert nw({"status": "error"})
    assert nw({"status": "partial", "results": {"A": {
        "ok": False, "error": "x [nothing written; auto-checkpoint disarmed]"}}})
    assert not nw({"status": "partial", "results": {"A": {"ok": False, "error": "boom"}}})
    assert not nw({"status": "applied", "results": {}})


def test_restore_and_origin_of_a_consumed_token(tmp_path, monkeypatch):
    monkeypatch.setenv("CX_WRITE_SAFETY", "true")
    ws = WriteSafety(str(tmp_path / "p.json"), str(tmp_path / "j.json"))
    planned = ws.freeze({"status": "planned"}, "op", ["A"], {"A": 1}, issued_by="s1")
    tok = planned["dry_run_token"]
    assert ws.token_origin(tok, "s1")["same_session"] is True
    assert ws.token_origin(tok, "s2")["same_session"] is False
    assert ws.token_origin(tok, None)["same_session"] is None
    assert ws.require_token(tok, "op", {"A": 1}) is None          # consumed
    assert ws.require_token(tok, "op", {"A": 1})["status"] == "error"
    assert ws.restore_token(tok)
    assert ws.require_token(tok, "op", {"A": 1}) is None


# ─── minors ────────────────────────────────────────────────────────────────

def test_configure_ospf_accepts_router_id_mapping_and_passive_interfaces(inv):
    res = _run(tools_configure.configure_ospf(
        device="A,B", router_id={"A": "10.0.0.1", "B": "10.0.0.2"},
        passive_interfaces=["loopback0"]))
    assert res["status"] == "planned"
    assert res["plan"]["A"]["router_id"] == "10.0.0.1"
    assert res["plan"]["B"]["router_id"] == "10.0.0.2"
    assert res["plan"]["A"]["passive_interfaces"] == ["loopback0"]


def test_l3_link_sets_point_to_point_and_creates_ospf_router(inv):
    res = _run(orch.orchestrate_l3_link("1/1/1", device="A", ip_address="10.1.1.0/31",
                                        ospf_area="0.0.0.0"))
    acts = [s["action"] for s in res["plan"]["A"]]
    assert acts == ["configure_routed_interface", "ensure_ospf_router", "ensure_ospf_area",
                    "add_ospf_interface", "configure_ospf_interface_options"]
    res = _run(orch.orchestrate_l3_link("1/1/1", device="A", ip_address="10.1.1.0/31",
                                        ospf_area="0.0.0.0", ospf_network_type=None))
    assert "configure_ospf_interface_options" not in [s["action"] for s in res["plan"]["A"]]


def test_fabric_underlay_exposes_lag_and_checkpoint_options(inv):
    res = _run(orch.orchestrate_fabric_underlay(
        spines=["A"], leafs=["B"], underlay_subnet="10.0.0.0/24",
        loopback0_subnet="10.1.0.0/24",
        cabling=[{"a_device": "A", "a_interface": "1/1/1",
                  "b_device": "B", "b_interface": "1/1/2"}],
        remove_from_lag=True, ensure_internal_vlan_range=True, auto_checkpoint=False))
    assert res["status"] == "planned"


def test_run_steps_counts_partial_steps_as_failed():
    class _C:
        pass

    async def ok(c):
        return {"status": "partial"}
    res = _run(orch._run_steps("d", _C(), [orch._step("configure_routed_interface", ok)]))
    assert res["summary"]["failed"] == 1


def test_routed_ports_hides_default_routing_ports_without_l3_config(client):
    raw = {
        "1/1/1": {"type": "system", "routing": True},
        "1/1/2": {"type": "system", "routing": True, "ip4_address": "10.0.0.0/31"},
        "1/1/3": {"type": "system", "routing": True,
                  "vrf": {"CAMPUS": "/rest/v10.17/system/vrfs/CAMPUS"}},
    }

    async def _filtered(pred):
        return [(n, r) for n, r in raw.items() if pred(n, r)]
    client._filtered_interfaces = _filtered
    import clients.aruba_client as ac
    monkey = pytest.MonkeyPatch()
    monkey.setattr(ac, "_format_interface", lambda n, r: {"name": n})
    try:
        names = [i["name"] for i in _run(client.get_routed_ports())["interfaces"]]
        assert names == ["1/1/2", "1/1/3"]
        everything = _run(client.get_routed_ports(include_unconfigured=True))
        assert everything["count"] == 3
    finally:
        monkey.undo()


# ─── EVPN redistribute local-mac / local-svi ───────────────────────────────

def test_set_evpn_global_redistribute_only_touches_given_keys(client):
    st = _Stateful(client, {"/system/evpn": {"arp_suppression_enable": True,
                                             "redistribute": {"local-svi": True}}})
    res = _run(client.set_evpn_global(redistribute_local_mac=True))
    assert res["status"] == "updated"
    body = st.puts[0][1]
    assert body["redistribute"] == {"local-svi": True, "local-mac": True}
    assert body["arp_suppression_enable"] is True


def test_set_evpn_global_reports_redistribute_not_kept(client):
    import copy
    _Recorder(client, {})
    stored = {"redistribute": {}}

    async def _get(path, params=None, _retried=False):
        return copy.deepcopy(stored)  # the device ignores the PUT
    client._get = _get
    res = _run(client.set_evpn_global(redistribute_local_svi=True))
    assert res["status"] == "partial" and "redistribute.local-svi" in res["not_applied"]


def test_set_evpn_global_rejects_unknown_redistribute_key(client):
    _Recorder(client, {"/system/evpn": {}})
    with pytest.raises(ArubaAPIError):
        _run(client.set_evpn_global(extra={"redistribute": {"bogus": True}}))


def test_read_evpn_exposes_redistribute(client):
    _Recorder(client, {"/system/evpn": {"redistribute": {"local-mac": True}}})
    out = _run(client.read_evpn())
    assert out["redistribute_local_mac"] is True and out["redistribute_local_svi"] is False


def test_configure_evpn_plan_and_overlay_carry_redistribute(inv):
    res = _run(tools_configure.configure_evpn(
        device="A", redistribute_local_mac=True, redistribute_local_svi=False))
    assert res["plan"]["A"]["redistribute_local_mac"] is True
    assert res["plan"]["A"]["redistribute_local_svi"] is False
    res = _run(orch.orchestrate_overlay(
        device="A", source_ip="10.0.1.1",
        evpn_options={"redistribute_local_svi": True}))
    assert res["plan"]["A"][1]["redistribute_local_svi"] is True
