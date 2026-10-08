"""AOS-CX PUT semantics: an update must never send a sparse body.

A plain PUT replaces the whole writable object (omitted attributes are reset to
default). Every idempotent ``ensure_*`` / ``create_*`` update branch must go
through ``_put_merge`` (GET writable → deep-merge → PUT full object)."""
import asyncio

import pytest

from clients.aruba_client import ArubaAPIError, ArubaOSCXClient


class _Recorder:
    """Stub the low-level verbs on a client: canned GETs, captured PUT/POST."""

    def __init__(self, client: ArubaOSCXClient, resources: dict):
        self.resources = resources  # path -> writable payload (None = 404)
        self.puts: list[tuple[str, dict]] = []
        self.posts: list[tuple[str, dict]] = []

        async def _get(path, params=None, _retried=False):
            data = self.resources.get(path, None)
            if data is None:
                raise ArubaAPIError(f"Resource not found: {path}", 404)
            return dict(data)

        async def _put(path, body=None, params=None, _retried=False):
            self.puts.append((path, body))
            return {}

        async def _post(path, body=None, params=None, _retried=False):
            self.posts.append((path, body))
            return {}

        client._get = _get
        client._put = _put
        client._post = _post


@pytest.fixture
def client():
    return ArubaOSCXClient("192.0.2.1", "admin", "pw", api_version="v10.17")


def test_put_merge_preserves_sibling_attributes(client):
    rec = _Recorder(client, {
        "/system/vrfs/TENANT": {"name": "TENANT", "rd": "65000:1",
                                "evpn_export_route_targets": ["65000:1"],
                                "https_server": {"enable": True}},
    })
    asyncio.run(client.ensure_vrf("TENANT", evpn_import_rts=["65000:2"]))

    assert rec.posts == []
    assert len(rec.puts) == 1
    path, body = rec.puts[0]
    assert path == "/system/vrfs/TENANT"
    # the patch landed…
    assert body["evpn_import_route_targets"] == ["65000:2"]
    # …and every attribute NOT in the patch is still there (no reset to default)
    assert body["rd"] == "65000:1"
    assert body["evpn_export_route_targets"] == ["65000:1"]
    assert body["https_server"] == {"enable": True}


def test_put_merge_nested_dict_is_merged_not_replaced(client):
    rec = _Recorder(client, {
        "/system/interfaces/1%2F1%2F1": {"name": "1/1/1", "description": "uplink",
                                          "vlan_mode": "native-untagged",
                                          "vlan_trunks": {"10": "/rest/v10.17/system/vlans/10"},
                                          "user_config": {"admin": "up", "mtu": 9198}},
    })
    asyncio.run(client.add_vlan_to_trunk("1/1/1", 20))

    (_, body), = rec.puts
    assert set(body["vlan_trunks"]) == {"10", "20"}
    assert body["description"] == "uplink"
    assert body["user_config"] == {"admin": "up", "mtu": 9198}


def test_put_merge_absent_resource_raises_404(client):
    _Recorder(client, {})
    with pytest.raises(ArubaAPIError) as exc:
        asyncio.run(client._put_merge("/system/vrfs/NOPE", {"rd": "1:1"}))
    assert exc.value.status_code == 404


def test_create_branch_still_posts_when_absent(client):
    rec = _Recorder(client, {})
    asyncio.run(client.ensure_vrf("NEW", rd="65000:9"))
    assert rec.puts == []
    assert rec.posts and rec.posts[0][0] == "/system/vrfs"
    assert rec.posts[0][1]["name"] == "NEW"


def test_no_sparse_put_left_in_update_branches():
    """Guard: every update-branch PUT in the client goes through _put_merge.
    The whitelist below is the exhaustive set of intentional raw PUTs."""
    import inspect
    src = inspect.getsource(ArubaOSCXClient)
    raw = [l.strip() for l in src.splitlines() if "await self._put(" in l]
    allowed = {
        "return await self._put(path, body, params, _retried=True)",  # 401 retry
        "await self._put(",                                           # config copy (no body)
        'await self._put("/configs/autocheckpoint")',
        "await self._put(path, existing)",                            # _put_merge itself
        "await self._put(path, body)",                                # configure_routed_interface (pre-merged)
        'await self._put(f"{base}/{instance_tag}", existing)',        # ospf router (pre-merged)
        'await self._put(f"{base}/{key}", existing)',                 # ospf area/iface, bgp neighbor (pre-merged)
        'await self._put(f"{base}/{asn}", existing)',                 # bgp router (pre-merged)
        'await self._put("/system", {"virtual_mac": mac})',           # documented exception
        'await self._put("/system", {"hostname": hostname})',         # same exception (set_hostname)
        'await self._put("/system", body)',                           # set_port_access_global (aaa + CoA, pre-merged)
        "await self._put(path, writable)",                            # configure_interface_group delete (pre-merged)
        "await self._put(base, existing)",                            # set_ospf_interface_passive (pre-merged, full replace)
        "await self._put(member_path, existing)",                     # _clear_lacp_aggregation_key (pre-merged, full replace)
    }
    unexpected = [l for l in raw if l not in allowed]
    assert unexpected == [], f"sparse PUT(s) found: {unexpected}"
