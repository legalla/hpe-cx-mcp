"""Regression test: deleting a LAG (or removing a member from one) must clean
up `other_config.lacp-aggregation-key` on the freed member ports, exactly like
the native CLI `no interface lag N` does. Previously `configure_lag(delete=
True)` only deleted the LAG interface object itself and left this key stamped
on every former member, which kept the port from re-joining another LAG or
working standalone until manually cleared."""
import asyncio

from clients.aruba_client import ArubaOSCXClient
from tests.test_put_merge import _Recorder


def _client():
    return ArubaOSCXClient("192.0.2.1", "admin", "pw", api_version="v10.17")


def _stub_delete(client, resources):
    """Stub `_delete` to pop the target from `resources` (404 if absent),
    mirroring what `_Recorder` does for GET/PUT/POST."""
    from clients.aruba_client import ArubaAPIError

    async def _delete(path, _retried=False):
        if resources.pop(path, None) is None:
            raise ArubaAPIError(f"Resource not found: {path}", 404)

    client._delete = _delete


def test_delete_lag_clears_lacp_aggregation_key_on_members():
    client = _client()
    rec = _Recorder(client, {
        "/system/interfaces/lag1": {
            "name": "lag1", "type": "lag",
            "interfaces": {
                "1/1/5": "/rest/v10.17/system/interfaces/1%2F1%2F5",
                "1/1/6": "/rest/v10.17/system/interfaces/1%2F1%2F6"},
        },
        "/system/interfaces/1%2F1%2F5": {
            "name": "1/1/5", "description": "to-Core1-1/3/46",
            "other_config": {"lacp-aggregation-key": "1"},
            "user_config": {"admin": "up"}},
        "/system/interfaces/1%2F1%2F6": {
            "name": "1/1/6", "description": "to-Core2-1/3/46",
            "other_config": {"lacp-aggregation-key": "1"},
            "user_config": {"admin": "up"}},
    })
    _stub_delete(client, rec.resources)

    result = asyncio.run(client.configure_lag(1, delete=True))

    assert result["status"] == "deleted"
    # both former members got a full-object PUT with the key stripped,
    # every sibling attribute preserved.
    puts_by_path = {p: b for p, b in rec.puts}
    assert "/system/interfaces/1%2F1%2F5" in puts_by_path
    assert "/system/interfaces/1%2F1%2F6" in puts_by_path
    for path in ("/system/interfaces/1%2F1%2F5", "/system/interfaces/1%2F1%2F6"):
        body = puts_by_path[path]
        assert "lacp-aggregation-key" not in body.get("other_config", {})
        assert body["user_config"] == {"admin": "up"}
        assert body["description"] in ("to-Core1-1/3/46", "to-Core2-1/3/46")


def test_remove_members_clears_lacp_aggregation_key():
    client = _client()
    rec = _Recorder(client, {
        "/system/interfaces/lag2": {
            "name": "lag2", "type": "lag",
            "interfaces": {
                "1/1/7": "/rest/v10.17/system/interfaces/1%2F1%2F7",
                "1/1/8": "/rest/v10.17/system/interfaces/1%2F1%2F8"},
        },
        "/system/interfaces/1%2F1%2F7": {
            "name": "1/1/7",
            "other_config": {"lacp-aggregation-key": "2"},
            "user_config": {"admin": "up"}},
    })

    asyncio.run(client.configure_lag(2, remove_members=["1/1/7"]))

    puts_by_path = {p: b for p, b in rec.puts}
    member_body = puts_by_path["/system/interfaces/1%2F1%2F7"]
    assert "lacp-aggregation-key" not in member_body.get("other_config", {})
    assert member_body["user_config"] == {"admin": "up"}


def test_delete_lag_absent_is_noop_and_skips_member_cleanup():
    client = _client()
    rec = _Recorder(client, {})  # LAG already absent, no members to read
    _stub_delete(client, rec.resources)

    result = asyncio.run(client.configure_lag(3, delete=True))

    assert result["status"] == "absent"
    assert rec.puts == []
