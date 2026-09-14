import aiohttp
import pytest

from core.config import DeviceConfig, Inventory, SourceConfig, VaultConfig, LOCAL_SOURCE
from core.inventory_sources import (
    InventoryManager,
    InventorySourceError,
    InfrahubSource,
    NautobotSource,
    NetBoxSource,
    VaultClient,
    _mask,
    _strip_prefix_len,
    build_source_client,
)


# ── Pure helpers ─────────────────────────────────────────────────────────

def test_mask_short_token():
    assert _mask("abc") == "***"


def test_mask_long_token_keeps_prefix_and_suffix():
    masked = _mask("supersecrettoken123")
    assert masked.startswith("sup")
    assert masked.endswith("23")
    assert "…" in masked


def test_mask_empty_token():
    assert _mask("") == ""


def test_strip_prefix_len():
    assert _strip_prefix_len("10.0.0.1/24") == "10.0.0.1"
    assert _strip_prefix_len("10.0.0.1") == "10.0.0.1"
    assert _strip_prefix_len("") == ""


# ── build_source_client factory ─────────────────────────────────────────

def _source_cfg(type_, **kw):
    defaults = dict(name=type_, type=type_, url="https://example.net", token="tok")
    defaults.update(kw)
    return SourceConfig(**defaults)


def test_build_source_client_netbox():
    client = build_source_client(_source_cfg("netbox"))
    assert isinstance(client, NetBoxSource)


def test_build_source_client_nautobot():
    client = build_source_client(_source_cfg("nautobot"))
    assert isinstance(client, NautobotSource)


def test_build_source_client_infrahub():
    client = build_source_client(_source_cfg("infrahub"))
    assert isinstance(client, InfrahubSource)


def test_build_source_client_unsupported_type_raises():
    cfg = SourceConfig(name="weird", type="weird")
    with pytest.raises(InventorySourceError):
        build_source_client(cfg)


def test_rest_device_source_requires_url():
    with pytest.raises(InventorySourceError):
        NetBoxSource(SourceConfig(name="netbox", type="netbox", url=""))


# ── _RestDeviceSource._normalize (NetBox/Nautobot record shape) ─────────

def test_normalize_extracts_name_host_tags_and_extra():
    source = NetBoxSource(_source_cfg("netbox"))
    record = {
        "name": "sw-core-01",
        "primary_ip4": {"address": "10.0.0.1/24"},
        "tags": [{"name": "prod"}, "raw-tag"],
        "site": {"name": "paris"},
        "tenant": {"slug": "acme"},
        "custom_fields": {"owner": "netops"},
    }
    norm = source._normalize(record)
    assert norm["name"] == "sw-core-01"
    assert norm["host"] == "10.0.0.1"
    assert norm["tags"] == ["prod", "raw-tag"]
    assert norm["site"] == "paris"
    assert norm["extra"]["tenant"] == "acme"
    assert norm["extra"]["custom_fields"] == {"owner": "netops"}


def test_normalize_returns_none_without_name():
    source = NetBoxSource(_source_cfg("netbox"))
    assert source._normalize({"primary_ip4": {"address": "10.0.0.1/24"}}) is None


def test_normalize_falls_back_to_name_when_no_ip():
    source = NetBoxSource(_source_cfg("netbox"))
    norm = source._normalize({"name": "sw-01"})
    assert norm["host"] == "sw-01"


# ── VaultClient ──────────────────────────────────────────────────────────

def test_vault_client_not_configured_without_url_or_token():
    assert VaultClient(VaultConfig(enabled=True, url="", token="")).configured is False
    assert VaultClient(VaultConfig(enabled=True, url="https://vault", token="")).configured is False
    assert VaultClient(VaultConfig(enabled=False, url="https://vault", token="t")).configured is False


def test_vault_client_configured():
    assert VaultClient(VaultConfig(enabled=True, url="https://vault", token="t")).configured is True


def test_vault_secret_url_kv2():
    client = VaultClient(VaultConfig(url="https://vault:8200", mount="secret", kv_version=2))
    assert client._secret_url("switches/sw1") == "https://vault:8200/v1/secret/data/switches/sw1"


def test_vault_secret_url_kv1():
    client = VaultClient(VaultConfig(url="https://vault:8200", mount="secret", kv_version=1))
    assert client._secret_url("switches/sw1") == "https://vault:8200/v1/secret/switches/sw1"


@pytest.mark.asyncio
async def test_vault_get_credentials_not_configured_returns_none():
    client = VaultClient(VaultConfig(enabled=False))
    assert await client.get_credentials("sw1") is None


# ── VaultClient.get_credentials (mocked HTTP) ──────────────────────────
# Reuses the same hand-rolled aiohttp fakes as test_aruba_client.py, since
# aioresponses is incompatible with this aiohttp release.

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
    def __init__(self):
        self.calls = []
        self._queued = {}

    def queue(self, method, url, response):
        self._queued.setdefault((method.upper(), url), []).append(response)

    def _pop(self, method, url):
        self.calls.append((method, url))
        bucket = self._queued.get((method.upper(), url))
        if not bucket:
            raise AssertionError(f"Unexpected request: {method} {url}")
        return bucket.pop(0)

    def get(self, url, **kwargs):
        return self._pop("GET", url)

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def close(self):
        pass


@pytest.fixture
def fake_session(monkeypatch):
    session = _FakeSession()
    monkeypatch.setattr(aiohttp, "ClientSession", lambda *a, **kw: session)
    return session


@pytest.mark.asyncio
async def test_vault_get_credentials_kv2_success(fake_session):
    cfg = VaultConfig(enabled=True, url="https://vault:8200", token="t", mount="secret",
                       kv_version=2, path_template="switches/{device}")
    client = VaultClient(cfg)
    url = "https://vault:8200/v1/secret/data/switches/sw1"
    fake_session.queue("GET", url, _FakeResponse(status=200, payload={
        "data": {"data": {"username": "vault-admin", "password": "vault-pass"}}
    }))
    creds = await client.get_credentials("sw1")
    assert creds == {"username": "vault-admin", "password": "vault-pass"}


@pytest.mark.asyncio
async def test_vault_get_credentials_404_returns_none(fake_session):
    cfg = VaultConfig(enabled=True, url="https://vault:8200", token="t", path_template="switches/{device}")
    client = VaultClient(cfg)
    url = "https://vault:8200/v1/secret/data/switches/sw1"
    fake_session.queue("GET", url, _FakeResponse(status=404))
    assert await client.get_credentials("sw1") is None


@pytest.mark.asyncio
async def test_vault_get_credentials_error_status_raises(fake_session):
    cfg = VaultConfig(enabled=True, url="https://vault:8200", token="t", path_template="switches/{device}")
    client = VaultClient(cfg)
    url = "https://vault:8200/v1/secret/data/switches/sw1"
    fake_session.queue("GET", url, _FakeResponse(status=500, text="internal error"))
    with pytest.raises(InventorySourceError):
        await client.get_credentials("sw1")


# ── InventoryManager (local-only: no network involved) ──────────────────

def _make_manager(devices=None, source_order=None):
    devices = devices or {}
    sources = {"local": SourceConfig(name="local", type=LOCAL_SOURCE)}
    inv = Inventory(devices=devices, sources=sources, source_order=source_order or ["local"])
    return InventoryManager(inv)


def test_priority_index_known_and_unknown_source():
    mgr = _make_manager(source_order=["netbox", "local"])
    assert mgr.priority_index("netbox") == 0
    assert mgr.priority_index("local") == 1
    assert mgr.priority_index("unknown") == 2


def test_has_external_sources_false_for_local_only():
    mgr = _make_manager()
    assert mgr.has_external_sources is False


def test_local_record_shape():
    dev = DeviceConfig(name="sw1", host="10.0.0.1", site="paris", tags=["prod"], description="core")
    rec = InventoryManager._local_record(dev)
    assert rec["name"] == "sw1"
    assert rec["host"] == "10.0.0.1"
    assert rec["site"] == "paris"
    assert rec["extra"]["tags"] == ["prod"]
    assert rec["extra"]["description"] == "core"


def test_matches_by_name_substring():
    rec = {"name": "sw-core-01", "tags": [], "extra": {}}
    assert InventoryManager._matches(rec, {"name": "core"}) is True
    assert InventoryManager._matches(rec, {"name": "access"}) is False


def test_matches_by_tag():
    rec = {"name": "sw1", "tags": ["prod", "core"], "extra": {}}
    assert InventoryManager._matches(rec, {"tag": "core"}) is True
    assert InventoryManager._matches(rec, {"tag": "dev"}) is False


def test_matches_by_site_extra_field():
    rec = {"name": "sw1", "tags": [], "extra": {"site": "paris"}}
    assert InventoryManager._matches(rec, {"site": "paris"}) is True
    assert InventoryManager._matches(rec, {"site": "lyon"}) is False


def test_matches_by_custom_field():
    rec = {"name": "sw1", "tags": [], "extra": {"custom_fields": {"owner": "netops"}}}
    assert InventoryManager._matches(rec, {"owner": "netops"}) is True
    assert InventoryManager._matches(rec, {"owner": "other"}) is False


def test_merge_keeps_higher_priority_source():
    merged, provenance = {}, {}
    InventoryManager._merge(merged, provenance, {"name": "sw1", "host": "1.1.1.1"}, prio=1)
    InventoryManager._merge(merged, provenance, {"name": "sw1", "host": "2.2.2.2"}, prio=0)
    assert merged["sw1"]["host"] == "2.2.2.2"  # lower prio number wins


def test_merge_ignores_lower_priority_after_higher_seen():
    merged, provenance = {}, {}
    InventoryManager._merge(merged, provenance, {"name": "sw1", "host": "1.1.1.1"}, prio=0)
    InventoryManager._merge(merged, provenance, {"name": "sw1", "host": "9.9.9.9"}, prio=5)
    assert merged["sw1"]["host"] == "1.1.1.1"


@pytest.mark.asyncio
async def test_find_devices_local_only_filters_by_site(tmp_path):
    devices = {
        "sw1": DeviceConfig(name="sw1", host="10.0.0.1", site="paris"),
        "sw2": DeviceConfig(name="sw2", host="10.0.0.2", site="lyon"),
    }
    mgr = _make_manager(devices)
    result = await mgr.find_devices({"site": "paris"}, local_devices=devices)
    assert [d["name"] for d in result["devices"]] == ["sw1"]
    assert result["queried_sources"] == ["local"]
    assert result["errors"] == {}


@pytest.mark.asyncio
async def test_resolve_device_local_by_name_and_ip():
    devices = {"sw1": DeviceConfig(name="sw1", host="10.0.0.1")}
    mgr = _make_manager(devices)
    by_name = await mgr.resolve_device("sw1", local_devices=devices)
    assert by_name["host"] == "10.0.0.1"
    by_ip = await mgr.resolve_device("10.0.0.1", local_devices=devices)
    assert by_ip["name"] == "sw1"
    assert await mgr.resolve_device("nope", local_devices=devices) is None


@pytest.mark.asyncio
async def test_resolve_credentials_prefers_device_specific_over_vault():
    dev = DeviceConfig(name="sw1", host="10.0.0.1", username="explicit-user",
                       password="explicit-pass", vault=True)
    inv = Inventory(devices={"sw1": dev},
                    sources={"local": SourceConfig(name="local", type=LOCAL_SOURCE)},
                    source_order=["local"],
                    vault=VaultConfig(enabled=False))
    mgr = InventoryManager(inv)
    creds = await mgr.resolve_credentials(dev)
    assert creds["username"] == "explicit-user"
    assert creds["password"] == "explicit-pass"
    assert creds["source"] == "inventory/env"
