import os
import stat

from clients.ssh_client import (
    _TofuSSHClient,
    _load_host_keys,
    _save_host_keys,
    _strip_ansi,
)


class _FakeKey:
    def __init__(self, fingerprint: str):
        self._fingerprint = fingerprint

    def get_fingerprint(self, hash_name: str = "sha256") -> str:
        return self._fingerprint


def test_strip_ansi_removes_escape_sequences():
    raw = "\x1b[1mswitch\x1b[0m#"
    assert _strip_ansi(raw) == "switch#"


def test_load_host_keys_missing_file_returns_empty(tmp_path):
    assert _load_host_keys(str(tmp_path / "nope.json")) == {}


def test_load_host_keys_corrupt_file_returns_empty(tmp_path):
    path = tmp_path / "known_hosts.json"
    path.write_text("not json", encoding="utf-8")
    assert _load_host_keys(str(path)) == {}


def test_save_and_load_host_keys_roundtrip_with_strict_perms(tmp_path):
    path = str(tmp_path / "known_hosts.json")
    _save_host_keys({"sw1:22": "SHA256:abc"}, path)

    assert _load_host_keys(path) == {"sw1:22": "SHA256:abc"}
    mode = stat.S_IMODE(os.stat(path).st_mode)
    assert mode == 0o600


def test_tofu_trusts_new_host_key_on_first_use(tmp_path):
    path = str(tmp_path / "known_hosts.json")
    client = _TofuSSHClient("sw1", 22, store_path=path)

    accepted = client.validate_host_public_key("sw1", "192.0.2.1", 22, _FakeKey("SHA256:aaa"))

    assert accepted is True
    assert _load_host_keys(path) == {"sw1:22": "SHA256:aaa"}


def test_tofu_accepts_matching_key_on_later_connections(tmp_path):
    path = str(tmp_path / "known_hosts.json")
    _save_host_keys({"sw1:22": "SHA256:aaa"}, path)
    client = _TofuSSHClient("sw1", 22, store_path=path)

    accepted = client.validate_host_public_key("sw1", "192.0.2.1", 22, _FakeKey("SHA256:aaa"))

    assert accepted is True


def test_tofu_rejects_mismatched_key():
    """A key that differs from the stored fingerprint must be refused
    (protects against MITM or an unexpectedly replaced device)."""
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "known_hosts.json")
        _save_host_keys({"sw1:22": "SHA256:aaa"}, path)
        client = _TofuSSHClient("sw1", 22, store_path=path)

        accepted = client.validate_host_public_key(
            "sw1", "192.0.2.1", 22, _FakeKey("SHA256:different")
        )

        assert accepted is False
        # The stored fingerprint must NOT be overwritten by the rejected key.
        assert _load_host_keys(path) == {"sw1:22": "SHA256:aaa"}


def test_tofu_keys_are_scoped_per_host_and_port(tmp_path):
    path = str(tmp_path / "known_hosts.json")
    client_a = _TofuSSHClient("sw1", 22, store_path=path)
    client_b = _TofuSSHClient("sw1", 2222, store_path=path)

    assert client_a.validate_host_public_key("sw1", "192.0.2.1", 22, _FakeKey("SHA256:a")) is True
    assert client_b.validate_host_public_key("sw1", "192.0.2.1", 2222, _FakeKey("SHA256:b")) is True

    hosts = _load_host_keys(path)
    assert hosts == {"sw1:22": "SHA256:a", "sw1:2222": "SHA256:b"}
