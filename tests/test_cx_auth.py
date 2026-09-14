import json
import os
import stat

import pytest

from security import cx_auth


def test_generate_token_format():
    token = cx_auth.generate_token()
    assert token.startswith(cx_auth.TOKEN_PREFIX)
    assert len(token) > len(cx_auth.TOKEN_PREFIX) + 20


def test_add_load_revoke_roundtrip(tmp_path):
    path = str(tmp_path / ".tokens")

    record = cx_auth.add_token("vscode-dev", "VS Code client", path=path)
    assert record["token"].startswith("cx_")
    assert record["description"] == "VS Code client"
    assert "created" in record

    tokens = cx_auth.load_tokens(path)
    assert set(tokens) == {"vscode-dev"}
    assert tokens["vscode-dev"]["token"] == record["token"]

    assert cx_auth.revoke_token("vscode-dev", path=path) is True
    assert cx_auth.load_tokens(path) == {}
    assert cx_auth.revoke_token("vscode-dev", path=path) is False


def test_add_token_rejects_empty_name(tmp_path):
    path = str(tmp_path / ".tokens")
    with pytest.raises(ValueError):
        cx_auth.add_token("   ", path=path)


def test_add_token_rejects_duplicate_name(tmp_path):
    path = str(tmp_path / ".tokens")
    cx_auth.add_token("dup", path=path)
    with pytest.raises(ValueError):
        cx_auth.add_token("dup", path=path)


def test_load_tokens_missing_file_returns_empty(tmp_path):
    assert cx_auth.load_tokens(str(tmp_path / "nope.json")) == {}


def test_load_tokens_corrupt_file_returns_empty(tmp_path):
    path = tmp_path / ".tokens"
    path.write_text("not json", encoding="utf-8")
    assert cx_auth.load_tokens(str(path)) == {}


def test_save_tokens_sets_strict_permissions(tmp_path):
    path = str(tmp_path / ".tokens")
    cx_auth.save_tokens({"a": {"token": "cx_x"}}, path)
    mode = stat.S_IMODE(os.stat(path).st_mode)
    assert mode == 0o600
    with open(path, encoding="utf-8") as fh:
        assert json.load(fh) == {"a": {"token": "cx_x"}}


def test_token_store_resolve_and_reload(tmp_path):
    path = str(tmp_path / ".tokens")
    cx_auth.add_token("client-a", path=path)
    tokens = cx_auth.load_tokens(path)
    token_value = tokens["client-a"]["token"]

    store = cx_auth.TokenStore(path)
    assert len(store) == 1
    assert store.resolve(token_value) == "client-a"
    assert store.resolve("unknown") is None
    assert store.resolve("") is None

    cx_auth.add_token("client-b", path=path)
    assert store.resolve("cx_still-stale") is None  # not reloaded yet
    assert store.reload() == 2
    assert len(store) == 2
