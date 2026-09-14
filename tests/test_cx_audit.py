import json

from security.cx_audit import AuditLogger, classify_tool, redact


# ── classify_tool ────────────────────────────────────────────────────────

def test_classify_tool_read_by_default():
    assert classify_tool("get_system") == "read"
    assert classify_tool(None) == "read"


def test_classify_tool_write_prefixes():
    assert classify_tool("configure_bgp") == "write"
    assert classify_tool("create_vlan_service") == "write"
    assert classify_tool("delete_vlan_service") == "write"


def test_classify_tool_write_explicit_names():
    assert classify_tool("manage_config") == "write"
    assert classify_tool("run_ssh_commands") == "write"


# ── redact ───────────────────────────────────────────────────────────────

def test_redact_hides_secret_looking_keys():
    out = redact({"username": "admin", "password": "hunter2", "api_key": "abc"})
    assert out["username"] == "admin"
    assert out["password"] == "***redacted***"
    assert out["api_key"] == "***redacted***"


def test_redact_recurses_into_nested_structures():
    out = redact({"devices": [{"token": "secret-token", "name": "sw1"}]})
    assert out["devices"][0]["token"] == "***redacted***"
    assert out["devices"][0]["name"] == "sw1"


def test_redact_truncates_long_strings():
    long_value = "x" * 3000
    out = redact({"description": long_value})
    assert out["description"].endswith("…[truncated]")
    assert len(out["description"]) < len(long_value)


# ── AuditLogger ──────────────────────────────────────────────────────────

def test_audit_logger_disabled_is_noop(tmp_path):
    logger = AuditLogger(enabled=False, path=str(tmp_path / "audit.jsonl"))
    logger.record(tool="configure_bgp", actor="alice")
    assert not (tmp_path / "audit.jsonl").exists()


def test_audit_logger_records_all_by_default(tmp_path):
    path = tmp_path / "audit.jsonl"
    logger = AuditLogger(enabled=True, path=str(path), level="all")

    logger.record(tool="get_system", actor="alice", arguments={"device": "sw1"})
    logger.record(tool="configure_bgp", actor="alice", arguments={"password": "x"})

    lines = path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    events = [json.loads(line) for line in lines]
    assert events[0]["category"] == "read"
    assert events[1]["category"] == "write"
    assert events[1]["arguments"]["password"] == "***redacted***"


def test_audit_logger_writes_only_filter(tmp_path):
    path = tmp_path / "audit.jsonl"
    logger = AuditLogger(enabled=True, path=str(path), level="writes")

    logger.record(tool="get_system", actor="alice")
    logger.record(tool="configure_bgp", actor="alice")

    lines = path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    event = json.loads(lines[0])
    assert event["tool"] == "configure_bgp"
