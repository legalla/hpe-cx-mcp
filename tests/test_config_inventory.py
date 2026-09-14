import pytest

from core.config import DeviceConfig, InventoryError, load_inventory, normalize_api_version


# ── normalize_api_version ───────────────────────────────────────────────

def test_normalize_api_version_latest():
    assert normalize_api_version("latest") == "latest"


def test_normalize_api_version_adds_v_prefix():
    assert normalize_api_version("10.13") == "v10.13"


def test_normalize_api_version_accepts_v_prefix():
    assert normalize_api_version("v10.09") == "v10.09"


def test_normalize_api_version_rejects_garbage():
    with pytest.raises(ValueError):
        normalize_api_version("not-a-version")


# ── DeviceConfig ─────────────────────────────────────────────────────────

def test_device_config_access_mode_aliases():
    assert DeviceConfig(name="a", host="1.1.1.1", access_mode="rw").access_mode == "read-write"
    assert DeviceConfig(name="a", host="1.1.1.1", access_mode="ro").access_mode == "read-only"
    assert DeviceConfig(name="a", host="1.1.1.1", access_mode="READONLY").access_mode == "read-only"


def test_device_config_invalid_access_mode_raises():
    with pytest.raises(ValueError):
        DeviceConfig(name="a", host="1.1.1.1", access_mode="bogus")


def test_device_config_can_write_property():
    assert DeviceConfig(name="a", host="1.1.1.1", access_mode="read-write").can_write is True
    assert DeviceConfig(name="a", host="1.1.1.1", access_mode="read-only").can_write is False


def test_device_config_ssh_credentials_fall_back_to_rest_credentials():
    dev = DeviceConfig(name="a", host="1.1.1.1", username="admin", password="secret")
    assert dev.ssh_username == "admin"
    assert dev.ssh_password == "secret"


def test_device_config_explicit_ssh_credentials_are_kept():
    dev = DeviceConfig(
        name="a", host="1.1.1.1", username="admin", password="secret",
        ssh_username="sshuser", ssh_password="sshpass",
    )
    assert dev.ssh_username == "sshuser"
    assert dev.ssh_password == "sshpass"


# ── load_inventory ────────────────────────────────────────────────────────

def test_load_inventory_missing_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_inventory(str(tmp_path / "nope.yaml"))


def test_load_inventory_list_format(tmp_path):
    path = tmp_path / "inventory.yaml"
    path.write_text(
        """
devices:
  - name: sw-core-01
    host: 192.168.1.1
    username: admin
    password: secret
    access_mode: read-write
""",
        encoding="utf-8",
    )
    inv = load_inventory(str(path))
    assert set(inv.devices) == {"sw-core-01"}
    dev = inv.devices["sw-core-01"]
    assert dev.host == "192.168.1.1"
    assert dev.access_mode == "read-write"


def test_load_inventory_dict_format_with_defaults(tmp_path):
    path = tmp_path / "inventory.yaml"
    path.write_text(
        """
defaults:
  username: admin
  password: secret
  access_mode: read-only

devices:
  sw-01:
    host: 10.0.0.1
  sw-02:
    host: 10.0.0.2
    access_mode: read-write
""",
        encoding="utf-8",
    )
    inv = load_inventory(str(path))
    assert set(inv.devices) == {"sw-01", "sw-02"}
    assert inv.devices["sw-01"].access_mode == "read-only"
    assert inv.devices["sw-01"].username == "admin"
    assert inv.devices["sw-02"].access_mode == "read-write"


def test_load_inventory_sites_format_propagates_site(tmp_path):
    path = tmp_path / "inventory.yaml"
    path.write_text(
        """
sites:
  campus-paris:
    devices:
      Border:
        host: 192.0.2.20
""",
        encoding="utf-8",
    )
    inv = load_inventory(str(path))
    assert inv.devices["Border"].site == "campus-paris"
    assert inv.devices["Border"].host == "192.0.2.20"


def test_load_inventory_invalid_access_mode_raises_inventory_error(tmp_path):
    path = tmp_path / "inventory.yaml"
    path.write_text(
        """
devices:
  sw-01:
    host: 10.0.0.1
    access_mode: not-a-mode
""",
        encoding="utf-8",
    )
    with pytest.raises(InventoryError):
        load_inventory(str(path))


def test_load_inventory_flat_ip_string_shortcut(tmp_path):
    path = tmp_path / "inventory.yaml"
    path.write_text(
        """
devices:
  sw-01: 10.0.0.5
""",
        encoding="utf-8",
    )
    inv = load_inventory(str(path))
    assert inv.devices["sw-01"].host == "10.0.0.5"
