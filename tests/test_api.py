import base64

from landbook_api import DEFAULT_REGION, REGIONS, LandbookMQTTClient
from landbook_api.api import _encrypt_password, _region_cfg


def test_regions_have_required_keys():
    required = {"label", "api_base", "mqtt_host", "user_domain", "app_domain_key"}
    for region, cfg in REGIONS.items():
        assert required <= cfg.keys(), f"region {region} missing keys"


def test_default_region_is_valid():
    assert DEFAULT_REGION in REGIONS


def test_region_cfg_falls_back_to_default_for_unknown_region():
    assert _region_cfg("does-not-exist") == REGIONS[DEFAULT_REGION]


def test_region_cfg_returns_requested_region():
    assert _region_cfg("eu") == REGIONS["eu"]


def test_encrypt_password_returns_base64_ciphertext_and_16_char_rand():
    pwd_b64, rand = _encrypt_password("hunter2")
    assert len(rand) == 16
    # Should round-trip through base64 without error.
    base64.b64decode(pwd_b64)


def test_encrypt_password_uses_random_salt_each_call():
    pwd_a, rand_a = _encrypt_password("hunter2")
    pwd_b, rand_b = _encrypt_password("hunter2")
    assert rand_a != rand_b
    assert pwd_a != pwd_b


def test_mqtt_client_can_be_constructed_without_connecting():
    client = LandbookMQTTClient(uid="u1", bearer_token="Bearer abc")
    assert client._mqtt_host == REGIONS[DEFAULT_REGION]["mqtt_host"]
