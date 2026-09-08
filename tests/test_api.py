import asyncio
import base64
import json
from io import BytesIO
from unittest.mock import MagicMock, patch

import pytest

from landbook_api import DEFAULT_REGION, REGIONS, LandbookAuthError, LandbookAPIError
from landbook_api.api import (
    _encrypt_password,
    _region_cfg,
    get_device_attributes,
    get_device_list,
    get_tsl,
    login,
    refresh_token,
    async_login,
    async_get_device_list,
    async_get_tsl,
    async_refresh_token,
    async_get_device_attributes,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fake_jwt(uid: str = "user123") -> str:
    payload = base64.b64encode(json.dumps({"uid": uid}).encode()).decode().rstrip("=")
    return f"Bearer header.{payload}.signature"


def _mock_urlopen(body: dict):
    resp = MagicMock()
    resp.read.return_value = json.dumps(body).encode()
    return resp


# ---------------------------------------------------------------------------
# Region / encryption (existing + expanded)
# ---------------------------------------------------------------------------

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
    base64.b64decode(pwd_b64)


def test_encrypt_password_uses_random_salt_each_call():
    pwd_a, rand_a = _encrypt_password("hunter2")
    pwd_b, rand_b = _encrypt_password("hunter2")
    assert rand_a != rand_b
    assert pwd_a != pwd_b


def test_encrypt_password_empty_string():
    pwd_b64, rand = _encrypt_password("")
    assert len(rand) == 16
    base64.b64decode(pwd_b64)


# ---------------------------------------------------------------------------
# login()
# ---------------------------------------------------------------------------

class TestLogin:
    def _login_response(self, uid="user123"):
        token = _fake_jwt(uid)
        return {
            "code": 200,
            "data": {
                "accessToken": {"token": token},
                "refreshToken": {"token": "Bearer refresh_abc"},
            },
        }

    @patch("landbook_api.api.urllib.request.urlopen")
    def test_login_success(self, mock_urlopen):
        mock_urlopen.return_value = _mock_urlopen(self._login_response())
        bearer, uid, rt = login("a@b.com", "pass")
        assert uid == "user123"
        assert bearer.startswith("Bearer ")
        assert rt == "Bearer refresh_abc"

    @patch("landbook_api.api.urllib.request.urlopen")
    def test_login_sends_post_to_correct_url(self, mock_urlopen):
        mock_urlopen.return_value = _mock_urlopen(self._login_response())
        login("a@b.com", "pass", region="eu")
        req = mock_urlopen.call_args[0][0]
        assert req.full_url == REGIONS["eu"]["api_base"] + "/v2/enduser/enduserapi/emailPwdLogin"
        assert req.data is not None

    @patch("landbook_api.api.urllib.request.urlopen")
    def test_login_includes_app_headers(self, mock_urlopen):
        mock_urlopen.return_value = _mock_urlopen(self._login_response())
        login("a@b.com", "pass")
        req = mock_urlopen.call_args[0][0]
        assert req.get_header("Appid") == "584"
        assert req.get_header("Appversion") == "3.6.0"

    @patch("landbook_api.api.urllib.request.urlopen")
    def test_login_non_200_code_raises(self, mock_urlopen):
        mock_urlopen.return_value = _mock_urlopen({"code": 401, "msg": "bad creds"})
        with pytest.raises(LandbookAuthError, match="bad creds"):
            login("a@b.com", "wrong")

    @patch("landbook_api.api.urllib.request.urlopen")
    def test_login_missing_data_key_raises(self, mock_urlopen):
        mock_urlopen.return_value = _mock_urlopen({"code": 200})
        with pytest.raises(LandbookAuthError):
            login("a@b.com", "pass")

    @patch("landbook_api.api.urllib.request.urlopen", side_effect=ConnectionError("offline"))
    def test_login_network_error_raises(self, mock_urlopen):
        with pytest.raises(LandbookAuthError, match="Login request failed"):
            login("a@b.com", "pass")


# ---------------------------------------------------------------------------
# get_device_list()
# ---------------------------------------------------------------------------

class TestGetDeviceList:
    @patch("landbook_api.api.urllib.request.urlopen")
    def test_returns_device_list(self, mock_urlopen):
        devices = [{"deviceId": "d1"}, {"deviceId": "d2"}]
        mock_urlopen.return_value = _mock_urlopen({"code": 200, "data": {"list": devices}})
        result = get_device_list("Bearer tok")
        assert result == devices

    @patch("landbook_api.api.urllib.request.urlopen")
    def test_returns_empty_list_when_no_list_key(self, mock_urlopen):
        mock_urlopen.return_value = _mock_urlopen({"code": 200, "data": {}})
        assert get_device_list("Bearer tok") == []

    @patch("landbook_api.api.urllib.request.urlopen")
    def test_sends_pagination_params(self, mock_urlopen):
        mock_urlopen.return_value = _mock_urlopen({"code": 200, "data": {"list": []}})
        get_device_list("Bearer tok")
        req = mock_urlopen.call_args[0][0]
        assert "page=1" in req.full_url
        assert "pageSize=50" in req.full_url

    @patch("landbook_api.api.urllib.request.urlopen")
    def test_api_error_raises(self, mock_urlopen):
        mock_urlopen.return_value = _mock_urlopen({"code": 500, "msg": "server error"})
        with pytest.raises(LandbookAPIError, match="server error"):
            get_device_list("Bearer tok")


# ---------------------------------------------------------------------------
# get_tsl()
# ---------------------------------------------------------------------------

class TestGetTSL:
    @patch("landbook_api.api.urllib.request.urlopen")
    def test_filters_writable_properties(self, mock_urlopen):
        props = [
            {"code": "a", "type": "PROPERTY", "subType": "RW", "sort": 2},
            {"code": "b", "type": "PROPERTY", "subType": "R", "sort": 1},
            {"code": "c", "type": "EVENT", "subType": "W", "sort": 0},
            {"code": "d", "type": "PROPERTY", "subType": "W", "sort": 0},
        ]
        mock_urlopen.return_value = _mock_urlopen({"code": 200, "data": {"properties": props}})
        result = get_tsl("Bearer tok", "pk1")
        codes = [p["code"] for p in result]
        assert "b" not in codes
        assert "c" not in codes
        assert "a" in codes and "d" in codes

    @patch("landbook_api.api.urllib.request.urlopen")
    def test_sorts_by_sort_field(self, mock_urlopen):
        props = [
            {"code": "z", "type": "PROPERTY", "subType": "RW", "sort": 10},
            {"code": "a", "type": "PROPERTY", "subType": "W", "sort": 1},
        ]
        mock_urlopen.return_value = _mock_urlopen({"code": 200, "data": {"properties": props}})
        result = get_tsl("Bearer tok", "pk1")
        assert result[0]["code"] == "a"
        assert result[1]["code"] == "z"

    @patch("landbook_api.api.urllib.request.urlopen")
    def test_empty_properties(self, mock_urlopen):
        mock_urlopen.return_value = _mock_urlopen({"code": 200, "data": {"properties": []}})
        assert get_tsl("Bearer tok", "pk1") == []

    @patch("landbook_api.api.urllib.request.urlopen")
    def test_missing_properties_key(self, mock_urlopen):
        mock_urlopen.return_value = _mock_urlopen({"code": 200, "data": {}})
        assert get_tsl("Bearer tok", "pk1") == []


# ---------------------------------------------------------------------------
# refresh_token()
# ---------------------------------------------------------------------------

class TestRefreshToken:
    @patch("landbook_api.api.urllib.request.urlopen")
    def test_returns_new_token_pair(self, mock_urlopen):
        mock_urlopen.return_value = _mock_urlopen({
            "code": 200,
            "data": {
                "accessToken": {"token": "Bearer new_access"},
                "refreshToken": {"token": "Bearer new_refresh"},
            },
        })
        access, refresh = refresh_token("Bearer old", "Bearer old_refresh")
        assert access == "Bearer new_access"
        assert refresh == "Bearer new_refresh"

    @patch("landbook_api.api.urllib.request.urlopen")
    def test_sends_put_with_refresh_token_body(self, mock_urlopen):
        mock_urlopen.return_value = _mock_urlopen({
            "code": 200,
            "data": {
                "accessToken": {"token": "Bearer a"},
                "refreshToken": {"token": "Bearer r"},
            },
        })
        refresh_token("Bearer tok", "Bearer rt_val", region="us")
        req = mock_urlopen.call_args[0][0]
        assert req.method == "PUT"
        assert b"refreshToken=" in req.data

    @patch("landbook_api.api.urllib.request.urlopen")
    def test_non_200_raises_auth_error(self, mock_urlopen):
        mock_urlopen.return_value = _mock_urlopen({"code": 401, "msg": "expired"})
        with pytest.raises(LandbookAuthError, match="expired"):
            refresh_token("Bearer old", "Bearer old_refresh")

    @patch("landbook_api.api.urllib.request.urlopen", side_effect=ConnectionError("down"))
    def test_network_error_raises_api_error(self, mock_urlopen):
        with pytest.raises(LandbookAPIError, match="Token refresh request failed"):
            refresh_token("Bearer old", "Bearer old_refresh")


# ---------------------------------------------------------------------------
# get_device_attributes()
# ---------------------------------------------------------------------------

class TestGetDeviceAttributes:
    @patch("landbook_api.api.urllib.request.urlopen")
    def test_returns_data(self, mock_urlopen):
        attrs = {"switch": True, "brightness": 80}
        mock_urlopen.return_value = _mock_urlopen({"code": 200, "data": attrs})
        assert get_device_attributes("Bearer tok", "pk1", "dk1") == attrs

    @patch("landbook_api.api.urllib.request.urlopen")
    def test_passes_pk_dk_params(self, mock_urlopen):
        mock_urlopen.return_value = _mock_urlopen({"code": 200, "data": {}})
        get_device_attributes("Bearer tok", "pk1", "dk1")
        req = mock_urlopen.call_args[0][0]
        assert "pk=pk1" in req.full_url
        assert "dk=dk1" in req.full_url


# ---------------------------------------------------------------------------
# Async wrappers
# ---------------------------------------------------------------------------

class TestAsyncWrappers:
    @patch("landbook_api.api.urllib.request.urlopen")
    def test_async_login(self, mock_urlopen):
        token = _fake_jwt("u1")
        mock_urlopen.return_value = _mock_urlopen({
            "code": 200,
            "data": {
                "accessToken": {"token": token},
                "refreshToken": {"token": "Bearer r"},
            },
        })
        bearer, uid, rt = asyncio.get_event_loop().run_until_complete(
            async_login("a@b.com", "pass")
        )
        assert uid == "u1"

    @patch("landbook_api.api.urllib.request.urlopen")
    def test_async_get_device_list(self, mock_urlopen):
        mock_urlopen.return_value = _mock_urlopen({"code": 200, "data": {"list": [{"id": 1}]}})
        result = asyncio.get_event_loop().run_until_complete(
            async_get_device_list("Bearer tok")
        )
        assert result == [{"id": 1}]

    @patch("landbook_api.api.urllib.request.urlopen")
    def test_async_get_tsl(self, mock_urlopen):
        props = [{"code": "a", "type": "PROPERTY", "subType": "W", "sort": 0}]
        mock_urlopen.return_value = _mock_urlopen({"code": 200, "data": {"properties": props}})
        result = asyncio.get_event_loop().run_until_complete(
            async_get_tsl("Bearer tok", "pk1")
        )
        assert len(result) == 1

    @patch("landbook_api.api.urllib.request.urlopen")
    def test_async_refresh_token(self, mock_urlopen):
        mock_urlopen.return_value = _mock_urlopen({
            "code": 200,
            "data": {
                "accessToken": {"token": "Bearer a2"},
                "refreshToken": {"token": "Bearer r2"},
            },
        })
        a, r = asyncio.get_event_loop().run_until_complete(
            async_refresh_token("Bearer a", "Bearer r")
        )
        assert a == "Bearer a2"

    @patch("landbook_api.api.urllib.request.urlopen")
    def test_async_get_device_attributes(self, mock_urlopen):
        mock_urlopen.return_value = _mock_urlopen({"code": 200, "data": {"on": True}})
        result = asyncio.get_event_loop().run_until_complete(
            async_get_device_attributes("Bearer tok", "pk1", "dk1")
        )
        assert result == {"on": True}
