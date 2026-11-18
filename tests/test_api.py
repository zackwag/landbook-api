import asyncio
import base64
import io
import json
import urllib.error
import urllib.parse
from unittest.mock import MagicMock, patch

import pytest

from landbook_api import DEFAULT_REGION, REGIONS, LandbookAPIError, LandbookAuthError
from landbook_api.api import (
    async_get_device_attributes,
    async_get_device_list,
    async_get_tsl,
    async_login,
    async_refresh_token,
    get_device_attributes,
    get_device_list,
    get_tsl,
    login,
    refresh_token,
)
from landbook_api.const import APP_ID, APP_SYSTEM_TYPE, APP_VERSION


def _fake_jwt(uid: str = "user123") -> str:
    payload = base64.urlsafe_b64encode(json.dumps({"uid": uid}).encode()).decode().rstrip("=")
    return f"Bearer header.{payload}.signature"


def _mock_urlopen(body: dict):
    resp = MagicMock()
    resp.read.return_value = json.dumps(body).encode()
    return resp


def _login_response(uid="user123"):
    return {
        "code": 200,
        "data": {
            "accessToken": {"token": _fake_jwt(uid)},
            "refreshToken": {"token": "Bearer refresh_abc"},
        },
    }


def _token_pair_response(access="Bearer new_access", refresh="Bearer new_refresh"):
    return {
        "code": 200,
        "data": {"accessToken": {"token": access}, "refreshToken": {"token": refresh}},
    }


def _http_error(status: int, body: dict | None) -> urllib.error.HTTPError:
    raw = json.dumps(body).encode() if body is not None else b"<html>Service Unavailable</html>"
    return urllib.error.HTTPError("https://x", status, "error", {}, io.BytesIO(raw))


class _ResetBody(io.RawIOBase):
    def readable(self):
        return True

    def readinto(self, _b):
        raise ConnectionResetError("reset while reading error body")


def _form(req) -> dict[str, str]:
    return dict(urllib.parse.parse_qsl(req.data.decode()))


def test_regions_have_required_keys():
    required = {"label", "api_base", "mqtt_host", "user_domain", "app_domain_key"}
    for region, cfg in REGIONS.items():
        assert required <= cfg.keys(), f"region {region} missing keys"


def test_default_region_is_valid():
    assert DEFAULT_REGION in REGIONS


@patch("landbook_api.api.urllib.request.urlopen")
def test_unknown_region_falls_back_to_default(mock_urlopen):
    mock_urlopen.return_value = _mock_urlopen({"code": 200, "data": {"list": []}})
    get_device_list("Bearer tok", region="does-not-exist")
    assert mock_urlopen.call_args[0][0].full_url.startswith(REGIONS[DEFAULT_REGION]["api_base"])


@patch("landbook_api.api.urllib.request.urlopen")
def test_every_request_sends_app_identity_headers(mock_urlopen):
    mock_urlopen.return_value = _mock_urlopen(_login_response())
    login("a@b.com", "pass")
    mock_urlopen.return_value = _mock_urlopen({"code": 200, "data": {"list": []}})
    get_device_list("Bearer tok")
    for call in mock_urlopen.call_args_list:
        req = call[0][0]
        assert req.get_header("Appid") == APP_ID
        assert req.get_header("Appversion") == APP_VERSION
        assert req.get_header("Appsystemtype") == APP_SYSTEM_TYPE


@patch("landbook_api.api.urllib.request.urlopen")
def test_success_code_without_data_raises_api_error(mock_urlopen):
    mock_urlopen.return_value = _mock_urlopen({"code": 200})
    with pytest.raises(LandbookAPIError):
        get_device_attributes("Bearer tok", "pk1", "dk1")


@patch("landbook_api.api.urllib.request.urlopen")
def test_rejection_message_carries_server_msg(mock_urlopen):
    # landbook-ha matches "Token validation failed" in this message to decide
    # whether to refresh the token.
    mock_urlopen.return_value = _mock_urlopen({"code": 5032, "msg": "Token validation failed"})
    with pytest.raises(LandbookAPIError, match="Token validation failed"):
        get_tsl("Bearer tok", "pk1")


class TestLogin:
    @patch("landbook_api.api.urllib.request.urlopen")
    def test_returns_token_uid_and_refresh_token(self, mock_urlopen):
        mock_urlopen.return_value = _mock_urlopen(_login_response())
        bearer, uid, rt = login("a@b.com", "pass")
        assert uid == "user123"
        assert bearer == _fake_jwt()
        assert rt == "Bearer refresh_abc"

    @patch("landbook_api.api.urllib.request.urlopen")
    def test_decodes_base64url_jwt_payload(self, mock_urlopen):
        uid = "???~~~"  # encodes to base64url with '-' and '_' in it
        assert {"-", "_"} <= set(_fake_jwt(uid))
        mock_urlopen.return_value = _mock_urlopen(_login_response(uid))
        assert login("a@b.com", "pass")[1] == uid

    @patch("landbook_api.api.urllib.request.urlopen")
    def test_unparseable_token_raises_api_error(self, mock_urlopen):
        body = _login_response()
        body["data"]["accessToken"]["token"] = "Bearer not-a-jwt"
        mock_urlopen.return_value = _mock_urlopen(body)
        with pytest.raises(LandbookAPIError):
            login("a@b.com", "pass")

    def test_password_and_signature_match_known_good_values(self):
        # Captured from the version known to log in against the real server.
        with (
            patch("landbook_api.api.random.choices", return_value=list("ABCDEFGHIJKLMNOP")),
            patch("landbook_api.api.urllib.request.urlopen") as mock_urlopen,
        ):
            mock_urlopen.return_value = _mock_urlopen(_login_response())
            login("a@b.com", "hunter2", region="us")
        form = _form(mock_urlopen.call_args[0][0])
        assert form["random"] == "ABCDEFGHIJKLMNOP"
        assert form["pwd"] == "Rd2wsFhZQoq8XdUWJjinNg=="
        assert form["signature"] == (
            "bbb3d893911f464cdd21e3b27fdb7fbf2fc13bd3f395d9a611bb764080350f83"
        )

    @patch("landbook_api.api.urllib.request.urlopen")
    def test_http_error_with_api_envelope_raises_auth_error(self, mock_urlopen):
        mock_urlopen.side_effect = _http_error(401, {"code": 401, "msg": "bad creds"})
        with pytest.raises(LandbookAuthError, match="bad creds"):
            login("a@b.com", "wrong")

    @patch("landbook_api.api.urllib.request.urlopen")
    def test_http_error_without_envelope_raises_api_error(self, mock_urlopen):
        mock_urlopen.side_effect = _http_error(503, None)
        with pytest.raises(LandbookAPIError, match="Login request failed"):
            login("a@b.com", "pass")

    @patch("landbook_api.api.urllib.request.urlopen")
    def test_unreadable_http_error_body_raises_api_error(self, mock_urlopen):
        mock_urlopen.side_effect = urllib.error.HTTPError(
            "https://x", 401, "error", {}, io.BufferedReader(_ResetBody())
        )
        with pytest.raises(LandbookAPIError, match="Login request failed"):
            login("a@b.com", "pass")

    @patch("landbook_api.api.urllib.request.urlopen")
    def test_posts_encrypted_credentials_to_region(self, mock_urlopen):
        mock_urlopen.return_value = _mock_urlopen(_login_response())
        login("a@b.com", "hunter2", region="eu")
        req = mock_urlopen.call_args[0][0]
        assert req.get_method() == "POST"
        assert req.full_url == REGIONS["eu"]["api_base"] + "/v2/enduser/enduserapi/emailPwdLogin"
        form = _form(req)
        assert form["email"] == "a@b.com"
        assert form["userDomain"] == REGIONS["eu"]["user_domain"]
        assert len(form["random"]) == 16
        assert "hunter2" not in req.data.decode()
        assert len(base64.b64decode(form["pwd"])) % 16 == 0

    @patch("landbook_api.api.urllib.request.urlopen")
    def test_salt_differs_per_login(self, mock_urlopen):
        mock_urlopen.return_value = _mock_urlopen(_login_response())
        login("a@b.com", "hunter2")
        mock_urlopen.return_value = _mock_urlopen(_login_response())
        login("a@b.com", "hunter2")
        first, second = (_form(c[0][0]) for c in mock_urlopen.call_args_list)
        assert first["random"] != second["random"]
        assert first["pwd"] != second["pwd"]

    @patch("landbook_api.api.urllib.request.urlopen")
    def test_rejected_raises_auth_error(self, mock_urlopen):
        mock_urlopen.return_value = _mock_urlopen({"code": 401, "msg": "bad creds"})
        with pytest.raises(LandbookAuthError, match="bad creds"):
            login("a@b.com", "wrong")

    @patch("landbook_api.api.urllib.request.urlopen")
    def test_missing_data_raises_auth_error(self, mock_urlopen):
        mock_urlopen.return_value = _mock_urlopen({"code": 200})
        with pytest.raises(LandbookAuthError):
            login("a@b.com", "pass")

    @patch("landbook_api.api.urllib.request.urlopen", side_effect=ConnectionError("offline"))
    def test_network_error_raises_api_error_not_auth_error(self, mock_urlopen):
        with pytest.raises(LandbookAPIError, match="Login request failed"):
            login("a@b.com", "pass")


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


class TestRefreshToken:
    @patch("landbook_api.api.urllib.request.urlopen")
    def test_returns_new_token_pair(self, mock_urlopen):
        mock_urlopen.return_value = _mock_urlopen(_token_pair_response())
        assert refresh_token("Bearer old", "Bearer old_refresh") == (
            "Bearer new_access",
            "Bearer new_refresh",
        )

    @patch("landbook_api.api.urllib.request.urlopen")
    def test_puts_refresh_token_with_access_token_header(self, mock_urlopen):
        mock_urlopen.return_value = _mock_urlopen(_token_pair_response())
        refresh_token("Bearer tok", "Bearer rt_val", region="us")
        req = mock_urlopen.call_args[0][0]
        assert req.get_method() == "PUT"
        assert req.get_header("Authorization") == "Bearer tok"
        assert _form(req) == {"refreshToken": "Bearer rt_val"}

    @patch("landbook_api.api.urllib.request.urlopen")
    def test_rejected_raises_auth_error(self, mock_urlopen):
        # landbook-ha matches "rejected" in this message to start reauth.
        mock_urlopen.return_value = _mock_urlopen({"code": 401, "msg": "expired"})
        with pytest.raises(LandbookAuthError, match="rejected: expired"):
            refresh_token("Bearer old", "Bearer old_refresh")

    @patch("landbook_api.api.urllib.request.urlopen", side_effect=ConnectionError("down"))
    def test_network_error_raises_api_error(self, mock_urlopen):
        with pytest.raises(LandbookAPIError, match="Token refresh request failed"):
            refresh_token("Bearer old", "Bearer old_refresh")

    @pytest.mark.parametrize(
        "body", [{"code": 500, "msg": "system busy"}, {"status": 503, "error": "Unavailable"}]
    )
    @patch("landbook_api.api.urllib.request.urlopen")
    def test_server_error_is_not_a_rejection(self, mock_urlopen, body):
        # A LandbookAuthError here makes landbook-ha halt reconnects and ask the
        # user to log in again over what is only a cloud outage.
        mock_urlopen.side_effect = _http_error(503, body)
        with pytest.raises(LandbookAPIError) as excinfo:
            refresh_token("Bearer old", "Bearer old_refresh")
        assert not isinstance(excinfo.value, LandbookAuthError)

    @patch("landbook_api.api.urllib.request.urlopen")
    def test_malformed_success_raises_api_error(self, mock_urlopen):
        mock_urlopen.return_value = _mock_urlopen({"code": 200, "data": {"accessToken": None}})
        with pytest.raises(LandbookAPIError, match="not understood"):
            refresh_token("Bearer old", "Bearer old_refresh")


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


class TestAsyncWrappers:
    @patch("landbook_api.api.urllib.request.urlopen")
    def test_async_login(self, mock_urlopen):
        mock_urlopen.return_value = _mock_urlopen(_login_response("u1"))
        _bearer, uid, _rt = asyncio.run(async_login("a@b.com", "pass", "eu"))
        assert uid == "u1"
        assert mock_urlopen.call_args[0][0].full_url.startswith(REGIONS["eu"]["api_base"])

    @patch("landbook_api.api.urllib.request.urlopen")
    def test_async_refresh_token(self, mock_urlopen):
        mock_urlopen.return_value = _mock_urlopen(_token_pair_response("Bearer a2", "Bearer r2"))
        assert asyncio.run(async_refresh_token("Bearer a", "Bearer r")) == (
            "Bearer a2",
            "Bearer r2",
        )
        assert _form(mock_urlopen.call_args[0][0]) == {"refreshToken": "Bearer r"}

    @patch("landbook_api.api.urllib.request.urlopen")
    def test_async_get_device_list(self, mock_urlopen):
        mock_urlopen.return_value = _mock_urlopen({"code": 200, "data": {"list": [{"id": 1}]}})
        assert asyncio.run(async_get_device_list("Bearer tok", "eu")) == [{"id": 1}]
        assert mock_urlopen.call_args[0][0].full_url.startswith(REGIONS["eu"]["api_base"])

    @patch("landbook_api.api.urllib.request.urlopen")
    def test_async_get_tsl(self, mock_urlopen):
        props = [{"code": "a", "type": "PROPERTY", "subType": "W", "sort": 0}]
        mock_urlopen.return_value = _mock_urlopen({"code": 200, "data": {"properties": props}})
        assert asyncio.run(async_get_tsl("Bearer tok", "pk1")) == props
        assert "pk=pk1" in mock_urlopen.call_args[0][0].full_url

    @patch("landbook_api.api.urllib.request.urlopen")
    def test_async_get_device_attributes(self, mock_urlopen):
        mock_urlopen.return_value = _mock_urlopen({"code": 200, "data": {"on": True}})
        result = asyncio.run(async_get_device_attributes("Bearer tok", "pk1", "dk1"))
        assert result == {"on": True}
        assert "dk=dk1" in mock_urlopen.call_args[0][0].full_url
